package relay

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"math/big"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/muxsession"
	"github.com/tnldotdev/tnl/internal/observability"
	"github.com/tnldotdev/tnl/internal/opaqueid"
	"github.com/tnldotdev/tnl/internal/proxyproto"
	"github.com/tnldotdev/tnl/internal/serviceapi"
	"github.com/tnldotdev/tnl/internal/tunnel"
	"github.com/tnldotdev/tnl/pkg/api/relayv1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

func privateRelayID(prefix string) string { return prefix + strings.Repeat("a", 22) }

func privateRelayPair(t *testing.T, hello tunnelv1.Message) (*tunnel.Session, *tunnel.Session) {
	t.Helper()
	public, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: []string{"relay.test"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, leaf, leaf, public, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(cert)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	accepted := make(chan *tunnel.Session, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		transport, err := muxsession.AcceptTLSYamux(t.Context(), conn, &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}, muxsession.TLSYamuxConfig{})
		if err != nil {
			return
		}
		server, _, err := tunnel.Accept(t.Context(), transport, func(_ context.Context, message tunnelv1.Message) error {
			if message.Role != hello.Role || message.Credential != hello.Credential {
				return errors.New("wrong peer")
			}
			return nil
		})
		if err == nil {
			accepted <- server
		}
	}()
	transport, err := (muxsession.TLSYamuxConnector{TLSConfig: &tls.Config{RootCAs: roots}}).Connect(t.Context(), muxsession.Endpoint{Address: listener.Addr().String(), ServerName: "relay.test"})
	if err != nil {
		t.Fatal(err)
	}
	client, err := tunnel.Dial(t.Context(), transport, hello)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	server := relayAwait(t, accepted)
	t.Cleanup(func() { _ = server.Close() })
	return client, server
}

func TestPrivateRelayPreservesOriginalProxyAndRejectsStaleAssignment(t *testing.T) {
	ref := tunnelv1.PrivatePublisherConnectionRef{PrivateServiceID: privateRelayID(opaqueid.PrivateServicePrefix), PrivateRunID: privateRelayID(opaqueid.PrivateRunPrefix), RunNumber: 3,
		PublisherConnectionID: privateRelayID(opaqueid.PublisherConnectionPrefix), ConnectionSlot: 0, ConnectionAssignmentRevision: 2, RelayServiceID: "relay-a"}
	publisher, relayPublisher := privateRelayPair(t, tunnelv1.Message{Type: tunnelv1.Hello, ProtocolVersion: tunnelv1.Version, Role: tunnelv1.Publisher, Credential: "assigned-publisher", PrivateConnection: &ref})
	paths := &PublisherConnection{session: relayPublisher, streams: make(map[*trackedConn]struct{}), changed: make(chan struct{})}
	lease := relayv1.RelayLease{RelayServiceId: ref.RelayServiceID, RelayId: "relay-process", RelayRunId: privateRelayID(opaqueid.RelayRunPrefix), RelayLeaseRevision: 4, LeaseExpiresAt: time.Now().Add(time.Minute), ConnectionCapacity: 4}
	registry := NewPrivateRegistry()
	metrics := observability.New("relay")
	registry.Instrument(metrics)
	connection := &privateConnection{ref: ref, lease: lease, paths: paths}
	if err := registry.insert(connection); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = registry.Close() })
	secrets, err := serviceapi.NewBearerSecrets(strings.Repeat("s", 32), "")
	if err != nil {
		t.Fatal(err)
	}
	forwarder, err := NewForwardingAcceptor(ForwardingAcceptorConfig{Registry: NewRegistry(), PrivateRegistry: registry, CurrentLease: func() relayv1.RelayLease { return lease }, ClusterSecrets: secrets, StreamCapacity: 2, Observer: metrics, StreamsDelta: metrics.AddRelayStreams, StreamRejected: metrics.ObserveRelayStreamRejection})
	if err != nil {
		t.Fatal(err)
	}
	ingress, relayIngress := privateRelayPair(t, tunnelv1.Message{Type: tunnelv1.Hello, ProtocolVersion: tunnelv1.Version, Role: tunnelv1.Ingress, Credential: strings.Repeat("s", 32)})
	header := tunnelv1.PrivateForwardingHeader{PrivateStreamHeader: tunnelv1.PrivateStreamHeader{ProtocolVersion: tunnelv1.Version, Kind: tunnelv1.PrivateForwardingStream,
		PrivateServiceID: ref.PrivateServiceID, PrivateRunID: ref.PrivateRunID, RunNumber: ref.RunNumber, PublisherConnectionID: ref.PublisherConnectionID, ConnectionAssignmentRevision: ref.ConnectionAssignmentRevision,
		Connector: &tunnelv1.ConnectorAdmission{SessionID: privateRelayID(opaqueid.PrivateConnectorSessionPrefix), Subject: tunnelv1.VisitorSubject{Kind: tunnelv1.VisitorHumanDevice, IdentityID: privateRelayID(opaqueid.IdentityPrefix), DeviceID: "vdev_aaaaaaaaaaaaaaaaaaaaaa"}, GrantRevision: 7},
		SourceIP:  "192.0.2.4", VisitorConnectionID: privateRelayID(opaqueid.VisitorConnectionPrefix), ExpiresAt: time.Now().Add(time.Minute)},
		ConnectionSlot: 0, RelayServiceID: lease.RelayServiceId, RelayID: lease.RelayId, RelayRunID: lease.RelayRunId, RelayLeaseRevision: 4, LeaseExpiresAt: lease.LeaseExpiresAt}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	forwarded := relayWorker(t, cancel, func() error {
		incoming, err := relayIngress.AcceptInternalForwardingStream(ctx)
		if err != nil {
			return err
		}
		return forwarder.forward(ctx, incoming)
	})
	publisherDone := relayWorker(t, func() { _ = publisher.Close() }, func() error {
		incoming, err := publisher.AcceptPrivateForwardingStream(ctx)
		if err != nil {
			return err
		}
		if incoming.Header.Connector.Subject != header.Connector.Subject || incoming.Header.Connector.GrantRevision != header.Connector.GrantRevision || incoming.Header.VisitorConnectionID != header.VisitorConnectionID {
			return errors.New("relay rewrote authorized private identity")
		}
		if err := incoming.Accept(); err != nil {
			return err
		}
		defer incoming.Stream.Close()
		_, err = io.Copy(incoming.Stream, incoming.Stream)
		return err
	})
	stream, err := ingress.OpenPrivateForwardingStream(ctx, header)
	if err != nil {
		t.Fatal(err)
	}
	proxy, err := proxyproto.Encode(proxyproto.Header{Source: netip.MustParseAddrPort("192.0.2.4:40000"), Destination: netip.MustParseAddrPort("203.0.113.1:443")})
	if err != nil {
		t.Fatal(err)
	}
	payload := append(proxy, []byte("opaque visitor TLS bytes")...)
	if _, err := stream.Write(payload); err != nil {
		t.Fatal(err)
	}
	response := make([]byte, len(payload))
	if _, err := io.ReadFull(stream, response); err != nil || !bytes.Equal(payload, response) {
		t.Fatalf("relay rewrote or duplicated original metadata/bytes: %x %v", response, err)
	}
	_ = stream.Close()
	_ = relayAwait(t, forwarded)
	_ = relayAwait(t, publisherDone)
	header.ConnectionAssignmentRevision++
	denied := relayWorker(t, cancel, func() error {
		incoming, err := relayIngress.AcceptInternalForwardingStream(ctx)
		if err != nil {
			return err
		}
		return forwarder.forward(ctx, incoming)
	})
	if _, err := ingress.OpenPrivateForwardingStream(ctx, header); err == nil {
		t.Fatal("stale private assignment admitted")
	}
	_ = relayAwait(t, denied)
	assertRelayOperation(t, metrics, "RelayOpenVisitorStream", "success", 1)
	assertRelayOperation(t, metrics, "RelayOpenVisitorStream", "rejected", 1)
	assertRelayOperation(t, metrics, "RelayOpenVisitorStream", "error", 0)
	registry.remove(connection)
	registry.remove(connection) // duplicate removal cannot make the gauge negative.
	families, err := metrics.Gather()
	if err != nil {
		t.Fatal(err)
	}
	seenBytes := 0
	for _, family := range families {
		if family.GetName() == "tnl_relay_forwarded_bytes_total" {
			for _, point := range family.Metric {
				if point.GetCounter().GetValue() != float64(len(payload)) {
					t.Fatal("private relay bytes differ from the wire transfer", point)
				}
				seenBytes++
			}
		}
		if family.GetName() == "tnl_relay_publisher_connections_registered" || family.GetName() == "tnl_relay_visitor_stream_slots_occupied" {
			if family.Metric[0].GetGauge().GetValue() != 0 {
				t.Fatal("private relay leaked occupancy", family)
			}
		}
		if family.GetName() == "tnl_relay_visitor_stream_rejections_total" && family.Metric[0].GetCounter().GetValue() != 1 {
			t.Fatal("stale stream was not counted exactly once", family)
		}
	}
	if seenBytes != 2 {
		t.Fatal("missing private relay byte directions")
	}
}

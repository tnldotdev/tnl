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
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/observability"
	"github.com/tnldotdev/tnl/internal/serviceapi"
	"github.com/tnldotdev/tnl/internal/transport/muxsession"
	"github.com/tnldotdev/tnl/internal/transport/proxyproto"
	"github.com/tnldotdev/tnl/internal/transport/tunnel"
	relayv1 "github.com/tnldotdev/tnl/pkg/api/control/private/relay/v1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

func privateRelayID(prefix string) string { return prefix + strings.Repeat("a", 22) }

type privateClaimControlStub struct {
	ControlClient
	claims     atomic.Int64
	claim      func()
	disconnect func()
}

func (c *privateClaimControlStub) ClaimServicePublisherConnection(_ context.Context, id string, body relayv1.ServicePublisherConnectionClaim) (relayv1.ServicePublisherConnection, error) {
	if c.claims.Add(1) == 1 && c.claim != nil {
		c.claim()
	}
	return relayv1.ServicePublisherConnection{ServiceId: body.ServiceId, ServiceRunId: body.ServiceRunId, RunNumber: body.RunNumber,
		PublisherConnectionId: id, ConnectionAssignmentRevision: body.ConnectionAssignmentRevision, RelayServiceId: "relay-a"}, nil
}

func (*privateClaimControlStub) ReadyServicePublisherConnection(context.Context, string, relayv1.ServicePublisherConnectionTransition) (relayv1.ServicePublisherConnection, error) {
	return relayv1.ServicePublisherConnection{}, nil
}

func (c *privateClaimControlStub) DisconnectServicePublisherConnection(context.Context, string, relayv1.ServicePublisherConnectionTransition) error {
	if c.disconnect != nil {
		c.disconnect()
	}
	return nil
}

func TestPrivateClaimReservesOwnerBeforeControl(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	unblock := sync.OnceFunc(func() { close(release) })
	t.Cleanup(unblock)
	client := &privateClaimControlStub{claim: func() { close(entered); <-release }}
	controller := &Controller{client: client, now: time.Now, lease: relayv1.RelayLease{RelayServiceId: "relay-a", RelayId: "relay-a-1", RelayRunId: "process", RelayLeaseRevision: 1, LeaseExpiresAt: time.Now().Add(time.Minute)}}
	registry := NewServiceRegistry()
	acceptor := &ServicePublisherAcceptor{Select: func(string) (ServicePublisherTarget, bool) {
		return ServicePublisherTarget{Control: controller, Registry: registry}, true
	}}
	ref := tunnelv1.ServicePublisherConnectionRef{ServiceID: privateRelayID(opaqueid.ServicePrefix), ServiceRunID: privateRelayID(opaqueid.ServiceRunPrefix), RunNumber: 1,
		PublisherConnectionID: privateRelayID(opaqueid.PublisherConnectionPrefix), ConnectionSlot: 0, ConnectionAssignmentRevision: 1, RelayServiceID: "relay-a"}
	message := tunnelv1.Message{Role: tunnelv1.Publisher, ServiceConnection: &ref, Credential: "credential"}
	type result struct {
		claim *privateClaim
		err   error
	}
	first := make(chan result, 1)
	go func() { claim, err := acceptor.claim(t.Context(), message); first <- result{claim, err} }()
	relayAwait(t, entered)
	duplicates := func() {
		t.Helper()
		done := make(chan error, 8)
		for range 8 {
			go func() { _, err := acceptor.claim(t.Context(), message); done <- err }()
		}
		for range 8 {
			if err := relayAwait(t, done); err == nil {
				t.Error("duplicate handshake acquired pending claim")
			}
		}
	}
	duplicates()
	if client.claims.Load() != 1 {
		t.Errorf("duplicate handshake reached control %d times", client.claims.Load())
	}
	unblock()
	owner := relayAwait(t, first)
	if owner.err != nil {
		t.Fatal(owner.err)
	}
	// keep the local guard until the owner's final control disconnect finishes.
	disconnecting, finish := make(chan struct{}), make(chan struct{})
	unblockDisconnect := sync.OnceFunc(func() { close(finish) })
	t.Cleanup(unblockDisconnect)
	client.disconnect = func() { close(disconnecting); <-finish }
	outer := &PublisherAcceptor{readyDelta: func(int) {}, connectionExited: func(bool) {}}
	done := make(chan error, 1)
	go func() { done <- owner.claim.serve(t.Context(), nil, outer, func(error) {}) }()
	relayAwait(t, disconnecting)
	duplicates()
	unblockDisconnect()
	if err := relayAwait(t, done); err == nil {
		t.Fatal("missing tunnel session was accepted")
	}
	recovered, err := acceptor.claim(t.Context(), message)
	if err != nil {
		t.Fatalf("failed handshake retained local owner: %v", err)
	}
	registry.release(recovered)
}

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
	ref := tunnelv1.ServicePublisherConnectionRef{ServiceID: privateRelayID(opaqueid.ServicePrefix), ServiceRunID: privateRelayID(opaqueid.ServiceRunPrefix), RunNumber: 3,
		PublisherConnectionID: privateRelayID(opaqueid.PublisherConnectionPrefix), ConnectionSlot: 0, ConnectionAssignmentRevision: 2, RelayServiceID: "relay-a"}
	publisher, relayPublisher := privateRelayPair(t, tunnelv1.Message{Type: tunnelv1.Hello, ProtocolVersion: tunnelv1.Version, Role: tunnelv1.Publisher, Credential: "assigned-publisher", ServiceConnection: &ref})
	paths := newStreamLifetime(relayPublisher)
	lease := relayv1.RelayLease{RelayServiceId: ref.RelayServiceID, RelayId: "relay-process", RelayRunId: privateRelayID(opaqueid.RelayRunPrefix), RelayLeaseRevision: 4, LeaseExpiresAt: time.Now().Add(time.Minute), ConnectionCapacity: 4}
	registry := NewServiceRegistry()
	metrics := observability.New("relay")
	registry.Instrument(metrics)
	connection := &serviceConnection{ref: ref, lease: lease, paths: paths}
	if err := registry.insert(connection); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = registry.Close() })
	secrets, err := serviceapi.NewBearerSecrets(strings.Repeat("s", 32), "")
	if err != nil {
		t.Fatal(err)
	}
	forwarder, err := NewForwardingAcceptor(ForwardingAcceptorConfig{Registry: NewRegistry(), ServiceRegistry: registry, CurrentLease: func() relayv1.RelayLease { return lease }, ClusterSecrets: secrets, StreamCapacity: 2, Observer: metrics, StreamsDelta: metrics.AddRelayStreams, StreamRejected: metrics.ObserveRelayStreamRejection})
	if err != nil {
		t.Fatal(err)
	}
	ingress, relayIngress := privateRelayPair(t, tunnelv1.Message{Type: tunnelv1.Hello, ProtocolVersion: tunnelv1.Version, Role: tunnelv1.Ingress, Credential: strings.Repeat("s", 32)})
	header := tunnelv1.ServiceForwardingHeader{ServiceStreamHeader: tunnelv1.ServiceStreamHeader{ProtocolVersion: tunnelv1.Version, Kind: tunnelv1.ServiceForwardingStream,
		ServiceID: ref.ServiceID, ServiceRunID: ref.ServiceRunID, RunNumber: ref.RunNumber, PublisherConnectionID: ref.PublisherConnectionID, ConnectionAssignmentRevision: ref.ConnectionAssignmentRevision,
		Connector: &tunnelv1.ConnectorAdmission{SessionID: privateRelayID(opaqueid.ConnectorSessionPrefix), Subject: tunnelv1.VisitorSubject{Kind: tunnelv1.VisitorHumanDevice, IdentityID: privateRelayID(opaqueid.IdentityPrefix), DeviceID: "vdev_aaaaaaaaaaaaaaaaaaaaaa"}, GrantRevision: 7},
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
		incoming, err := publisher.AcceptServiceForwardingStream(ctx)
		if err != nil {
			return err
		}
		if incoming.Header.Connector.Subject != header.Connector.Subject || incoming.Header.Connector.GrantRevision != header.Connector.GrantRevision || incoming.Header.VisitorConnectionID != header.VisitorConnectionID {
			return errors.New("relay rewrote authorized private identity")
		}
		if err := incoming.Accept(); err != nil {
			return err
		}
		defer incoming.Stream().Close()
		_, err = io.Copy(incoming.Stream(), incoming.Stream())
		return err
	})
	stream, err := ingress.OpenServiceForwardingStream(ctx, header)
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
	if _, err := ingress.OpenServiceForwardingStream(ctx, header); err == nil {
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

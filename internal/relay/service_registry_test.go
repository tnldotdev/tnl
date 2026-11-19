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
	serverhttp "github.com/tnldotdev/tnl/internal/serverhttp"
	"github.com/tnldotdev/tnl/internal/transport/muxsession"
	"github.com/tnldotdev/tnl/internal/transport/proxyproto"
	"github.com/tnldotdev/tnl/internal/transport/tunnel"
	relayv1 "github.com/tnldotdev/tnl/pkg/api/control/private/relay/v1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

func privateRelayID(prefix string) string { return prefix + strings.Repeat("a", 22) }

type privateClaimControlStub struct {
	ControlClient
	claims        atomic.Int64
	ready         atomic.Int64
	claim         func()
	disconnect    func(context.Context, string, relayv1.ServicePublisherConnectionTransition)
	source        netip.Addr
	claimErr      error
	readyErr      error
	beforeReady   func()
	disconnectErr error
}

func (c *privateClaimControlStub) ClaimServicePublisherConnection(_ context.Context, id string, body relayv1.ServicePublisherConnectionClaim) (relayv1.ServicePublisherConnection, error) {
	if c.source.IsValid() && body.ObservedSourceIp != c.source.Unmap().String() {
		return relayv1.ServicePublisherConnection{}, errors.New("relay changed the accepted publisher source")
	}
	if c.claims.Add(1) == 1 && c.claim != nil {
		c.claim()
	}
	if c.claimErr != nil {
		return relayv1.ServicePublisherConnection{}, c.claimErr
	}
	return relayv1.ServicePublisherConnection{ServiceId: body.ServiceId, ServiceRunId: body.ServiceRunId, RunNumber: body.RunNumber,
		PublisherConnectionId: id, ConnectionAssignmentRevision: body.ConnectionAssignmentRevision, RelayServiceId: "relay-a"}, nil
}

func (c *privateClaimControlStub) ReadyServicePublisherConnection(_ context.Context, id string, body relayv1.ServicePublisherConnectionTransition) (relayv1.ServicePublisherConnection, error) {
	c.ready.Add(1)
	if c.beforeReady != nil {
		c.beforeReady()
	}
	return relayv1.ServicePublisherConnection{ServiceId: privateRelayID(opaqueid.ServicePrefix), ServiceRunId: body.ServiceRunId, RunNumber: body.RunNumber,
		PublisherConnectionId: id, ConnectionAssignmentRevision: body.ConnectionAssignmentRevision, RelayServiceId: "relay-a"}, c.readyErr
}

func (c *privateClaimControlStub) DisconnectServicePublisherConnection(ctx context.Context, id string, body relayv1.ServicePublisherConnectionTransition) error {
	if c.disconnect != nil {
		c.disconnect(ctx, id, body)
	}
	return c.disconnectErr
}

func TestPrivateClaimReservesOwnerBeforeControl(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	unblock := sync.OnceFunc(func() { close(release) })
	t.Cleanup(unblock)
	source := netip.MustParseAddr("192.0.2.1")
	client := &privateClaimControlStub{claim: func() { close(entered); <-release }, source: source}
	controller := &Controller{client: client, now: time.Now, lease: relayv1.RelayLease{RelayServiceId: "relay-a", RelayId: "relay-a-1", RelayRunId: "process", RelayLeaseRevision: 1, ServingUntil: time.Now().Add(time.Minute)}}
	registry := NewServiceRegistry()
	acceptor := &PublisherAcceptor{selectTarget: func(string) (ServicePublisherTarget, bool) {
		return ServicePublisherTarget{Control: controller, Registry: registry}, true
	}}
	ref := tunnelv1.ServicePublisherConnectionRef{ServiceID: privateRelayID(opaqueid.ServicePrefix), ServiceRunID: privateRelayID(opaqueid.ServiceRunPrefix), RunNumber: 1,
		PublisherConnectionID: privateRelayID(opaqueid.PublisherConnectionPrefix), ConnectionSlot: 0, ConnectionAssignmentRevision: 1, RelayServiceID: "relay-a"}
	message := tunnelv1.Message{Role: tunnelv1.Publisher, ServiceConnection: &ref, Credential: "credential"}
	type result struct {
		claim *publisherClaim
		err   error
	}
	first := make(chan result, 1)
	go func() { claim, err := acceptor.claim(t.Context(), message, source); first <- result{claim, err} }()
	relayAwait(t, entered)
	duplicates := func() {
		t.Helper()
		done := make(chan error, 8)
		for range 8 {
			go func() { _, err := acceptor.claim(t.Context(), message, source); done <- err }()
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
	client.disconnect = func(context.Context, string, relayv1.ServicePublisherConnectionTransition) {
		close(disconnecting)
		<-finish
	}
	outer := &PublisherAcceptor{readyDelta: func(int) {}, connectionExited: func(bool) {}}
	done := make(chan error, 1)
	go func() { done <- owner.claim.serve(t.Context(), nil, nil, outer, nil, func(error) {}) }()
	relayAwait(t, disconnecting)
	duplicates()
	unblockDisconnect()
	if err := relayAwait(t, done); err == nil {
		t.Fatal("missing tunnel session was accepted")
	}
	recovered, err := acceptor.claim(t.Context(), message, source)
	if err != nil {
		t.Fatalf("failed handshake retained local owner: %v", err)
	}
	registry.release(recovered)
}

func TestServicePublisherClaimRequiresObservedSource(t *testing.T) {
	client := &privateClaimControlStub{source: netip.MustParseAddr("192.0.2.1")}
	controller := &Controller{client: client, now: time.Now, lease: relayv1.RelayLease{RelayServiceId: "relay-a",
		RelayId: "relay-a-1", RelayRunId: "process", RelayLeaseRevision: 1, ServingUntil: time.Now().Add(time.Minute)}}
	ref := tunnelv1.ServicePublisherConnectionRef{ServiceID: privateRelayID(opaqueid.ServicePrefix), ServiceRunID: privateRelayID(opaqueid.ServiceRunPrefix), RunNumber: 1,
		PublisherConnectionID: privateRelayID(opaqueid.PublisherConnectionPrefix), ConnectionAssignmentRevision: 1, RelayServiceID: "relay-a"}
	for _, source := range []netip.Addr{{}, netip.IPv4Unspecified(), netip.IPv6Unspecified(), netip.MustParseAddr("fe80::1%en0")} {
		if _, err := controller.claimServiceConnection(t.Context(), ref, "credential", source); err == nil {
			t.Fatal("missing or invalid publisher source reached control", source)
		}
	}
	if client.claims.Load() != 0 {
		t.Fatal("invalid publisher source reached control")
	}
	if _, err := controller.claimServiceConnection(t.Context(), ref, "credential", netip.MustParseAddr("::ffff:192.0.2.1")); err != nil {
		t.Fatal("valid observed source was not normalized", err)
	}
	if client.claims.Load() != 1 {
		t.Fatal("valid source did not reach the exact claim")
	}
}

func TestServicePublisherAcceptRequiresPinnedSourceAndRechecksAfterClaim(t *testing.T) {
	for _, mode := range []string{"missing peer", "unbound UDP", "changed during claim"} {
		t.Run(mode, func(t *testing.T) {
			peer := &connectorSourcePeer{}
			peer.move("192.0.2.1:443")
			var disconnected atomic.Int64
			client := &privateClaimControlStub{source: netip.MustParseAddr("192.0.2.1"),
				claim:      func() { peer.move("192.0.2.2:443") },
				disconnect: func(context.Context, string, relayv1.ServicePublisherConnectionTransition) { disconnected.Add(1) }}
			controller := &Controller{client: client, now: time.Now, lease: relayv1.RelayLease{
				RelayServiceId: "relay-a", RelayId: "relay-a-1", RelayRunId: "process",
				RelayLeaseRevision: 1, ServingUntil: time.Now().Add(time.Minute)}}
			registry := NewServiceRegistry()
			selectTarget := func(string) (ServicePublisherTarget, bool) {
				return ServicePublisherTarget{Control: controller, Registry: registry}, true
			}
			acceptor, err := NewPublisherAcceptor(PublisherAcceptorConfig{Select: selectTarget})
			if err != nil {
				t.Fatal(err)
			}
			ref := tunnelv1.ServicePublisherConnectionRef{ServiceID: privateRelayID(opaqueid.ServicePrefix),
				ServiceRunID: privateRelayID(opaqueid.ServiceRunPrefix), RunNumber: 1,
				PublisherConnectionID:        privateRelayID(opaqueid.PublisherConnectionPrefix),
				ConnectionAssignmentRevision: 1, RelayServiceID: "relay-a"}
			hello := tunnelv1.Message{Type: tunnelv1.Hello, ProtocolVersion: tunnelv1.Version,
				Role: tunnelv1.Publisher, Credential: "credential", ServiceConnection: &ref}
			session, done, err := dialPrivateClaim(t, func(ctx context.Context, outer muxsession.Session) error {
				switch mode {
				case "missing peer":
					return acceptor.Accept(ctx, struct{ muxsession.Session }{outer})
				case "unbound UDP":
					return acceptor.Accept(ctx, struct {
						muxsession.Session
						muxsession.AcceptedPeer
					}{outer, peer})
				default:
					return acceptor.Accept(ctx, struct {
						muxsession.Session
						*connectorSourcePeer
					}{outer, peer})
				}
			}, hello)
			if err == nil || session != nil {
				t.Fatal("untrusted or changed publisher source was admitted")
			}
			if err := relayAwait(t, done); err == nil {
				t.Fatal("source rejection lost its error")
			}
			wantClaims := int64(0)
			if mode == "changed during claim" {
				wantClaims = 1
			}
			if client.claims.Load() != wantClaims || disconnected.Load() != wantClaims || client.ready.Load() != 0 {
				t.Fatal("source rejection reached readiness or lost exact-claim cleanup", client.claims.Load(), disconnected.Load(), client.ready.Load())
			}
			// rejected handshakes must release their pending local reservation.
			client.claim = nil
			claim, err := acceptor.claim(t.Context(), hello, client.source)
			if err != nil {
				t.Fatal("source rejection retained its local claim", err)
			}
			registry.release(claim)
		})
	}
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
		transport, err := muxsession.AcceptWebSocket(t.Context(), conn, &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}, muxsession.WebSocketConfig{})
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
	transport, err := (muxsession.WebSocketConnector{TLSConfig: &tls.Config{RootCAs: roots}}).Connect(t.Context(), muxsession.Endpoint{Address: listener.Addr().String(), ServerName: "relay.test"})
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
	lease := relayv1.RelayLease{RelayServiceId: ref.RelayServiceID, RelayId: "relay-process", RelayRunId: privateRelayID(opaqueid.RelayRunPrefix), RelayLeaseRevision: 4, ServingUntil: time.Now().Add(time.Minute), ConnectionCapacity: 4}
	registry := NewServiceRegistry()
	metrics := observability.New("relay")
	registry.Instrument(metrics)
	connection := &serviceConnection{ref: ref, lease: lease, paths: paths}
	if err := registry.insert(connection); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = registry.Close() })
	secrets, err := serverhttp.NewBearerSecrets(strings.Repeat("s", 32), "")
	if err != nil {
		t.Fatal(err)
	}
	forwarder, err := NewForwardingAcceptor(ForwardingAcceptorConfig{ServiceRegistry: registry, CurrentLease: func() relayv1.RelayLease { return lease }, ClusterSecrets: secrets, StreamCapacity: 2, Observer: metrics, StreamsDelta: metrics.AddRelayStreams, StreamRejected: metrics.ObserveRelayStreamRejection})
	if err != nil {
		t.Fatal(err)
	}
	ingress, relayIngress := privateRelayPair(t, tunnelv1.Message{Type: tunnelv1.Hello, ProtocolVersion: tunnelv1.Version, Role: tunnelv1.Ingress, Credential: strings.Repeat("s", 32)})
	header := tunnelv1.ServiceForwardingHeader{ServiceStreamHeader: tunnelv1.ServiceStreamHeader{ProtocolVersion: tunnelv1.Version, Kind: tunnelv1.ServiceForwardingStream,
		ServiceID: ref.ServiceID, ServiceRunID: ref.ServiceRunID, RunNumber: ref.RunNumber, PublisherConnectionID: ref.PublisherConnectionID, ConnectionAssignmentRevision: ref.ConnectionAssignmentRevision,
		PublicService: &tunnelv1.PublicServiceAdmission{IngressID: "ingress-a", IngressRunID: privateRelayID(opaqueid.IngressRunPrefix), IngressLeaseRevision: 7, DestinationPort: 25443},
		SourceIP:      "192.0.2.4", VisitorConnectionID: privateRelayID(opaqueid.VisitorConnectionPrefix), ExpiresAt: time.Now().Add(time.Minute)},
		ConnectionSlot: 0, RelayServiceID: lease.RelayServiceId, RelayID: lease.RelayId, RelayRunID: lease.RelayRunId, RelayLeaseRevision: 4, ServingUntil: lease.ServingUntil}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	forwarded := relayWorker(t, cancel, func() error {
		incoming, err := relayIngress.AcceptServiceForwardingStream(ctx)
		if err != nil {
			return err
		}
		return forwarder.forwardService(ctx, incoming)
	})
	publisherDone := relayWorker(t, func() { _ = publisher.Close() }, func() error {
		incoming, err := publisher.AcceptServiceForwardingStream(ctx)
		if err != nil {
			return err
		}
		if *incoming.Header.PublicService != *header.PublicService || incoming.Header.VisitorConnectionID != header.VisitorConnectionID {
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
		incoming, err := relayIngress.AcceptServiceForwardingStream(ctx)
		if err != nil {
			return err
		}
		return forwarder.forwardService(ctx, incoming)
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

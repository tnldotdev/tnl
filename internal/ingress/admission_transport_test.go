package ingress

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/relay"
	"github.com/tnldotdev/tnl/internal/transport/muxsession"
	"github.com/tnldotdev/tnl/internal/transport/proxyproto"
	"github.com/tnldotdev/tnl/internal/transport/tunnel"
	ingressv1 "github.com/tnldotdev/tnl/pkg/api/control/private/ingress/v1"
	relayv1 "github.com/tnldotdev/tnl/pkg/api/control/private/relay/v1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

type admissionTransportFixture struct {
	forwarder *Forwarder
	publisher *tunnel.Session
	entry     ingressv1.IngressRoutingTableEntry
	ref       tunnelv1.PublisherConnectionRef
	material  forwardingTestMaterial
	lease     atomic.Pointer[relayv1.RelayLease]
	prepared  *preparedVisitorRun
}

// both hops use verified TLS/yamux and the real tunnel authentication handshake.
func newAdmissionTransportFixture(t *testing.T) *admissionTransportFixture {
	t.Helper()
	material := newForwardingTestMaterial(t)
	f := &admissionTransportFixture{entry: forwardingTestEntry(time.Now(), ""), material: material}
	f.entry.PublicUrlId, f.entry.PublishRunId = "url_"+strings.Repeat("A", 22), "pr_"+strings.Repeat("B", 22)
	f.entry.CanonicalHostname = "route.example"
	f.entry.IpPolicy = ingressv1.AllowAll
	registry := relay.NewRegistry()
	t.Cleanup(func() { _ = registry.Close() })
	ref := tunnelv1.PublisherConnectionRef{PublishRunID: f.entry.PublishRunId, PublicURLID: f.entry.PublicUrlId, PublishRunNumber: uint64(f.entry.PublishRunNumber),
		PublisherConnectionID: "publisher_connection_1", ConnectionAssignmentRevision: 3, RelayServiceID: "relay_service_1"}
	f.ref = ref
	claimed := relayv1.ClaimedPublisherConnection{PublishRunId: ref.PublishRunID, PublicUrlId: ref.PublicURLID, PublishRunNumber: int64(ref.PublishRunNumber), PublisherConnectionId: ref.PublisherConnectionID,
		ConnectionAssignmentRevision: 3, RelayServiceId: ref.RelayServiceID, RelayId: "relay_1", RelayRunId: "relay_run_1", RelayLeaseRevision: 4}
	ready := make(chan struct{}, 1)
	publisherServer := startForwardingTestServer(t, material, func(ctx context.Context, transport muxsession.Session) error {
		session, _, err := tunnel.Accept(ctx, transport, func(_ context.Context, m tunnelv1.Message) error {
			if m.Role != tunnelv1.Publisher || m.Credential != "publisher-secret" || m.PublisherConnection == nil || *m.PublisherConnection != ref {
				return &tunnel.ProtocolError{Code: tunnelv1.Unauthenticated}
			}
			return nil
		})
		if err != nil {
			return err
		}
		c, err := relay.NewPublisherConnection(ref, claimed, session)
		if err != nil {
			return err
		}
		if err := registry.Insert(c); err != nil {
			return err
		}
		defer registry.Remove(c)
		ready <- struct{}{}
		select {
		case <-ctx.Done():
		case <-session.Done():
		}
		return nil
	})
	transport, err := (muxsession.TLSYamuxConnector{TLSConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: material.roots}}).Connect(ingressContext(t), muxsession.Endpoint{Address: publisherServer.address(), ServerName: material.serverName})
	if err != nil {
		t.Fatal(err)
	}
	f.publisher, err = tunnel.Dial(ingressContext(t), transport, tunnelv1.Message{Type: tunnelv1.Hello, ProtocolVersion: tunnelv1.Version, Role: tunnelv1.Publisher, Credential: "publisher-secret", PublisherConnection: &ref})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.publisher.Close() })
	ingressAwait(t, ready)
	f.lease.Store(&relayv1.RelayLease{RelayServiceId: ref.RelayServiceID, RelayId: claimed.RelayId, RelayRunId: claimed.RelayRunId, RelayLeaseRevision: 4, LeaseExpiresAt: time.Now().Add(time.Minute)})
	acceptor, err := relay.NewForwardingAcceptor(relay.ForwardingAcceptorConfig{Registry: registry, CurrentLease: func() relayv1.RelayLease { return *f.lease.Load() }, ClusterSecrets: forwardingTestSecrets(t), StreamCapacity: 32})
	if err != nil {
		t.Fatal(err)
	}
	forwardingServer := startForwardingTestServer(t, material, acceptor.Accept)
	f.entry.PublisherConnections[0].InternalRelayAddress = forwardingServer.address()
	f.forwarder = newTestForwarder(t, material)
	return f
}

func publisherAdmission(h tunnelv1.VisitorStreamHeader) tunnelv1.AdmissionHeader {
	return tunnelv1.AdmissionHeader{ProtocolVersion: tunnelv1.Version, Kind: tunnelv1.PublisherAdmissionStream, VisitorConnectionID: h.VisitorConnectionID,
		PublicURLID: h.PublicURLID, PublishRunID: h.PublishRunID, PublishRunNumber: h.PublishRunNumber, PublisherConnectionID: h.PublisherConnectionID,
		ConnectionAssignmentRevision: h.ConnectionAssignmentRevision, RelayServiceID: "relay_service_1"}
}

func openPendingTransport(t *testing.T, f *admissionTransportFixture, id string) (net.Conn, *tunnel.IncomingVisitorStream) {
	t.Helper()
	return openPendingTransportWithContext(t, f, id, ingressContext(t))
}

func openPendingTransportWithContext(t *testing.T, f *admissionTransportFixture, id string, ctx context.Context) (net.Conn, *tunnel.IncomingVisitorStream) {
	t.Helper()
	incoming := make(chan *tunnel.IncomingVisitorStream, 1)
	worker := ingressWorker(t, func() { _ = f.publisher.Close() }, func() error {
		v, err := f.publisher.AcceptVisitorStream(ingressContext(t))
		if err != nil {
			return err
		}
		incoming <- v
		return v.Accept()
	})
	b := mustOnlyBackend(t, f.forwarder, f.entry).(forwardingBackend)
	c, err := b.OpenPending(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if err := ingressAwait(t, worker); err != nil {
		t.Fatal(err)
	}
	return c, ingressAwait(t, incoming)
}

func TestForwardingCarriesMaximumClientHelloAfterProxy(t *testing.T) {
	f := newAdmissionTransportFixture(t)
	proxy, err := proxyproto.Encode(proxyproto.Header{Source: netip.MustParseAddrPort("192.0.2.1:40000"), Destination: netip.MustParseAddrPort("203.0.113.1:443")})
	if err != nil {
		t.Fatal(err)
	}
	prefix := bytes.Repeat([]byte{0x42}, tunnelv1.MaxInitialBytes)
	received := make(chan []byte, 1)
	worker := ingressWorker(t, func() { _ = f.publisher.Close() }, func() error {
		incoming, err := f.publisher.AcceptVisitorStream(ingressContext(t))
		if err != nil {
			return err
		}
		defer incoming.Stream.Close()
		if err := incoming.Accept(); err != nil {
			return err
		}
		payload := make([]byte, len(proxy)+len(prefix))
		_, err = io.ReadFull(incoming.Stream, payload)
		received <- payload
		return err
	})
	backend := mustOnlyBackend(t, f.forwarder, f.entry).(forwardingBackend)
	stream, err := backend.Start(ingressContext(t), "visitor_max_hello", false, proxy, prefix)
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	if got := ingressAwait(t, received); !bytes.Equal(got, append(bytes.Clone(proxy), prefix...)) {
		t.Fatal("the full ClientHello and its separate PROXY header did not reach the publisher once")
	}
	if err := ingressAwait(t, worker); err != nil {
		t.Fatal(err)
	}
}

func TestPendingPromotionSurvivesCompletedOpeningContext(t *testing.T) {
	f := newAdmissionTransportFixture(t)
	var decisions atomic.Int32
	f.forwarder.SetPromotionHandler(func(ctx context.Context, _ tunnelv1.AdmissionHeader) tunnelv1.AdmissionResult {
		if ctx.Err() != nil {
			t.Error("promotion inherited completed opening deadline")
		}
		decisions.Add(1)
		return tunnelv1.AdmissionResult{Type: tunnelv1.StreamAccepted}
	})
	opening, cancel := context.WithCancel(ingressContext(t))
	stream, incoming := openPendingTransportWithContext(t, f, "visitor_after_open", opening)
	defer stream.Close()
	defer incoming.Stream.Close()
	cancel()
	h := publisherAdmission(incoming.Header)
	done := ingressWorker(t, func() { _ = incoming.Stream.Close() }, func() error {
		if err := sendTransportPromotion(t, incoming, h); err != nil {
			return err
		}
		_, err := incoming.Stream.Write([]byte("reply"))
		return err
	})
	var reply [5]byte
	if _, err := io.ReadFull(stream, reply[:]); err != nil || string(reply[:]) != "reply" {
		t.Fatalf("promotion after setup did not carry the visitor response: %q, %v", reply, err)
	}
	if err := ingressAwait(t, done); err != nil || decisions.Load() != 1 {
		t.Fatal("promotion was not bound to the live stream once", err, decisions.Load())
	}
}

func assertAdmissionCode(t *testing.T, err error, want tunnelv1.ErrorCode) {
	t.Helper()
	if want == "" {
		if err != nil {
			t.Fatal(err)
		}
		return
	}
	var protocolError *tunnel.ProtocolError
	if !errors.As(err, &protocolError) || protocolError.Code != want {
		t.Fatalf("admission = %v; want %s", err, want)
	}
}

func sendTransportPromotion(t *testing.T, incoming *tunnel.IncomingVisitorStream, h tunnelv1.AdmissionHeader) error {
	t.Helper()
	notifier, ok := incoming.Stream.(interface {
		Promote(tunnelv1.AdmissionHeader) error
	})
	if !ok {
		t.Fatal("publisher stream cannot emit an ordered promotion")
	}
	return notifier.Promote(h)
}

func TestAuthenticatedPromotionBindsIdentitySessionAndSingleUse(t *testing.T) {
	f := newAdmissionTransportFixture(t)
	var decisions atomic.Int32
	f.forwarder.SetPromotionHandler(func(_ context.Context, h tunnelv1.AdmissionHeader) tunnelv1.AdmissionResult {
		decisions.Add(1)
		if h.RelayRunID != "relay_run_1" || h.RelayLeaseRevision != 4 {
			t.Error("relay did not bind process identity")
		}
		return tunnelv1.AdmissionResult{Type: tunnelv1.StreamAccepted}
	})
	for index, change := range []func(*tunnelv1.AdmissionHeader){
		func(h *tunnelv1.AdmissionHeader) { h.PublicURLID = "other" }, func(h *tunnelv1.AdmissionHeader) { h.PublishRunID = "other" },
		func(h *tunnelv1.AdmissionHeader) { h.PublishRunNumber++ }, func(h *tunnelv1.AdmissionHeader) { h.PublisherConnectionID = "other" },
		func(h *tunnelv1.AdmissionHeader) { h.ConnectionSlot = 1 }, func(h *tunnelv1.AdmissionHeader) { h.ConnectionAssignmentRevision++ },
		func(h *tunnelv1.AdmissionHeader) { h.RelayServiceID = "other" },
	} {
		stream, incoming := openPendingTransport(t, f, fmt.Sprintf("visitor_bad_promotion_%d", index))
		t.Cleanup(func() { _ = stream.Close(); _ = incoming.Stream.Close() })
		bad := publisherAdmission(incoming.Header)
		change(&bad)
		sent := ingressWorker(t, func() { _ = incoming.Stream.Close() }, func() error { return sendTransportPromotion(t, incoming, bad) })
		_, err := stream.Read(make([]byte, 1))
		assertAdmissionCode(t, err, tunnelv1.StaleConnectionAssignment)
		if err := ingressAwait(t, sent); err != nil {
			t.Fatal(err)
		}
	}
	stream, incoming := openPendingTransport(t, f, "visitor_promotion")
	t.Cleanup(func() { _ = stream.Close(); _ = incoming.Stream.Close() })
	h := publisherAdmission(incoming.Header)
	// notification is one-way. only return-side consumption observes rejection;
	// no acceptance record or notification may enter visitor TLS bytes.
	done := ingressWorker(t, func() { _ = incoming.Stream.Close() }, func() error {
		if err := sendTransportPromotion(t, incoming, h); err != nil {
			return err
		}
		_, err := incoming.Stream.Write([]byte("encrypted"))
		return err
	})
	bytes := make([]byte, 9)
	if _, err := io.ReadFull(stream, bytes); err != nil || string(bytes) != "encrypted" {
		t.Fatalf("%q, %v", bytes, err)
	}
	if err := ingressAwait(t, done); err != nil {
		t.Fatal(err)
	}
	if err := sendTransportPromotion(t, incoming, h); !errors.Is(err, tunnelv1.ErrReturnFrame) || decisions.Load() != 1 {
		t.Fatal("promotion was reusable or authorized another visitor", err, decisions.Load())
	}
}

func TestAuthenticatedPromotionRejectsStaleRelayLeaseAndPropagatesCapacity(t *testing.T) {
	for _, test := range []struct {
		name  string
		stale bool
		want  tunnelv1.ErrorCode
	}{{"capacity", false, tunnelv1.CapacityExceeded}, {"lease", true, tunnelv1.StaleConnectionAssignment}} {
		t.Run(test.name, func(t *testing.T) {
			f := newAdmissionTransportFixture(t)
			f.forwarder.SetPromotionHandler(func(context.Context, tunnelv1.AdmissionHeader) tunnelv1.AdmissionResult {
				return tunnelv1.AdmissionResult{Type: tunnelv1.StreamRejected, Code: tunnelv1.CapacityExceeded}
			})
			c, incoming := openPendingTransport(t, f, "visitor_rejected")
			defer c.Close()
			defer incoming.Stream.Close()
			if test.stale {
				lease := *f.lease.Load()
				lease.RelayRunId = "restarted"
				f.lease.Store(&lease)
			}
			h := publisherAdmission(incoming.Header)
			sent := ingressWorker(t, func() { _ = incoming.Stream.Close() }, func() error { return sendTransportPromotion(t, incoming, h) })
			_, err := c.Read(make([]byte, 1))
			assertAdmissionCode(t, err, test.want)
			if err := ingressAwait(t, sent); err != nil {
				t.Fatal(err)
			}
			if err := sendTransportPromotion(t, incoming, h); !errors.Is(err, tunnelv1.ErrReturnFrame) {
				t.Fatal("rejected promotion was reusable", err)
			}
		})
	}
}

func TestAuthenticatedPromotionRejectsAnotherIngressSessionAndClosedVisitor(t *testing.T) {
	f := newAdmissionTransportFixture(t)
	var decisions atomic.Int32
	f.forwarder.SetPromotionHandler(func(context.Context, tunnelv1.AdmissionHeader) tunnelv1.AdmissionResult {
		decisions.Add(1)
		return tunnelv1.AdmissionResult{Type: tunnelv1.StreamAccepted}
	})
	c, incoming := openPendingTransport(t, f, "visitor_session")
	defer c.Close()
	defer incoming.Stream.Close()
	peer := make(chan *tunnel.Session, 1)
	other := startForwardingTestServer(t, f.material, func(ctx context.Context, transport muxsession.Session) error {
		s, _, err := tunnel.Accept(ctx, transport, func(_ context.Context, m tunnelv1.Message) error {
			if m.Role != tunnelv1.Ingress || m.Credential != forwardingClusterSecret {
				return &tunnel.ProtocolError{Code: tunnelv1.Unauthenticated}
			}
			return nil
		})
		if err != nil {
			return err
		}
		defer s.Close()
		peer <- s
		select {
		case <-ctx.Done():
		case <-s.Done():
		}
		return nil
	})
	b := mustOnlyBackend(t, f.forwarder, f.entry).(forwardingBackend)
	target := b.target
	target.address = other.address()
	target.relayID = "another_authenticated_peer"
	if _, _, err := f.forwarder.session(ingressContext(t), target); err != nil {
		t.Fatal(err)
	}
	h := forwardingTestHeader(f.entry, "visitor_session").Admission()
	// a notification belongs to one stream. a separately authenticated session
	// cannot substitute for the session retained by that stream's local binding.
	foreign := ingressAwait(t, peer)
	result := f.forwarder.promoteAdmission(ingressContext(t), foreign, h)
	if result.Type != tunnelv1.StreamRejected || result.Code != tunnelv1.StaleConnectionAssignment {
		t.Fatal("foreign session replaced a stream's notification binding")
	}
	if decisions.Load() != 0 {
		t.Fatal("foreign authenticated session authorized visitor")
	}
	_ = c.Close()
	result = f.forwarder.promoteAdmission(ingressContext(t), foreign, h)
	if result.Type != tunnelv1.StreamRejected || result.Code != tunnelv1.StaleConnectionAssignment {
		t.Fatal("closed visitor retained a notification binding")
	}
	if decisions.Load() != 0 {
		t.Fatal("closed visitor authorized")
	}
}

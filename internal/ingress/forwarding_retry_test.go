package ingress

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/transport/muxsession"
	"github.com/tnldotdev/tnl/internal/transport/tunnel"
	ingressv1 "github.com/tnldotdev/tnl/pkg/api/control/private/ingress/v1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

func TestForwarderWarmStalledAssignmentFallsBackBeforeVisitorBytes(t *testing.T) {
	material := newForwardingTestMaterial(t)
	fallback := newServiceTLSRelay(t)
	fallbackHeaders := make(chan tunnelv1.ServiceForwardingHeader, 2)
	var forwarder *Forwarder
	var relay ingressv1.ServiceRelay
	config := serviceIngressConfig(t, func(ctx context.Context, header tunnelv1.ServiceForwardingHeader) (net.Conn, error) {
		return forwarder.OpenPrivate(ctx, relay, header)
	}, func(ctx context.Context, header tunnelv1.ServiceForwardingHeader) (net.Conn, error) {
		fallbackHeaders <- header
		return fallback.open(ctx, header)
	})
	control := config.PublicServices.config.Control.(*httpsServiceControl)
	lease := config.PublicServices.config.CurrentLease()
	expectedRelay := control.relays[0]
	ref := tunnelv1.ServicePublisherConnectionRef{
		ServiceID: control.service, ServiceRunID: control.run, RunNumber: 1,
		PublisherConnectionID: control.relays[0].PublisherConnectionId, ConnectionSlot: 0,
		ConnectionAssignmentRevision: uint64(control.relays[0].ConnectionAssignmentRevision), RelayServiceID: control.relays[0].RelayServiceId,
	}
	warmed := make(chan *tunnel.IncomingServiceForwardingStream, 1)
	stalled := make(chan *tunnel.IncomingServiceForwardingStream, 1)
	checkSibling := make(chan struct{})
	releaseSibling := sync.OnceFunc(func() { close(checkSibling) })
	t.Cleanup(releaseSibling)
	noUnacknowledgedBytes := func(request *tunnel.IncomingServiceForwardingStream) error {
		if request.Header.Validate() != nil || tunnel.ServiceForwardingRef(request.Header) != ref ||
			request.Header.RelayID != expectedRelay.RelayId || request.Header.RelayRunID != expectedRelay.RelayRunId ||
			request.Header.RelayLeaseRevision != uint64(expectedRelay.RelayLeaseRevision) ||
			!request.Header.LeaseExpiresAt.Equal(expectedRelay.LeaseExpiresAt) || !request.Header.ExpiresAt.After(time.Now()) ||
			request.Header.PublicService == nil || request.Header.PublicService.IngressID != lease.IngressId ||
			request.Header.PublicService.IngressRunID != lease.IngressRunId ||
			request.Header.PublicService.IngressLeaseRevision != uint64(lease.IngressLeaseRevision) ||
			request.Header.PublicService.DestinationPort != 443 || request.Header.SourceIP != "192.0.2.4" {
			return errors.New("service opening changed its current run, assignment, or ingress lease")
		}
		if err := request.Stream().SetReadDeadline(time.Now()); err != nil {
			return err
		}
		var beforeAcceptance [1]byte
		if n, err := request.Stream().Read(beforeAcceptance[:]); n != 0 || err == nil {
			return errors.New("service opening sent metadata or visitor bytes before acknowledgment")
		}
		return request.Stream().SetReadDeadline(time.Time{})
	}
	server := startForwardingTestServer(t, material, func(ctx context.Context, transport muxsession.Session) error {
		session, _, err := tunnel.Accept(ctx, transport, func(_ context.Context, message tunnelv1.Message) error {
			if message.Role != tunnelv1.Ingress || message.Credential != forwardingClusterSecret || message.PublisherConnection != nil || message.ServiceConnection != nil {
				return &tunnel.ProtocolError{Code: tunnelv1.Unauthenticated}
			}
			return nil
		})
		if err != nil {
			return err
		}
		defer session.Close()
		firstOpening, err := session.AcceptInternalForwardingStream(ctx)
		if err != nil {
			return err
		}
		first, ok := firstOpening.(*tunnel.IncomingServiceForwardingStream)
		if !ok {
			return errors.New("warm opening did not use a service forwarding stream")
		}
		defer first.Stream().Close()
		if err := noUnacknowledgedBytes(first); err != nil {
			return err
		}
		if err := first.Accept(); err != nil {
			return err
		}
		warmed <- first
		secondOpening, err := session.AcceptInternalForwardingStream(ctx)
		if err != nil {
			return err
		}
		second, ok := secondOpening.(*tunnel.IncomingServiceForwardingStream)
		if !ok {
			return errors.New("stalled opening did not use a service forwarding stream")
		}
		defer second.Stream().Close()
		if err := noUnacknowledgedBytes(second); err != nil {
			return err
		}
		// withhold acceptance after this exact session/assignment was warmed.
		stalled <- second
		select {
		case <-checkSibling:
			if _, err := first.Stream().Write([]byte("ok")); err != nil {
				return err
			}
		case <-ctx.Done():
			return nil
		}
		<-ctx.Done()
		return nil
	})
	relay = control.relays[0]
	relay.InternalRelayAddress, relay.TlsServerName = server.address(), material.serverName
	control.relays[0] = relay
	connector, err := newTLSRelayConnector(&tls.Config{MinVersion: tls.VersionTLS13, RootCAs: material.roots}, forwardingClusterSecret, muxsession.TLSYamuxConfig{})
	if err != nil {
		t.Fatal(err)
	}
	forwarder = newForwarder(connector)
	closeForwarder := sync.OnceValue(func() error { return forwarder.Close() })
	t.Cleanup(func() {
		if err := closeForwarder(); err != nil {
			t.Error("close service forwarder", err)
		}
	})
	warmHeader := tunnelv1.ServiceForwardingHeader{ServiceStreamHeader: tunnelv1.ServiceStreamHeader{
		ProtocolVersion: tunnelv1.Version, Kind: tunnelv1.ServiceForwardingStream,
		ServiceID: ref.ServiceID, ServiceRunID: ref.ServiceRunID, RunNumber: ref.RunNumber,
		PublisherConnectionID: ref.PublisherConnectionID, ConnectionAssignmentRevision: ref.ConnectionAssignmentRevision,
		PublicService: &tunnelv1.PublicServiceAdmission{IngressID: lease.IngressId, IngressRunID: lease.IngressRunId,
			IngressLeaseRevision: uint64(lease.IngressLeaseRevision), DestinationPort: 443},
		SourceIP: "192.0.2.4", VisitorConnectionID: publicServiceTestID(t, opaqueid.VisitorConnectionPrefix), ExpiresAt: time.Now().Add(time.Minute),
	}, ConnectionSlot: ref.ConnectionSlot, RelayServiceID: ref.RelayServiceID, RelayID: relay.RelayId, RelayRunID: relay.RelayRunId,
		RelayLeaseRevision: uint64(relay.RelayLeaseRevision), LeaseExpiresAt: relay.LeaseExpiresAt}
	warm, err := forwarder.OpenPrivate(ingressContext(t), relay, warmHeader)
	if err != nil {
		t.Fatal(err)
	}
	ownIngressConn(t, warm)
	if first := ingressAwait(t, warmed); first.Header.VisitorConnectionID != warmHeader.VisitorConnectionID {
		t.Fatal("warm opening changed the visitor identity", first.Header)
	}
	target := relayTarget{address: relay.InternalRelayAddress, serverName: relay.TlsServerName, relayServiceID: relay.RelayServiceId,
		relayID: relay.RelayId, relayRunID: relay.RelayRunId, relayLeaseRevision: uint64(relay.RelayLeaseRevision)}
	session, reused, err := forwarder.session(ingressContext(t), target)
	if err != nil || !reused {
		t.Fatalf("warm service assignment was not pooled: reused=%t error=%v", reused, err)
	}
	config.PublicServices.config.PendingTimeout = 2 * time.Second
	_, address := startIngress(t, config)
	client := ingressClient(t, address, "route.example", "192.0.2.4:42000")
	_ = client.SetDeadline(time.Now().Add(2 * time.Second))
	if err := client.Handshake(); err != nil {
		t.Fatal("warm stalled assignment prevented fallback", err)
	}
	exchangePing(t, client)
	result := ingressAwait(t, fallback.result)
	if result.err != nil || result.request != "ping" || fallback.opens.Load() != 1 {
		t.Fatalf("fallback did not deliver exactly once: %+v opens=%d", result, fallback.opens.Load())
	}
	request := ingressAwait(t, stalled)
	if request.Header.VisitorConnectionID != result.visitorConnectionID || request.Header.VisitorConnectionID == warmHeader.VisitorConnectionID {
		t.Fatal("stalled service opening lost the fallback visitor identity", request.Header)
	}
	fallbackHeader := ingressAwait(t, fallbackHeaders)
	if fallbackHeader.ServiceID != ref.ServiceID || fallbackHeader.ServiceRunID != ref.ServiceRunID || fallbackHeader.RunNumber != ref.RunNumber ||
		fallbackHeader.VisitorConnectionID != request.Header.VisitorConnectionID || fallbackHeader.ConnectionSlot != 1 ||
		fallbackHeader.PublisherConnectionID != control.relays[1].PublisherConnectionId ||
		result.header.Source != netip.MustParseAddrPort("192.0.2.4:42000") || result.header.Destination != netip.MustParseAddrPort("203.0.113.10:443") {
		t.Fatal("fallback changed its service run, assignment, or trusted PROXY metadata", fallbackHeader, result.header)
	}
	if err := request.Stream().SetReadDeadline(time.Now()); err != nil {
		t.Fatal(err)
	}
	if n, _ := request.Stream().Read(make([]byte, 1)); n != 0 {
		t.Fatal("unacknowledged relay received metadata or visitor bytes after fallback")
	}
	if session.Err() != nil || !forwarder.currentSession(target.key(), session) {
		t.Fatal("stalled opening discarded a pooled session and its sibling")
	}
	releaseSibling()
	_ = warm.SetReadDeadline(time.Now().Add(fixtureTimeout))
	response := make([]byte, 2)
	if _, err := io.ReadFull(warm, response); err != nil || string(response) != "ok" {
		t.Fatalf("sibling stream did not survive: %q %v", response, err)
	}
	if got := server.accepted.Load(); got != 1 {
		t.Fatalf("pooled relay sessions=%d, want 1", got)
	}
	if err := warm.Close(); err != nil {
		t.Fatal("close warm sibling", err)
	}
	if err := closeForwarder(); err != nil {
		t.Fatal("service forwarder did not join", err)
	}
	server.cancel()
	_ = server.listener.Close()
	server.active.Wait()
}

type failingForwardingConnector struct {
	relayConnector
	opened  chan int
	release [2]chan struct{}
	calls   atomic.Int32
	failure error
}

func (c *failingForwardingConnector) Connect(ctx context.Context, target relayTarget) (muxsession.Session, error) {
	transport, err := c.relayConnector.Connect(ctx, target)
	if err != nil {
		return nil, err
	}
	return &failingForwardingTransport{Session: transport, connector: c, index: int(c.calls.Add(1)) - 1}, nil
}

type failingForwardingTransport struct {
	muxsession.Session
	connector *failingForwardingConnector
	index     int
	opens     atomic.Int32
}

func (s *failingForwardingTransport) OpenStream(ctx context.Context) (muxsession.Stream, error) {
	if s.opens.Add(1) == 1 {
		return s.Session.OpenStream(ctx)
	} // real control handshake.
	if s.index >= len(s.connector.release) {
		return nil, errors.New("unexpected third connection")
	}
	s.connector.opened <- s.index
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-s.connector.release[s.index]:
		return nil, s.connector.failure
	}
}

func TestForwarderRetryCanReuseConcurrentReplacement(t *testing.T) {
	material := newForwardingTestMaterial(t)
	requests := make(chan forwardingTestRequest, 1)
	server := startForwardingTestServer(t, material, func(ctx context.Context, transport muxsession.Session) error {
		return captureForwardingRequests(ctx, transport, requests)
	})
	forwarder := newTestForwarder(t, material)
	connector := &failingForwardingConnector{relayConnector: forwarder.connector, opened: make(chan int, 2),
		release: [2]chan struct{}{make(chan struct{}), make(chan struct{})}, failure: errors.New("stream open failed")}
	forwarder.connector = connector
	backend := mustOnlyBackend(t, forwarder, forwardingTestEntry(time.Now(), server.address())).(forwardingBackend)
	ctx, cancel := context.WithTimeout(t.Context(), fixtureTimeout)
	defer cancel()
	first, reused, err := forwarder.session(ctx, backend.target)
	if err != nil || reused {
		t.Fatalf("warm initial session: reused=%t error=%v", reused, err)
	}
	done := ingressWorker(t, cancel, func() error { _, err := backend.Start(ctx, "visitor_retry", false, nil, nil); return err })
	if index := ingressAwait(t, connector.opened); index != 0 {
		t.Fatalf("first attempt=%d", index)
	}
	// another visitor invalidates the first session and establishes a replacement
	// while this visitor's first open has not yet returned its failure.
	forwarder.invalidate(t.Context(), backend.target.key(), first)
	second, reused, err := forwarder.session(ctx, backend.target)
	if err != nil || reused || second == first {
		t.Fatalf("concurrent replacement: reused=%t error=%v", reused, err)
	}
	close(connector.release[0])
	if index := ingressAwait(t, connector.opened); index != 1 {
		t.Fatalf("retry attempt=%d", index)
	}
	close(connector.release[1])
	if err := ingressAwait(t, done); !errors.Is(err, connector.failure) {
		t.Fatalf("retry exhaustion=%v", err)
	}
	if connector.calls.Load() != 2 {
		t.Fatalf("connections=%d; expected bounded retry", connector.calls.Load())
	}
	select {
	case request := <-requests:
		t.Fatalf("forwarded bytes before stream acceptance: %q", request.payload)
	default:
	}
}

type singleStreamFailureConnector struct {
	relayConnector
	failure error
}

func (c singleStreamFailureConnector) Connect(ctx context.Context, target relayTarget) (muxsession.Session, error) {
	transport, err := c.relayConnector.Connect(ctx, target)
	if err != nil {
		return nil, err
	}
	return &singleStreamFailureTransport{Session: transport, failure: c.failure}, nil
}

type singleStreamFailureTransport struct {
	muxsession.Session
	failure error
	opens   atomic.Int32
}

func (s *singleStreamFailureTransport) OpenStream(ctx context.Context) (muxsession.Stream, error) {
	if s.opens.Add(1) == 2 { // the control handshake opened the first stream.
		return nil, s.failure
	}
	return s.Session.OpenStream(ctx)
}

func TestForwarderPreservesPooledSessionAfterVisitorStreamFailure(t *testing.T) {
	material := newForwardingTestMaterial(t)
	requests := make(chan forwardingTestRequest, 1)
	server := startForwardingTestServer(t, material, func(ctx context.Context, transport muxsession.Session) error {
		return captureForwardingRequests(ctx, transport, requests)
	})
	forwarder := newTestForwarder(t, material)
	failure := errors.New("one visitor stream failed")
	forwarder.connector = singleStreamFailureConnector{relayConnector: forwarder.connector, failure: failure}
	backend := mustOnlyBackend(t, forwarder, forwardingTestEntry(time.Now(), server.address())).(forwardingBackend)
	session, _, err := forwarder.session(ingressContext(t), backend.target)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := backend.Start(ingressContext(t), "visitor_failed", false, nil, nil); !errors.Is(err, failure) {
		t.Fatalf("failed visitor stream = %v", err)
	}
	if session.Err() != nil || !forwarder.currentSession(backend.target.key(), session) {
		t.Fatal("failed visitor invalidated a healthy pooled session")
	}
	connection, err := backend.Start(ingressContext(t), "visitor_next", false, nil, nil)
	if err != nil {
		t.Fatalf("next visitor stream: %v", err)
	}
	defer connection.Close()
	if _, err := connection.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	response := make([]byte, 4)
	if _, err := io.ReadFull(connection, response); err != nil || string(response) != "pong" {
		t.Fatalf("next visitor response = %q, %v", response, err)
	}
	if got := server.accepted.Load(); got != 1 {
		t.Fatalf("pooled relay sessions = %d, want 1", got)
	}
}

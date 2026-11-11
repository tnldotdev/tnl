package ingress

import (
	"bytes"
	"context"
	"errors"
	"io"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/transport/muxsession"
	"github.com/tnldotdev/tnl/internal/transport/proxyproto"
	"github.com/tnldotdev/tnl/internal/transport/tunnel"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

func TestForwarderWarmStalledAssignmentFallsBackBeforeVisitorBytes(t *testing.T) {
	material := newForwardingTestMaterial(t)
	warmed := make(chan tunnel.InternalForwardingRequest, 1)
	stalled := make(chan *tunnel.IncomingPublicForwardingStream, 1)
	checkSibling := make(chan struct{})
	server := startForwardingTestServer(t, material, func(ctx context.Context, transport muxsession.Session) error {
		session, _, err := tunnel.Accept(ctx, transport, func(_ context.Context, message tunnelv1.Message) error {
			if message.Role != tunnelv1.Ingress || message.Credential != forwardingClusterSecret {
				return &tunnel.ProtocolError{Code: tunnelv1.Unauthenticated}
			}
			return nil
		})
		if err != nil {
			return err
		}
		defer session.Close()
		first, err := session.AcceptInternalForwardingStream(ctx)
		if err != nil {
			return err
		}
		if err := first.Accept(); err != nil {
			return err
		}
		warmed <- first
		second, err := session.AcceptInternalForwardingStream(ctx)
		if err != nil {
			return err
		}
		// withhold acceptance after this exact session/assignment was warmed.
		stalled <- second.(*tunnel.IncomingPublicForwardingStream)
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
	forwarder := newTestForwarder(t, material)
	backend := mustOnlyBackend(t, forwarder, forwardingTestEntry(time.Now(), server.address())).(forwardingBackend)
	warm, err := backend.Start(ingressContext(t), "visitor_warm", false, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	ownIngressConn(t, warm)
	ingressAwait(t, warmed)
	session, _, err := forwarder.session(ingressContext(t), backend.target)
	if err != nil {
		t.Fatal(err)
	}
	fallback := newTLSBackend(t)
	config := publicURLConfig(backend, contextBackend{fallback})
	config.OpenTimeout = 2 * time.Second
	_, address := startIngress(t, config)
	client := ingressClient(t, address, "route.example", "")
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
	_, remainder, err := proxyproto.Decode(bytes.NewReader(request.TakeInitial()))
	if err != nil {
		t.Fatal("stalled relay lost PROXY metadata", err)
	}
	initial, err := io.ReadAll(remainder)
	if err != nil || !request.Header.ConfirmBeforeBytes || len(initial) != 0 || request.Header.VisitorConnectionID != result.visitorConnectionID {
		t.Fatal("stalled relay received visitor bytes or lost the connection identity", request.Header)
	}
	if err := request.Stream().SetReadDeadline(time.Now()); err != nil {
		t.Fatal(err)
	}
	if n, _ := request.Stream().Read(make([]byte, 1)); n != 0 {
		t.Fatal("stalled relay received a visitor byte after fallback")
	}
	if session.Err() != nil || !forwarder.currentSession(backend.target.key(), session) {
		t.Fatal("stalled opening discarded a pooled session and its sibling")
	}
	close(checkSibling)
	_ = warm.SetReadDeadline(time.Now().Add(fixtureTimeout))
	response := make([]byte, 2)
	if _, err := io.ReadFull(warm, response); err != nil || string(response) != "ok" {
		t.Fatalf("sibling stream did not survive: %q %v", response, err)
	}
	if got := server.accepted.Load(); got != 1 {
		t.Fatalf("pooled relay sessions=%d, want 1", got)
	}
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

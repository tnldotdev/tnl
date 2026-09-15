package ingress

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/muxsession"
)

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
	} // Real control handshake.
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
	done := ingressWorker(t, cancel, func() error { _, err := backend.Open(ctx, "visitor_retry"); return err })
	if index := ingressAwait(t, connector.opened); index != 0 {
		t.Fatalf("first attempt=%d", index)
	}
	// Another visitor invalidates the first session and establishes a replacement
	// while this visitor's first open has not yet returned its failure.
	forwarder.invalidate(backend.target.key(), first)
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

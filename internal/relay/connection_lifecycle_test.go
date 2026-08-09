package relay

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"math/big"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/muxsession"
	"github.com/tnldotdev/tnl/internal/tunnel"
	"github.com/tnldotdev/tnl/pkg/api/relayv1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

func relayAwait[T any](t *testing.T, ch <-chan T) T {
	t.Helper()
	select {
	case v := <-ch:
		return v
	case <-time.After(5 * time.Second):
		t.Fatal("relay worker timed out")
		var zero T
		return zero
	}
}
func relayWorker(t *testing.T, unblock func(), run func() error) <-chan error {
	t.Helper()
	result, done := make(chan error, 1), make(chan struct{})
	t.Cleanup(func() { unblock(); relayAwait(t, done) })
	go func() { defer close(done); result <- run() }()
	return result
}

// Lifecycle tests use the real TLS/yamux transport so closing a session also
// interrupts streams whose publisher acknowledgement is still pending.
func publisherFixture(t *testing.T, id string, revision uint64) (*PublisherConnection, *tunnel.Session) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	t.Cleanup(cancel)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert := &x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: []string{"relay.test"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	ref := tunnelv1.PublisherConnectionRef{RouteID: "route_1", RouteSessionID: "session_1", RouteVersion: 2, PublisherConnectionID: id, ConnectionSlot: 0, ConnectionAssignmentRevision: revision, RelayServiceID: "service_1"}
	type accepted struct {
		s   *tunnel.Session
		err error
	}
	result := make(chan accepted, 1)
	relayWorker(t, func() { cancel(); _ = listener.Close() }, func() error {
		c, err := listener.Accept()
		if err != nil {
			result <- accepted{err: err}
			return nil
		}
		defer c.Close()
		stop := context.AfterFunc(ctx, func() { _ = c.Close() })
		defer stop()
		_ = c.SetDeadline(time.Now().Add(10 * time.Second))
		transport, err := muxsession.AcceptTLSYamux(ctx, c, &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}, muxsession.TLSYamuxConfig{})
		if err != nil {
			result <- accepted{err: err}
			return nil
		}
		defer transport.Close()
		s, _, err := tunnel.Accept(ctx, transport, func(_ context.Context, m tunnelv1.Message) error {
			if m.PublisherConnection == nil || *m.PublisherConnection != ref {
				return errors.New("unexpected publisher reference")
			}
			return nil
		})
		if s != nil {
			defer s.Close()
		}
		result <- accepted{s, err}
		if err == nil {
			<-ctx.Done()
		}
		return nil
	})
	transport, err := (muxsession.TLSYamuxConnector{TLSConfig: &tls.Config{InsecureSkipVerify: true}}).Connect(ctx, muxsession.Endpoint{Address: listener.Addr().String(), ServerName: "relay.test"}) // Self-signed local fixture.
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = transport.Close() })
	publisher, err := tunnel.Dial(ctx, transport, tunnelv1.Message{Type: tunnelv1.Hello, ProtocolVersion: 1, Role: tunnelv1.Publisher, Credential: "credential", PublisherConnection: &ref})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = publisher.Close() })
	server := relayAwait(t, result)
	if server.err != nil {
		t.Fatal(server.err)
	}
	t.Cleanup(func() { _ = server.s.Close() })
	claimed := relayv1.ClaimedPublisherConnection{RouteId: "route_1", RouteSessionId: "session_1", RouteVersion: 2, PublisherConnectionId: id, ConnectionSlot: 0, ConnectionAssignmentRevision: int64(revision), RelayServiceId: "service_1", RelayId: "relay_1", RelayRunId: "run_1", RelayLeaseRevision: 4}
	connection, err := NewPublisherConnection(ref, claimed, server.s)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = connection.Close() })
	return connection, publisher
}

func lifecycleHeader(id string, revision uint64) tunnelv1.InternalForwardingHeader {
	return tunnelv1.InternalForwardingHeader{ProtocolVersion: 1, Kind: tunnelv1.InternalForwardingStream, VisitorConnectionID: "visitor_1", RouteID: "route_1", RouteSessionID: "session_1", RouteVersion: 2, PublisherConnectionID: id, ConnectionSlot: 0, ConnectionAssignmentRevision: revision, RelayServiceID: "service_1", RelayID: "relay_1", RelayRunID: "run_1", RelayLeaseRevision: 4, RouteExpiresAt: time.Now().Add(time.Minute), LeaseExpiresAt: time.Now().Add(time.Minute)}
}

func TestRegistryInsertionReplacementAndStaleRemoval(t *testing.T) {
	registry := NewRegistry()
	t.Cleanup(func() { _ = registry.Close() })
	first, _ := publisherFixture(t, "connection_1", 3)
	if err := registry.Insert(first); err != nil {
		t.Fatal(err)
	}
	if n, s := registry.Load(); n != 1 || s != 0 {
		t.Fatalf("load=%d/%d", n, s)
	}
	var duplicate *tunnel.ProtocolError
	if err := registry.Insert(first); !errors.As(err, &duplicate) || duplicate.Code != tunnelv1.DuplicatePublisherConnection {
		t.Fatalf("duplicate insert = %v", err)
	}
	stale, _ := publisherFixture(t, "connection_stale", 2)
	var protocolErr *tunnel.ProtocolError
	if err := registry.Insert(stale); !errors.As(err, &protocolErr) || protocolErr.Code != tunnelv1.StaleConnectionAssignment {
		t.Fatalf("stale insert=%v", err)
	}
	next, _ := publisherFixture(t, "connection_2", 4)
	if err := registry.Insert(next); err != nil {
		t.Fatal(err)
	}
	if _, err := first.OpenVisitor(t.Context(), "visitor_1"); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("replaced connection still open: %v", err)
	}
	if registry.Remove(first) {
		t.Fatal("stale removal succeeded")
	}
	if got, ok := registry.Candidate(lifecycleHeader("connection_2", 4), time.Now()); !ok || got != next {
		t.Fatal("stale removal removed replacement")
	}
	if got, ok := registry.Candidate(lifecycleHeader("connection_1", 3), time.Now()); ok || got != nil {
		t.Fatal("replaced assignment still selectable")
	}
	if !registry.Remove(next) || registry.Remove(next) {
		t.Fatal("remove was not exact and idempotent")
	}
	if n, s := registry.Load(); n != 0 || s != 0 {
		t.Fatalf("load after removal=%d/%d", n, s)
	}
	if err := registry.Close(); err != nil {
		t.Fatal(err)
	}
	if err := registry.Insert(stale); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("insert after close=%v", err)
	}
}

type waitingDrainContext struct {
	context.Context
	waiting chan struct{}
	once    sync.Once
}

func (c *waitingDrainContext) Done() <-chan struct{} {
	c.once.Do(func() { close(c.waiting) })
	return c.Context.Done()
}

func TestPublisherConnectionDrainWaitsForStreamAndRejectsNewWork(t *testing.T) {
	connection, publisher := publisherFixture(t, "connection_1", 3)
	registry := NewRegistry()
	t.Cleanup(func() { _ = registry.Close() })
	if err := registry.Insert(connection); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	t.Cleanup(cancel)
	peer := make(chan *tunnel.IncomingPublisherStream, 1)
	accepted := relayWorker(t, func() { cancel(); _ = publisher.Close() }, func() error {
		incoming, err := publisher.AcceptPublisherStream(ctx)
		if err != nil {
			return err
		}
		if incoming.Header != (tunnelv1.PublisherStreamHeader{ProtocolVersion: 1, Kind: tunnelv1.VisitorStream, VisitorConnectionID: "visitor_1", RouteID: "route_1", RouteSessionID: "session_1", RouteVersion: 2, PublisherConnectionID: "connection_1", ConnectionAssignmentRevision: 3}) {
			_ = incoming.Stream.Close()
			return errors.New("incorrect visitor header")
		}
		peer <- incoming
		return incoming.Accept()
	})
	stream, err := connection.OpenVisitor(ctx, "visitor_1")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = stream.Close() })
	_ = stream.SetDeadline(time.Now().Add(5 * time.Second))
	incoming := relayAwait(t, peer)
	t.Cleanup(func() { _ = incoming.Stream.Close() })
	_ = incoming.Stream.SetDeadline(time.Now().Add(5 * time.Second))
	if err := relayAwait(t, accepted); err != nil {
		t.Fatal(err)
	}
	if n, s := registry.Load(); n != 1 || s != 1 {
		t.Fatalf("active load=%d/%d", n, s)
	}
	drainCtx := &waitingDrainContext{Context: ctx, waiting: make(chan struct{})}
	drained := relayWorker(t, func() { cancel(); _ = connection.Close() }, func() error { return registry.Drain(drainCtx) })
	relayAwait(t, drainCtx.waiting)
	if _, err := connection.OpenVisitor(ctx, "visitor_2"); !errors.Is(err, ErrDraining) {
		t.Fatalf("open during drain=%v", err)
	}
	if err := registry.Insert(connection); !errors.Is(err, ErrDraining) {
		t.Fatalf("insert during drain=%v", err)
	}
	if _, ok := registry.Candidate(lifecycleHeader("connection_1", 3), time.Now()); ok {
		t.Fatal("draining registry selected candidate")
	}
	// Existing streams survive the admission gate.
	if _, err := stream.Write([]byte("live")); err != nil {
		t.Fatal(err)
	}
	var payload [4]byte
	if _, err := io.ReadFull(incoming.Stream, payload[:]); err != nil || string(payload[:]) != "live" {
		t.Fatalf("active stream=%q, %v", payload, err)
	}
	select {
	case err := <-drained:
		t.Fatalf("drained before stream close: %v", err)
	default:
	}
	_ = stream.Close()
	_ = stream.Close()
	if err := relayAwait(t, drained); err != nil {
		t.Fatal(err)
	}
	if n, s := registry.Load(); n != 1 || s != 0 {
		t.Fatalf("drained load=%d/%d", n, s)
	}
}

func TestPublisherConnectionCloseInterruptsPendingOpen(t *testing.T) {
	connection, publisher := publisherFixture(t, "connection_1", 3)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	t.Cleanup(cancel)
	result := relayWorker(t, func() { cancel(); _ = connection.session.Close() }, func() error {
		stream, err := connection.OpenVisitor(ctx, "visitor_pending")
		if stream != nil {
			_ = stream.Close()
		}
		return err
	})
	incoming, err := publisher.AcceptPublisherStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = incoming.Stream.Close() })
	_ = incoming.Stream.SetDeadline(time.Now().Add(5 * time.Second))
	closed := relayWorker(t, func() { _ = connection.session.Close() }, connection.Close)
	var timeout net.Error
	if err := relayAwait(t, result); err == nil || errors.As(err, &timeout) && timeout.Timeout() {
		t.Fatalf("closure did not interrupt pending open: %v", err)
	}
	if err := relayAwait(t, closed); err != nil {
		t.Fatal(err)
	}
	if _, err := connection.OpenVisitor(ctx, "visitor_after"); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("open after close=%v", err)
	}
	connection.mu.Lock()
	defer connection.mu.Unlock()
	if connection.opening != 0 || len(connection.streams) != 0 {
		t.Fatal("close retained opening/stream accounting")
	}
}

func TestPublisherConnectionDrainCancellationClosesPendingOpen(t *testing.T) {
	connection, publisher := publisherFixture(t, "connection_1", 3)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	t.Cleanup(cancel)
	opened := relayWorker(t, func() { cancel(); _ = connection.session.Close() }, func() error {
		stream, err := connection.OpenVisitor(ctx, "visitor_pending")
		if stream != nil {
			_ = stream.Close()
		}
		return err
	})
	incoming, err := publisher.AcceptPublisherStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = incoming.Stream.Close() })
	drainCtx, stop := context.WithCancel(ctx)
	waiting := &waitingDrainContext{Context: drainCtx, waiting: make(chan struct{})}
	drained := relayWorker(t, func() { stop(); _ = connection.session.Close() }, func() error { return connection.Drain(waiting) })
	relayAwait(t, waiting.waiting)
	stop()
	if err := relayAwait(t, drained); !errors.Is(err, context.Canceled) {
		t.Fatalf("drain cancellation = %v", err)
	}
	if err := relayAwait(t, opened); err == nil {
		t.Fatal("pending open survived forced drain")
	}
	if _, err := connection.OpenVisitor(ctx, "after_drain"); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("forced drain did not close connection: %v", err)
	}
}

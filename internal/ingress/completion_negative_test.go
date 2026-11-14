package ingress

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/observability"
	"github.com/tnldotdev/tnl/internal/transport/proxyproto"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

// gate only the real backend TCP half-close, after all visitor bytes were read.
type completionTCPConn struct {
	*net.TCPConn
	entered chan struct{}
	proceed chan struct{}
	result  chan error
	calls   atomic.Int32
}

func (c *completionTCPConn) CloseWrite() error {
	if c.calls.Add(1) != 1 {
		return errors.New("duplicate completion half-close")
	}
	close(c.entered)
	<-c.proceed
	err := c.TCPConn.CloseWrite()
	c.result <- err
	return err
}

type completionMetrics struct {
	testMetrics
	visitors atomic.Int32
	opens    atomic.Int32
	opened   atomic.Int32
	streams  atomic.Int32
}

func (m *completionMetrics) ObserveVisitor(outcome observability.VisitorOutcome) {
	m.visitors.Add(1)
	select {
	case m.visitorOutcomes <- string(outcome):
	default:
	}
}

func (m *completionMetrics) ObserveVisitorOpen(success bool, _ time.Duration) {
	m.opens.Add(1)
	if success {
		m.opened.Add(1)
	}
}

func (m *completionMetrics) SetIngressStreams(streams int) { m.streams.Store(int32(streams)) }

type completionCleanup struct {
	result chan error
	calls  atomic.Int32
}

func (o *completionCleanup) ObserveOperationContext(_ context.Context, name observability.ServerOperation, err error, _ time.Duration) {
	if name == observability.OpIngressBackendCleanup {
		o.calls.Add(1)
		select {
		case o.result <- err:
		default:
		}
	}
}

type restrictedCompletion struct {
	outcome   string
	err       error
	halfClose error
}

func completionAwait[T any](t *testing.T, ctx context.Context, result <-chan T) T {
	t.Helper()
	select {
	case value := <-result:
		return value
	case <-ctx.Done():
		t.Fatal("restricted completion exceeded original fixture budget")
		var zero T
		return zero
	}
}

func restrictedCompletionFixture(t *testing.T, prematureClose bool) restrictedCompletion {
	t.Helper()
	// keep one original fixtureTimeout for all setup, TLS, gates and completion.
	deadline := time.Now().Add(fixtureTimeout)
	ctx, cancel := context.WithDeadline(t.Context(), deadline)
	t.Cleanup(cancel)
	listener, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal("listen for completion fixture")
	}
	t.Cleanup(func() { _ = listener.Close() })
	if err := listener.SetDeadline(deadline); err != nil {
		t.Fatal("set completion accept deadline")
	}
	connection, err := (&net.Dialer{Deadline: deadline}).DialContext(ctx, "tcp", listener.Addr().String())
	if err != nil {
		t.Fatal("dial completion backend")
	}
	t.Cleanup(func() { _ = connection.Close() })
	peer, err := listener.AcceptTCP()
	if err != nil {
		t.Fatal("accept completion backend")
	}
	t.Cleanup(func() { _ = peer.Close() })
	for _, conn := range []net.Conn{connection, peer} {
		if err := conn.SetDeadline(deadline); err != nil {
			t.Fatal("set completion socket deadline")
		}
	}
	gate := &completionTCPConn{TCPConn: connection.(*net.TCPConn), entered: make(chan struct{}), proceed: make(chan struct{}), result: make(chan error, 2)}
	unblock := sync.OnceFunc(func() { close(gate.proceed) })
	t.Cleanup(unblock)
	metrics := &completionMetrics{testMetrics: testMetrics{visitorOutcomes: make(chan string, 2)}}
	cleanup := &completionCleanup{result: make(chan error, 2)}
	failures := make(chan error, 2)
	var failureCalls, openingCalls atomic.Int32
	relayHeaders := make(chan tunnelv1.ServiceForwardingHeader, 2)
	config := serviceIngressConfig(t, func(ctx context.Context, header tunnelv1.ServiceForwardingHeader) (net.Conn, error) {
		if openingCalls.Add(1) != 1 {
			return nil, errors.New("completion relay unexpectedly opened twice")
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		relayHeaders <- header
		return gate, nil
	})
	p := config.PublicServices
	control := p.config.Control.(*httpsServiceControl)
	control.pending = true
	control.recheckStarted, control.recheckGate, control.promoteStarted = make(chan struct{}, 2), make(chan struct{}), make(chan struct{}, 2)
	unblockRecheck := sync.OnceFunc(func() { close(control.recheckGate) })
	t.Cleanup(unblockRecheck)
	config.Metrics, config.Observer = metrics, cleanup
	p.config.Metrics, p.config.Observer = metrics, cleanup
	config.OnError = func(err error) {
		failureCalls.Add(1)
		select {
		case failures <- err:
		default:
		}
	}
	server, address := startIngress(t, config)
	certificate := testCertificate(t, "route.example")
	headers := make(chan proxyproto.Header, 1)
	peerResult, peerDone := make(chan error, 1), make(chan struct{})
	// install every unblock and join before starting the peer or a TLS operation.
	t.Cleanup(func() {
		unblock()
		unblockRecheck()
		_ = connection.Close()
		_ = peer.Close()
		ingressAwait(t, peerDone)
		server.closeConnections()
		server.active.Wait()
	})
	go func() {
		defer close(peerDone)
		peerResult <- finishCompletionPeer(peer, certificate, headers)
	}()
	visitor := ingressClient(t, address, "route.example", "192.0.2.4:42000")
	if err := visitor.SetDeadline(deadline); err != nil {
		t.Fatal("set original visitor deadline")
	}
	if _, err := visitor.Write([]byte("ping")); err != nil {
		t.Fatal("write completion ping")
	}
	var pong [4]byte
	if _, err := io.ReadFull(visitor, pong[:]); err != nil || string(pong[:]) != "pong" {
		t.Fatal("completion pong changed")
	}
	header := completionAwait(t, ctx, headers)
	if header.Source != netip.MustParseAddrPort("192.0.2.4:42000") || header.Destination != netip.MustParseAddrPort("203.0.113.10:443") {
		t.Fatal("completion PROXY endpoints changed")
	}
	claim, forwarding := completionAwait(t, ctx, control.claims), completionAwait(t, ctx, relayHeaders)
	if claim.Hostname == nil || *claim.Hostname != "route.example" || claim.DestinationPort != 443 || claim.ObservedSourceIp != "192.0.2.4" ||
		forwarding.ServiceID != control.service || forwarding.ServiceRunID != control.run || forwarding.RunNumber != 1 ||
		forwarding.VisitorConnectionID != claim.VisitorConnectionId || forwarding.SourceIP != "192.0.2.4" ||
		forwarding.PublicService == nil || forwarding.PublicService.DestinationPort != 443 {
		t.Fatal("completion lost its service admission or trusted source", claim, forwarding)
	}
	// the first recheck captured pending before its gate. allow the next check to
	// authenticate only after the pending reservation and live stream are visible.
	completionAwait(t, ctx, control.recheckStarted)
	p.mu.Lock()
	sessions, streams := p.sessions, p.streams
	p.mu.Unlock()
	pending, active := publicServiceAdmissionCounts(p)
	if sessions != 1 || pending != 1 || active != 0 || streams != 1 || metrics.streams.Load() != 1 {
		t.Fatalf("restricted service skipped pending capacity: sessions=%d pending=%d active=%d streams=%d", sessions, pending, active, streams)
	}
	control.mu.Lock()
	control.pending, control.authenticated = false, true
	control.mu.Unlock()
	unblockRecheck()
	completionAwait(t, ctx, control.promoteStarted)
	p.mu.Lock()
	sessions, streams = p.sessions, p.streams
	p.mu.Unlock()
	pending, active = publicServiceAdmissionCounts(p)
	if sessions != 1 || pending != 0 || active != 1 || streams != 1 {
		t.Fatalf("authenticated service did not promote exactly once: sessions=%d pending=%d active=%d streams=%d", sessions, pending, active, streams)
	}
	if err := visitor.CloseWrite(); err != nil {
		t.Fatal("visitor TLS close-notify failed")
	}
	if err := visitor.NetConn().(*net.TCPConn).CloseWrite(); err != nil {
		t.Fatal("visitor TCP half-close failed")
	}
	completionAwait(t, ctx, gate.entered)
	// drain the peer's TLS close-notify and TCP FIN before deliberately closing
	// the backend. otherwise its own CloseWrite races our injected failure.
	if n, err := io.Copy(io.Discard, visitor); err != nil || n != 0 {
		t.Fatal("visitor TLS close-notify drain failed", err)
	}
	if n, err := io.Copy(io.Discard, visitor.NetConn()); err != nil || n != 0 {
		t.Fatal("visitor TCP EOF drain failed", err)
	}
	if prematureClose {
		// payload alone cannot make closing the destination before shutdown clean.
		if err := connection.Close(); err != nil {
			t.Fatal("premature backend full close failed")
		}
	}
	unblock()
	halfClose := completionAwait(t, ctx, gate.result)
	if !prematureClose && halfClose != nil {
		t.Fatal("backend TCP half-close failed", halfClose)
	}
	if err := completionAwait(t, ctx, peerResult); err != nil {
		t.Fatal("peer TLS/TCP completion failed", err)
	}
	completionAwait(t, ctx, peerDone)
	outcome := completionAwait(t, ctx, metrics.visitorOutcomes)
	if err := server.Drain(ctx); err != nil {
		t.Fatal("ingress completion did not join")
	}
	completionAwait(t, ctx, server.Done())
	var forwardErr error
	select {
	case forwardErr = <-failures:
	default:
	}
	cleanupErr := completionAwait(t, ctx, cleanup.result)
	if !prematureClose && (forwardErr != nil || cleanupErr != nil) {
		t.Fatal("clean completion returned a forwarding/cleanup failure")
	}
	if metrics.visitors.Load() != 1 || metrics.opens.Load() != 1 || metrics.opened.Load() != 1 || openingCalls.Load() != 1 || gate.calls.Load() != 1 || cleanup.calls.Load() != 1 {
		t.Fatal("restricted open/half-close/outcome was not exact-once")
	}
	wantFailures := int32(0)
	if prematureClose {
		wantFailures = 1
	}
	if failureCalls.Load() != wantFailures {
		t.Fatal("forwarding error callback was not exact-once")
	}
	if len(failures) != 0 || len(cleanup.result) != 0 || len(metrics.visitorOutcomes) != 0 || len(relayHeaders) != 0 || len(control.claims) != 0 || len(control.promoteStarted) != 0 {
		t.Fatal("duplicate completion callback")
	}
	metrics.forwardedMu.Lock()
	upload, download := metrics.forwardedBytes["visitor_to_publisher"], metrics.forwardedBytes["publisher_to_visitor"]
	metrics.forwardedMu.Unlock()
	if upload <= 4 || download <= 4 {
		t.Fatal("completed TLS byte metrics changed")
	}
	server.mu.Lock()
	connections, inspecting, admitted := len(server.connections), server.pending, server.admitted
	server.mu.Unlock()
	if connections != 0 || inspecting != 0 {
		t.Fatal("completion retained server inspection ownership", connections, inspecting)
	}
	for kind, count := range admitted {
		if count != 0 {
			t.Fatal("completion retained server handoff ownership", kind, count)
		}
	}
	p.mu.Lock()
	sessions, streams = p.sessions, p.streams
	connections = len(p.connections)
	p.mu.Unlock()
	pending, active = publicServiceAdmissionCounts(p)
	control.mu.Lock()
	rechecks, closed := control.rechecks, control.closed
	control.mu.Unlock()
	if sessions != 0 || pending != 0 || active != 0 || streams != 0 || connections != 0 || !publicServiceCapacityReleased(p) || metrics.streams.Load() != 0 {
		t.Fatalf("completion retained service ownership: sessions=%d pending=%d active=%d streams=%d connections=%d gauge=%d", sessions, pending, active, streams, connections, metrics.streams.Load())
	}
	if control.recheckActive.Load() != 0 || rechecks < 2 || closed != 1 {
		t.Fatalf("completion missed a service lifecycle boundary: rechecks=%d active rechecks=%d closed=%d", rechecks, control.recheckActive.Load(), closed)
	}
	if err := visitor.Close(); err != nil {
		t.Fatal("visitor final full close failed")
	}
	if err := peer.Close(); err != nil {
		t.Fatal("peer final full close failed")
	}
	t.Logf("completion premature_close=%t payload=true half_close_failed=%t retained_closed_cause=%t workers_joined=true", prematureClose, halfClose != nil, errors.Is(forwardErr, net.ErrClosed))
	if prematureClose {
		t.Logf("actual supported half-close type=%T completion type=%T exact_half_close_cause_retained=%t", halfClose, forwardErr, errors.Is(forwardErr, halfClose))
	}
	return restrictedCompletion{outcome: outcome, err: forwardErr, halfClose: halfClose}
}

func finishCompletionPeer(peer *net.TCPConn, certificate tls.Certificate, headers chan<- proxyproto.Header) error {
	header, replay, err := proxyproto.Decode(peer)
	if err != nil {
		return err
	}
	headers <- header
	secured := tls.Server(&testReaderConn{Conn: peer, reader: replay}, &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS12})
	var ping [4]byte
	if _, err := io.ReadFull(secured, ping[:]); err != nil {
		return err
	}
	if string(ping[:]) != "ping" {
		return errors.New("completion ping changed")
	}
	if _, err := secured.Write([]byte("pong")); err != nil {
		return err
	}
	if err := secured.CloseWrite(); err != nil {
		return fmt.Errorf("peer TLS close-notify: %w", err)
	}
	if err := peer.CloseWrite(); err != nil {
		return fmt.Errorf("peer TCP half-close: %w", err)
	}
	if n, err := io.Copy(io.Discard, secured); err != nil || n != 0 {
		return errors.Join(errors.New("peer TLS close-notify drain failed"), err)
	}
	if n, err := io.Copy(io.Discard, replay); err != nil || n != 0 {
		return errors.Join(errors.New("peer TCP EOF drain failed"), err)
	}
	return nil
}

func TestRestrictedVisitorPayloadDoesNotHideHalfCloseFailure(t *testing.T) {
	result := restrictedCompletionFixture(t, true)
	if result.outcome != "committed_failed" || result.err == nil || !errors.Is(result.halfClose, net.ErrClosed) || !errors.Is(result.err, result.halfClose) {
		t.Fatal("payload hid the real TCP half-close failure or its exact cause")
	}
}

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

	"github.com/tnldotdev/tnl/internal/observability"
	"github.com/tnldotdev/tnl/internal/transport/proxyproto"
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

type completionBackend struct {
	pendingTLSBackend
	pending  atomic.Int32
	ordinary atomic.Int32
}

func (b *completionBackend) Open(ctx context.Context, id string) (net.Conn, error) {
	b.ordinary.Add(1)
	return b.pendingTLSBackend.Open(ctx, id)
}

func (b *completionBackend) OpenPending(ctx context.Context, id string) (net.Conn, error) {
	b.pending.Add(1)
	return b.pendingTLSBackend.OpenPending(ctx, id)
}

type completionMetrics struct {
	testMetrics
	visitors atomic.Int32
	opens    atomic.Int32
	opened   atomic.Int32
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

type completionCleanup struct {
	result chan error
	calls  atomic.Int32
}

func (o *completionCleanup) ObserveOperation(name string, err error, _ time.Duration) {
	if name == "IngressBackendCleanup" {
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
	backend := &completionBackend{pendingTLSBackend: pendingTLSBackend{connection: gate}}
	metrics := &completionMetrics{testMetrics: testMetrics{visitorOutcomes: make(chan string, 2)}}
	cleanup := &completionCleanup{result: make(chan error, 2)}
	failures := make(chan error, 2)
	var failureCalls atomic.Int32
	config := publicURLConfig(backend)
	lookup := config.Lookup
	config.Lookup = func(host string) (PublicURL, LookupReason) {
		url, reason := lookup(host)
		url.AccessMode = "restricted"
		return url, reason
	}
	config.Metrics, config.Observer = metrics, cleanup
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
	visitor := ingressClient(t, address, "route.example", "")
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
	if header.Source != netip.MustParseAddrPort(visitor.LocalAddr().String()) || header.Destination != netip.MustParseAddrPort(address) {
		t.Fatal("completion PROXY endpoints changed")
	}
	if err := visitor.CloseWrite(); err != nil {
		t.Fatal("visitor TLS close-notify failed")
	}
	if err := visitor.NetConn().(*net.TCPConn).CloseWrite(); err != nil {
		t.Fatal("visitor TCP half-close failed")
	}
	completionAwait(t, ctx, gate.entered)
	if prematureClose {
		// payload alone cannot make closing the destination before shutdown clean.
		if err := connection.Close(); err != nil {
			t.Fatal("premature backend full close failed")
		}
	}
	unblock()
	halfClose := completionAwait(t, ctx, gate.result)
	if !prematureClose {
		if halfClose != nil {
			t.Fatal("backend TCP half-close failed")
		}
		if n, err := io.Copy(io.Discard, visitor); err != nil || n != 0 {
			t.Fatal("visitor TLS close-notify drain failed")
		}
		if n, err := io.Copy(io.Discard, visitor.NetConn()); err != nil || n != 0 {
			t.Fatal("visitor TCP EOF drain failed")
		}
	}
	if err := completionAwait(t, ctx, peerResult); err != nil {
		t.Fatal("peer TLS/TCP completion failed")
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
	if metrics.visitors.Load() != 1 || metrics.opens.Load() != 1 || metrics.opened.Load() != 1 || backend.pending.Load() != 1 || backend.ordinary.Load() != 0 || gate.calls.Load() != 1 || cleanup.calls.Load() != 1 {
		t.Fatal("restricted open/half-close/outcome was not exact-once")
	}
	wantFailures := int32(0)
	if prematureClose {
		wantFailures = 1
	}
	if failureCalls.Load() != wantFailures {
		t.Fatal("forwarding error callback was not exact-once")
	}
	if len(failures) != 0 || len(cleanup.result) != 0 || len(metrics.visitorOutcomes) != 0 {
		t.Fatal("duplicate completion callback")
	}
	metrics.forwardedMu.Lock()
	upload, download := metrics.forwardedBytes["visitor_to_publisher"], metrics.forwardedBytes["publisher_to_visitor"]
	metrics.forwardedMu.Unlock()
	if upload <= 4 || download <= 4 {
		t.Fatal("completed TLS byte/open accounting changed")
	}
	server.mu.Lock()
	remaining := len(server.connections) + len(server.backends) + server.admitted[pendingConnection] + server.admitted[visitorConnection]
	server.mu.Unlock()
	if remaining != 0 {
		t.Fatal("completion retained owned connections")
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
		return err
	}
	if err := peer.CloseWrite(); err != nil {
		return err
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

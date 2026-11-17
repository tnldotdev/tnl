package stream

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"testing/synctest"
	"time"

	yamux "github.com/libp2p/go-yamux/v5"
	quic "github.com/quic-go/quic-go"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/transport/muxsession"
	"github.com/tnldotdev/tnl/internal/transport/tunnel"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

type stdioPhysicalWatch struct {
	net.Conn
	closed atomic.Int64
}

func (c *stdioPhysicalWatch) Close() error {
	c.closed.Add(1)
	return c.Conn.Close()
}

type stdioResetWatch struct {
	muxsession.Stream
	resets atomic.Int64
	err    error
}

func (s *stdioResetWatch) Reset(code uint32) error {
	s.resets.Add(1)
	return errors.Join(s.Stream.Reset(code), s.err)
}

func TestStdioAbortJoinsCopyBeforeTerminalWithoutPhysicalClose(t *testing.T) {
	for _, native := range []bool{false, true} {
		for _, resetFailure := range []bool{false, true} {
			t.Run(fmt.Sprintf("native=%v/reset_failure=%v", native, resetFailure), func(t *testing.T) {
				ctx, cancel := context.WithCancelCause(t.Context())
				defer cancel(nil)
				local, peer := net.Pipe()
				defer local.Close()
				defer peer.Close()
				o := newStdioOperation(ctx, local)
				var preparation *stdioOperation
				if native {
					preparation = o
				}
				f := newOwnerTeardownStdioFixture(t, true, false, preparation)
				f.returnWrite.open()
				f.cleanup.latch.open()
				f.outbound.open()
				physical := &stdioPhysicalWatch{Conn: f.prepared.conn}
				raw := &stdioResetWatch{Stream: f.prepared.raw}
				if native {
					raw.Stream = f.prepared.stdio.Stream
					f.prepared.stdio.Stream = raw
				} else {
					f.prepared.raw = raw
				}
				if resetFailure {
					raw.err = errors.New("selected raw reset cleanup failed")
				}
				f.prepared.conn = physical
				use := f.owner.warm
				f.owner.warm = nil
				closeLocal := sync.OnceValue(f.local.Close)
				o.local = &stdioLocalConn{Conn: &connectorLocalConn{Conn: f.local, close: closeLocal}, owner: o}
				copied, proceed, done := make(chan error, 1), make(chan struct{}), make(chan error, 1)
				release := sync.OnceFunc(func() { close(proceed) })
				defer release()
				f.workers.Go(func() {
					// hold the exact production boundary between joined local copy and
					// the authenticated terminal exchange over the retained session.
					result := f.owner.forwardUse(o.ctx, o.local, use, f.owner.run, use.entry)
					copied <- result
					<-proceed
					result = f.owner.terminalUse(use, result)
					o.complete()
					done <- o.finish(result)
				})
				if _, err := io.WriteString(f.input, "request\n"); err != nil {
					t.Fatal(err)
				}
				var request [8]byte
				if _, err := io.ReadFull(f.remote, request[:]); err != nil || string(request[:]) != "request\n" {
					t.Fatal("real visitor TLS did not carry the request", err)
				}
				cancel(context.Canceled)
				if err := ownerTeardownAwait(t, f.ctx, copied); err == nil {
					t.Fatal("aborted copy did not retain its stop evidence before terminal")
				}
				if physical.closed.Load() != 0 || raw.resets.Load() != 0 {
					t.Fatal("local cancellation physically closed or reset visitor TLS before authenticated Abort",
						physical.closed.Load(), raw.resets.Load())
				}
				release()
				err := ownerTeardownAwait(t, f.ctx, done)
				if resetFailure {
					if !errors.Is(err, raw.err) {
						t.Fatal("joined abort lost its exact raw reset cleanup failure", err)
					}
				} else if err != nil {
					t.Fatal("ordinary caller abort did not join cleanly", err)
				}
				if raw.resets.Load() != 1 || physical.closed.Load() != 0 {
					t.Fatal("abort did not perform exactly one raw reset without TLS close-notify",
						raw.resets.Load(), physical.closed.Load())
				}
			})
		}
	}
}

func TestStdioUnusedWarmHoldsPhysicalCleanupThroughTerminal(t *testing.T) {
	for _, selected := range []bool{false, true} {
		t.Run(fmt.Sprint(selected), func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			local, peer := net.Pipe()
			defer peer.Close()
			o := newStdioOperation(ctx, local)
			var preparation *stdioOperation
			if selected {
				preparation = o
			}
			f := newOwnerTeardownStdioFixture(t, true, false, preparation)
			f.cleanup.latch.open()
			f.outbound.open()
			physical := &stdioPhysicalWatch{Conn: f.prepared.conn}
			raw := &stdioResetWatch{Stream: f.prepared.raw, err: errors.New("warm reset failed")}
			f.prepared.conn, f.prepared.raw = physical, raw
			f.prepared.terminalHold = true
			use := f.owner.warm
			f.owner.warm = nil
			cancel()
			<-o.abortDone
			<-o.parentDone
			f.stopOwner(context.Canceled)
			for range 2 {
				if err := f.prepared.Close(); !failure.Only(err, context.Canceled) {
					t.Fatal("unused warm logical shutdown failed", err)
				}
			}
			if physical.closed.Load() != 0 || raw.resets.Load() != 0 {
				t.Fatal("unused warm cancellation physically closed before Abort")
			}
			err := f.owner.terminalUse(use, context.Canceled)
			if !errors.Is(err, raw.err) || errors.Is(err, tunnel.ErrConnectorTerminalFailed) {
				t.Fatal("warm Abort lost its joined result or raw reset cleanup failure", err)
			}
			if err := f.prepared.Close(); !errors.Is(err, raw.err) {
				t.Fatal("held close consumed physicalOnce or lost the later cleanup result", err)
			}
			if physical.closed.Load() != 0 || raw.resets.Load() != 1 {
				t.Fatal("warm Abort did not reset exactly once without TLS close-notify")
			}
			o.complete()
			if err := o.finish(err); !errors.Is(err, raw.err) {
				t.Fatal("unused warm operation lost raw cleanup failure", err)
			}
		})
	}
}

type stdioPipeStream struct{ net.Conn }

func (s stdioPipeStream) Reset(uint32) error { return s.Conn.Close() }
func (stdioPipeStream) CloseWrite() error    { return errors.ErrUnsupported }

func TestStdioAbortWakesPermissionWaitAndJoinsRenewalResult(t *testing.T) {
	for _, independent := range []error{nil, tunnel.ErrConnectorPermissionRejected, context.Canceled, context.DeadlineExceeded, &tls.RecordHeaderError{Msg: "renewal transport failed"}} {
		t.Run(fmt.Sprint(independent), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				local, input := net.Pipe()
				defer input.Close()
				raw, remote := net.Pipe()
				defer remote.Close()
				o := newStdioOperation(ctx, local)
				p := &PreparedConnector{ctx: t.Context(), conn: stdioPipeStream{raw}, raw: stdioPipeStream{raw},
					stream: streamPrepared{}, permission: permissionUsable{}, permissionUntil: time.Now().Add(time.Minute), stop: func() bool { return true }}
				if err := p.bindOperation(o, nil); err != nil {
					t.Fatal(err)
				}
				entered, stopped, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
				unblock := sync.OnceFunc(func() { close(release) })
				defer unblock()
				writer := preparedRenewalFunc(func(ctx context.Context, _ tunnelv1.ConnectorPermissionUpdate) error {
					close(entered)
					<-ctx.Done()
					close(stopped)
					<-release
					return errors.Join(context.Cause(ctx), independent)
				})
				if err := p.queuePermission(preparedPermissionRenewal{writer: writer, until: p.permissionUntil}); err != nil {
					t.Fatal(err)
				}
				<-entered
				done := make(chan error, 1)
				go func() {
					err := p.Forward(o.ctx, o.local)
					err = errors.Join(err, p.Close(), p.releaseTerminal())
					o.complete()
					done <- o.finish(err)
				}()
				if _, err := input.Write([]byte("permission-fenced write")); err != nil {
					t.Fatal(err)
				}
				synctest.Wait() // both copy directions and the permission write are blocked.
				cancel()
				<-stopped
				synctest.Wait()
				select {
				case err := <-done:
					t.Fatal("abort returned before the entered renewal joined", err)
				default:
				}
				unblock()
				err := <-done
				if independent == nil && err != nil || independent != nil && !errors.Is(err, independent) {
					t.Fatal("abort lost the exact renewal result", err)
				}
			})
		})
	}
}

func TestStdioAbortRetainsEarlierTransportDeadline(t *testing.T) {
	for _, transport := range []string{"quic", "wss"} {
		t.Run(transport, func(t *testing.T) {
			raw, _ := stdioTransportPair(t, transport)
			local, peer := net.Pipe()
			defer peer.Close()
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			o := newStdioOperation(ctx, local)
			selected, err := o.bind(raw)
			if err != nil {
				t.Fatal(err)
			}
			if err := o.activate(selected); err != nil {
				t.Fatal(err)
			}
			if err := selected.SetReadDeadline(time.Now().Add(-time.Second)); err != nil {
				t.Fatal(err)
			}
			_, prior := selected.Read(make([]byte, 1))
			if !stdioDeadlineOnly(prior) {
				t.Fatal("fixture did not reach its original transport deadline", prior)
			}
			o.stop(context.Canceled, true)
			cancel()
			_, after := selected.Read(make([]byte, 1))
			if _, owned := after.(*stdioInterruptError); owned {
				t.Fatal("caller abort claimed an already-expired transport deadline")
			}
			o.complete()
			if err := o.finish(errors.Join(prior, after)); err == nil || !errors.Is(err, prior) {
				t.Fatal("caller abort hid the earlier transport deadline", err)
			}
		})
	}
}

func TestStdioCleanupBudgetStartsAtFirstStop(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		local, peer := net.Pipe()
		defer peer.Close()
		ctx, cancel := context.WithCancel(t.Context())
		o := newStdioOperation(ctx, local)
		cleanup := newConnectorCleanup(t.Context(), nil)
		defer cleanup.close()
		cleanup.observe(time.Now().Add(time.Minute))
		o.bindCleanup(cleanup)
		first := time.Now()
		cancel()
		synctest.Wait()
		time.Sleep(2 * time.Second)
		bound, _ := o.cleanup.context().Deadline()
		if !bound.Equal(first.Add(5 * time.Second)) {
			t.Fatal("joining local work restarted the first stop's cleanup budget", bound)
		}
		if !cleanup.until.IsZero() {
			t.Fatal("one stream's abort started the retained owner's cleanup budget")
		}
		o.complete()
		if err := o.finish(nil); err != nil {
			t.Fatal(err)
		}
		time.Sleep(4 * time.Second)
		nextLocal, nextPeer := net.Pipe()
		defer nextPeer.Close()
		nextCtx, nextCancel := context.WithCancel(t.Context())
		next := newStdioOperation(nextCtx, nextLocal)
		next.bindCleanup(cleanup)
		nextStop := time.Now()
		nextCancel()
		synctest.Wait()
		if bound, _ := next.cleanup.context().Deadline(); !bound.Equal(nextStop.Add(5*time.Second)) || next.cleanup.context().Err() != nil {
			t.Fatal("a later stream inherited an earlier stream's spent cleanup budget", bound)
		}
		next.complete()
		if err := next.finish(nil); err != nil {
			t.Fatal(err)
		}
	})
}

func TestStdioOrdinaryCancellationJoinsOneStream(t *testing.T) {
	for _, transport := range []string{"quic", "wss"} {
		t.Run(transport, func(t *testing.T) {
			f := newConnectorFixture(t, transport)
			local, peer := net.Pipe()
			defer peer.Close()
			ctx, cancel := context.WithCancelCause(t.Context())
			defer cancel(nil)
			config := f.config
			config.Ready = nil
			done := make(chan error, 1)
			go func() { done <- Stream(ctx, &ownedStdioPipe{Conn: local}, config) }()
			_ = peer.SetDeadline(time.Now().Add(5 * time.Second))
			if _, err := io.WriteString(peer, "stdio bytes"); err != nil {
				t.Fatal(err)
			}
			response := make([]byte, len("stdio bytes"))
			if _, err := io.ReadFull(peer, response); err != nil || string(response) != "stdio bytes" {
				t.Fatal("stdio did not forward its bytes", err)
			}
			cancel(context.Canceled)
			select {
			case err := <-done:
				if err != nil {
					t.Fatalf("ordinary cancellation returned a synthetic failure: %v", err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("canceled stdio did not join")
			}
		})
	}
}

type stdioResolveControl struct {
	Control
	entered chan struct{}
}

// the peer stays open for the test, so a closed-pipe write on this local
// connection can only come from the operation's own close.
type ownedStdioPipe struct {
	net.Conn
	aborted bool
	mu      sync.Mutex
}

func (c *ownedStdioPipe) Abort(error) error {
	c.mu.Lock()
	c.aborted = true
	c.mu.Unlock()
	return c.Conn.Close()
}

func (c *ownedStdioPipe) OwnsAbortError(err error) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.aborted && err == io.ErrClosedPipe
}

func (c stdioResolveControl) ResolveService(ctx context.Context, _ string) (Run, error) {
	close(c.entered)
	<-ctx.Done()
	return Run{}, context.Cause(ctx)
}

func TestStdioCancellationDuringPreparationJoins(t *testing.T) {
	for _, transport := range []string{"quic", "wss"} {
		t.Run(transport, func(t *testing.T) {
			f := newConnectorFixture(t, transport)
			local, peer := net.Pipe()
			defer peer.Close()
			ctx, cancel := context.WithCancelCause(t.Context())
			defer cancel(nil)
			entered := make(chan struct{})
			config := f.config
			config.Control = stdioResolveControl{Control: config.Control, entered: entered}
			done := make(chan error, 1)
			go func() { done <- Stream(ctx, local, config) }()
			select {
			case <-entered:
			case <-time.After(5 * time.Second):
				t.Fatal("stdio did not reach preparation")
			}
			cancel(context.Canceled)
			select {
			case err := <-done:
				if err != nil {
					t.Fatal("ordinary cancellation during preparation did not join cleanly", err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("canceled preparation did not join")
			}
		})
	}
}

type stdioPanicIs struct{}

func (*stdioPanicIs) Error() string { return "custom Is must not classify a cancellation" }
func (*stdioPanicIs) Is(error) bool { panic("cancellation classification invoked custom Is") }

type stdioCycle struct{}

func (*stdioCycle) Error() string     { return "cyclic failure" }
func (e *stdioCycle) Unwrap() []error { return []error{net.ErrClosed, e} }

func TestStdioAbortOnlyAcceptsExactOperationEvidence(t *testing.T) {
	o, another := &stdioOperation{}, &stdioOperation{}
	o.selected, another.selected = &stdioStream{owner: o}, &stdioStream{owner: another}
	local := &stdioLocalAbortError{owner: o, cause: io.ErrClosedPipe}
	reset := &stdioAbortError{owner: o, stream: o.selected, cause: &yamux.StreamError{}}
	prepared := &stdioPreparedAbortError{owner: o, stream: o.selected}
	for _, independent := range []error{
		net.ErrClosed, os.ErrClosed, io.ErrClosedPipe,
		os.ErrDeadlineExceeded, yamux.ErrTimeout,
		&yamux.StreamError{}, &quic.StreamError{},
		&yamux.StreamError{ErrorCode: 7}, &quic.StreamError{Remote: true},
		&stdioLocalAbortError{owner: another, cause: net.ErrClosed},
		&stdioAbortError{owner: another, stream: another.selected, cause: &yamux.StreamError{}},
		&stdioAbortError{owner: o, stream: another.selected, cause: &yamux.StreamError{}},
		&stdioPreparedAbortError{owner: another, stream: another.selected},
		&stdioPreparedAbortError{owner: o, stream: another.selected},
		errors.New("independent copy failure"), io.EOF, fmt.Errorf("output: %w", io.EOF),
		syscall.EPIPE, syscall.ECONNRESET,
		failure.Wrap("output", failure.TunnelUnavailable, net.ErrClosed),
		&tls.RecordHeaderError{Msg: "independent TLS failure"},
		ErrServiceConnection,
		&CleanupError{Err: context.Canceled},
		failure.Wrap("permission", failure.ServerDenied, context.Canceled),
		failure.Wrap("permission", failure.ServerDenied, os.ErrDeadlineExceeded),
		&stdioInterruptError{owner: another, stream: another.selected, cause: os.ErrDeadlineExceeded},
		&stdioInterruptError{owner: o, stream: another.selected, cause: yamux.ErrTimeout},
		(*os.PathError)(nil), &stdioCycle{}, &stdioPanicIs{}, muxsession.ErrClosed,
	} {
		if o.abortOnly(errors.Join(local, reset, independent)) {
			t.Fatal("cancellation hid an independent or unowned error", independent)
		}
	}
	if !o.abortOnly(errors.Join(local, reset, prepared, context.Canceled)) {
		t.Fatal("exact operation evidence was rejected")
	}
}

type stdioFailureControl struct {
	Control
	cleanup error
}

func (c stdioFailureControl) Close(context.Context) error { return c.cleanup }

func TestStdioCancellationPreservesIndependentFailureAndCleanup(t *testing.T) {
	for _, transport := range []string{"quic", "wss"} {
		for _, cause := range []error{context.Canceled, context.DeadlineExceeded, errors.New("caller stopped")} {
			t.Run(transport+"/"+cause.Error(), func(t *testing.T) {
				f := newConnectorFixture(t, transport)
				ctx, cancel := context.WithCancelCause(t.Context())
				defer cancel(nil)
				cleanup := errors.New("cleanup failed")
				config := f.config
				config.Control = stdioFailureControl{Control: config.Control, cleanup: cleanup}
				err := serveConnections(ctx, config, func(context.Context, func(context.Context, net.Conn) error) error {
					cancel(cause)
					return syscall.EPIPE
				})
				if !errors.Is(err, syscall.EPIPE) || !errors.Is(err, cleanup) {
					t.Fatal("cancellation hid an independent output or cleanup error", err)
				}
				if cause != context.Canceled && !errors.Is(err, cause) {
					t.Fatal("cancellation lost its deadline or custom cause", err)
				}
			})
		}
	}
}

type gatedStdioOutput struct {
	net.Conn
	entered   chan struct{}
	release   chan struct{}
	closed    chan struct{}
	err       error
	once      sync.Once
	closeOnce sync.Once
}

func (c *gatedStdioOutput) Write([]byte) (int, error) {
	c.once.Do(func() { close(c.entered) })
	<-c.release
	return 0, c.err
}

func (c *gatedStdioOutput) Close() error {
	c.closeOnce.Do(func() { close(c.closed) })
	return c.Conn.Close()
}

func TestStdioCancellationDoesNotHideIndependentOutput(t *testing.T) {
	for _, transport := range []string{"quic", "wss"} {
		for _, failure := range []error{syscall.EPIPE, io.ErrClosedPipe} {
			t.Run(transport+"/"+failure.Error(), func(t *testing.T) {
				f := newConnectorFixture(t, transport)
				local, peer := net.Pipe()
				defer peer.Close()
				output := &gatedStdioOutput{Conn: local, entered: make(chan struct{}), release: make(chan struct{}), closed: make(chan struct{}), err: failure}
				release := sync.OnceFunc(func() { close(output.release) })
				defer release()
				ctx, cancel := context.WithCancelCause(t.Context())
				defer cancel(nil)
				done := make(chan error, 1)
				go func() { done <- Stream(ctx, output, f.config) }()
				_ = peer.SetDeadline(time.Now().Add(5 * time.Second))
				if _, err := io.WriteString(peer, "echo before output fails"); err != nil {
					t.Fatal(err)
				}
				select {
				case <-output.entered:
				case <-time.After(5 * time.Second):
					t.Fatal("application output did not begin")
				}
				cancel(context.Canceled)
				select {
				case <-output.closed:
				case <-time.After(5 * time.Second):
					t.Fatal("cancellation did not close the owned local connection")
				}
				release()
				select {
				case err := <-done:
					if !errors.Is(err, failure) {
						t.Fatal("caller cancellation hid completed output failure", err)
					}
				case <-time.After(5 * time.Second):
					t.Fatal("failed output did not join")
				}
			})
		}
	}
}

type failingStdioClose struct {
	net.Conn
	err error
}

func (c *failingStdioClose) Close() error { return errors.Join(c.Conn.Close(), c.err) }

func TestStdioActiveCancellationRetainsCallerCauseAndCleanup(t *testing.T) {
	for _, transport := range []string{"quic", "wss"} {
		for _, cause := range []error{context.Canceled, context.DeadlineExceeded, errors.New("custom caller stop")} {
			t.Run(transport+"/"+cause.Error(), func(t *testing.T) {
				f := newConnectorFixture(t, transport)
				local, peer := net.Pipe()
				defer peer.Close()
				ctx, cancel := context.WithCancelCause(t.Context())
				defer cancel(nil)
				cleanup := errors.New("local cleanup failed")
				done := make(chan error, 1)
				go func() { done <- Stream(ctx, &failingStdioClose{Conn: local, err: cleanup}, f.config) }()
				_ = peer.SetDeadline(time.Now().Add(5 * time.Second))
				if _, err := io.WriteString(peer, "active connection"); err != nil {
					t.Fatal(err)
				}
				response := make([]byte, len("active connection"))
				if _, err := io.ReadFull(peer, response); err != nil || string(response) != "active connection" {
					t.Fatal("active stdio did not forward", err)
				}
				cancel(cause)
				select {
				case err := <-done:
					if !errors.Is(err, cleanup) || cause != context.Canceled && !errors.Is(err, cause) {
						t.Fatal("cancellation lost cleanup or caller cause", err)
					}
				case <-time.After(5 * time.Second):
					t.Fatal("cleanup did not join")
				}
			})
		}
	}
}

type failingStdioHalfClose struct {
	net.Conn
	err error
}

func (c *failingStdioHalfClose) CloseWrite() error { return c.err }

func TestStdioAbortDoesNotHideIndependentHalfClose(t *testing.T) {
	local, peer := net.Pipe()
	defer local.Close()
	defer peer.Close()
	o := &stdioOperation{expected: true, localClosing: true}
	localConn := &stdioLocalConn{Conn: &failingStdioHalfClose{Conn: local, err: net.ErrClosed}, owner: o}
	if err := localConn.CloseWrite(); err != net.ErrClosed || o.abortOnly(err) {
		t.Fatal("cancellation hid a completed half-close failure", err)
	}
}

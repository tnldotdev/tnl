package stream

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"syscall"
	"testing"
	"time"

	yamux "github.com/libp2p/go-yamux/v5"
	quic "github.com/quic-go/quic-go"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/transport/muxsession"
)

func TestStdioOrdinaryCancellationJoinsOneStream(t *testing.T) {
	for _, transport := range []string{"quic", "tls-tcp"} {
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
	for _, transport := range []string{"quic", "tls-tcp"} {
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
	for _, transport := range []string{"quic", "tls-tcp"} {
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
	for _, transport := range []string{"quic", "tls-tcp"} {
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
	for _, transport := range []string{"quic", "tls-tcp"} {
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

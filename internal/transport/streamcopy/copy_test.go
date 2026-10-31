package streamcopy

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"syscall"
	"testing"
	"testing/synctest"

	yamux "github.com/libp2p/go-yamux/v5"
	quic "github.com/quic-go/quic-go"
)

func TestCopyPreservesFailureCausesAndStopsIdleDirection(t *testing.T) {
	other := errors.New("other stream copy error")
	quicFailure := &quic.StreamError{ErrorCode: 1, Remote: true}
	tests := []struct {
		name string
		err  error
	}{
		{name: "closed", err: net.ErrClosed},
		{name: "unsupported read", err: errors.ErrUnsupported},
		{
			name: "connection reset",
			err: &net.OpError{Op: "read", Net: "tcp", Err: &os.SyscallError{
				Syscall: "read", Err: syscall.ECONNRESET,
			}},
		},
		{
			name: "broken pipe",
			err: &net.OpError{Op: "write", Net: "tcp", Err: &os.SyscallError{
				Syscall: "write", Err: syscall.EPIPE,
			}},
		},
		{
			name: "disconnected half-close",
			err: &net.OpError{Op: "close", Net: "tcp", Err: &os.SyscallError{
				Syscall: "shutdown", Err: syscall.ENOTCONN,
			}},
		},
		{name: "other", err: other},
		{name: "normal QUIC cancel", err: &quic.StreamError{ErrorCode: 0, Remote: true}},
		{name: "QUIC error", err: quicFailure},
		{name: "wrapped EOF", err: fmt.Errorf("read: %w", io.EOF)},
		{name: "yamux reset wrapping EOF", err: fmt.Errorf("%w: connection closed: %w", yamux.ErrStreamReset, io.EOF)},
		{name: "joined reset and EOF", err: errors.Join(syscall.ECONNRESET, io.EOF)},
		{name: "joined typed error and EOF", err: fmt.Errorf("read: %w", errors.Join(quicFailure, io.EOF))},
		{name: "joined closed and other", err: errors.Join(net.ErrClosed, other)},
		{name: "joined unsupported and other", err: errors.Join(errors.ErrUnsupported, other)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				a, b := net.Pipe()
				left, right := &failingConn{Conn: a, readErr: test.err}, &failingConn{Conn: b}
				result := startCopy(t, left, right, nil, nil)
				synctest.Wait()
				select {
				case got := <-result:
					if !errors.Is(got.err, test.err) || got.result != (Result{}) || !left.closed.Load() || !right.closed.Load() {
						t.Fatalf("copy lost failure or cleanup: %+v, %v; want %v", got.result, got.err, test.err)
					}
					var typed *quic.StreamError
					if errors.As(test.err, &typed) {
						var preserved *quic.StreamError
						if !errors.As(got.err, &preserved) || preserved != typed {
							t.Fatal("lost typed QUIC cause")
						}
					}
				default:
					t.Fatal("copy retained an idle direction after failure")
				}
			})
		})
	}
}

type cleanupFailureConn struct {
	*failingConn
	failure error
	closes  int
}

func (c *cleanupFailureConn) Close() error {
	c.closes++
	return errors.Join(c.failingConn.Close(), c.failure)
}

func TestCopyJoinsBothDirectionAndCleanupFailures(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		leftFailure, rightFailure := errors.New("left failed"), errors.New("right failed")
		leftCleanup, rightCleanup := errors.New("left cleanup"), errors.New("right cleanup")
		a, b := net.Pipe()
		left := &cleanupFailureConn{failingConn: &failingConn{Conn: a, readErr: errors.Join(leftFailure, io.EOF)}, failure: leftCleanup}
		right := &cleanupFailureConn{failingConn: &failingConn{Conn: b, readErr: errors.Join(rightFailure, net.ErrClosed)}, failure: rightCleanup}
		result := startCopy(t, left, right, nil, nil)
		synctest.Wait()
		select {
		case got := <-result:
			for _, cause := range []error{leftFailure, io.EOF, rightFailure, net.ErrClosed, leftCleanup, rightCleanup} {
				if !errors.Is(got.err, cause) {
					t.Fatalf("lost %v: %v", cause, got.err)
				}
			}
			if left.closes != 1 || right.closes != 1 {
				t.Fatal("cleanup repeated")
			}
		default:
			t.Fatal("copy workers did not join")
		}
	})
}

type halfCloseFailureConn struct {
	*failingConn
	failure error
}

func (c *halfCloseFailureConn) CloseWrite() error { return c.failure }

func TestCopyHalfCloseFailureKeepsJoinedCauses(t *testing.T) {
	for _, failure := range []error{
		fmt.Errorf("half-close: %w", syscall.ENOTCONN),
		errors.Join(errors.ErrUnsupported, errors.New("half-close failed")),
		fmt.Errorf("half-close: %w", errors.Join(yamux.ErrStreamReset, io.EOF)),
	} {
		synctest.Test(t, func(t *testing.T) {
			a, b := net.Pipe()
			left := &failingConn{Conn: a, readErr: io.EOF}
			right := &halfCloseFailureConn{failingConn: &failingConn{Conn: b}, failure: failure}
			result := startCopy(t, left, right, nil, nil)
			synctest.Wait()
			select {
			case got := <-result:
				if !errors.Is(got.err, failure) || !left.closed.Load() || !right.closed.Load() {
					t.Fatalf("lost half-close failure or cleanup: %v", got.err)
				}
			default:
				t.Fatal("half-close failure retained idle copy")
			}
		})
	}
}

type stagedFailureConn struct {
	*failingConn
	readReady <-chan struct{}
	writeDone chan struct{}
}

func (c *stagedFailureConn) Read(p []byte) (int, error) { <-c.readReady; return c.failingConn.Read(p) }
func (c *stagedFailureConn) CloseWrite() error          { close(c.writeDone); return nil }

func TestCopyFailureAfterCleanHalfCloseClosesBothConnections(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		a, b := net.Pipe()
		failure := errors.New("response failed after request ended")
		readReady, writeDone := make(chan struct{}), make(chan struct{})
		release := sync.OnceFunc(func() { close(readReady) })
		left := &failingConn{Conn: a, readErr: io.EOF}
		right := &stagedFailureConn{failingConn: &failingConn{Conn: b, readErr: failure}, readReady: readReady, writeDone: writeDone}
		result := startCopy(t, left, right, nil, nil)
		t.Cleanup(release)
		synctest.Wait()
		select {
		case <-writeDone:
		default:
			t.Fatal("clean EOF did not half-close destination")
		}
		release()
		synctest.Wait()
		select {
		case got := <-result:
			if !errors.Is(got.err, failure) || !left.closed.Load() || !right.closed.Load() {
				t.Fatalf("lost second direction failure or cleanup: %v", got.err)
			}
		default:
			t.Fatal("failed response direction did not join")
		}
	})
}

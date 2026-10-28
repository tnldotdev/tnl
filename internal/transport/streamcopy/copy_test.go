package streamcopy

import (
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
					if !errors.Is(got.err, test.err) || got.result != (Result{}) {
						t.Fatalf("copy lost its complete failure: result=%+v error=%v; want %v", got.result, got.err, test.err)
					}
					if !left.closed.Load() || !right.closed.Load() {
						t.Fatal("failure did not close both connections")
					}
					var gotQUIC *quic.StreamError
					if errors.As(test.err, &gotQUIC) {
						var preserved *quic.StreamError
						if !errors.As(got.err, &preserved) || preserved != gotQUIC {
							t.Fatal("copy replaced the typed QUIC cause")
						}
					}
				default:
					t.Fatal("copy retained an idle direction after a non-nil read failure")
				}
			})
		})
	}
}

type cleanupFailureConn struct {
	*failingConn
	failure error
	closes  atomic.Int32
}

func (c *cleanupFailureConn) Close() error {
	c.closes.Add(1)
	return errors.Join(c.failingConn.Close(), c.failure)
}

func TestCopyJoinsBothDirectionAndCleanupFailures(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		leftFailure, rightFailure := errors.New("left copy failed"), errors.New("right copy failed")
		leftCleanup, rightCleanup := errors.New("left cleanup failed"), errors.New("right cleanup failed")
		a, b := net.Pipe()
		left := &cleanupFailureConn{failingConn: &failingConn{Conn: a, readErr: errors.Join(leftFailure, io.EOF)}, failure: leftCleanup}
		right := &cleanupFailureConn{failingConn: &failingConn{Conn: b, readErr: errors.Join(rightFailure, net.ErrClosed)}, failure: rightCleanup}
		result := startCopy(t, left, right, nil, nil)
		synctest.Wait()
		select {
		case got := <-result:
			for _, cause := range []error{leftFailure, io.EOF, rightFailure, net.ErrClosed, leftCleanup, rightCleanup} {
				if !errors.Is(got.err, cause) {
					t.Fatalf("copy lost cause %v: %v", cause, got.err)
				}
			}
			if left.closes.Load() != 1 || right.closes.Load() != 1 {
				t.Fatalf("failure cleanup repeated: left=%d right=%d", left.closes.Load(), right.closes.Load())
			}
		default:
			t.Fatal("joined failures left copy workers waiting")
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
					t.Fatalf("half-close lost its failure or left the other direction open: %v", got.err)
				}
			default:
				t.Fatal("half-close failure retained an idle copy")
			}
		})
	}
}

type stagedFailureConn struct {
	*failingConn
	readReady <-chan struct{}
	writeDone chan struct{}
}

func (c *stagedFailureConn) Read(p []byte) (int, error) {
	<-c.readReady
	return c.failingConn.Read(p)
}

func (c *stagedFailureConn) CloseWrite() error { close(c.writeDone); return nil }

func TestCopyFailureAfterCleanHalfCloseStillClosesBothConnections(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		a, b := net.Pipe()
		failure := errors.New("response failed after request ended")
		readReady, writeDone := make(chan struct{}), make(chan struct{})
		releaseRead := sync.OnceFunc(func() { close(readReady) })
		left := &failingConn{Conn: a, readErr: io.EOF}
		right := &stagedFailureConn{failingConn: &failingConn{Conn: b, readErr: failure}, readReady: readReady, writeDone: writeDone}
		result := startCopy(t, left, right, nil, nil)
		t.Cleanup(releaseRead)
		synctest.Wait()
		select {
		case <-writeDone:
		default:
			t.Fatal("clean request EOF did not half-close the destination")
		}
		releaseRead()
		synctest.Wait()
		select {
		case got := <-result:
			if !errors.Is(got.err, failure) || !left.closed.Load() || !right.closed.Load() {
				t.Fatalf("second direction failure lost its cause or cleanup: %v", got.err)
			}
		default:
			t.Fatal("copy did not join the failed response direction")
		}
	})
}

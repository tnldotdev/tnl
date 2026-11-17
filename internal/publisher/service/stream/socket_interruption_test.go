package stream

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"testing/synctest"
	"time"
)

type interruptedSocketConn struct {
	net.Conn
	reading chan struct{}
	fault   error
}

func (c *interruptedSocketConn) Read(data []byte) (int, error) {
	close(c.reading)
	return c.Conn.Read(data)
}
func (c *interruptedSocketConn) Close() error { return errors.Join(c.Conn.Close(), c.fault) }

func TestStreamSocketInterruptionRetainsExactCloseOwnerAndPhysicalFailure(t *testing.T) {
	for _, fault := range []error{nil, errors.New("independent physical close failure")} {
		t.Run(map[bool]string{false: "clean close", true: "failed close"}[fault != nil], func(t *testing.T) {
			listener, err := net.Listen("tcp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			raw, err := net.Dial("tcp4", listener.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer raw.Close()
			remote, err := listener.Accept()
			if err != nil {
				t.Fatal(err)
			}
			defer remote.Close()
			cause := errors.New("this stream owner's exact stop")
			ctx, cancel := context.WithCancelCause(t.Context())
			defer cancel(nil)
			conn := &interruptedSocketConn{Conn: raw, reading: make(chan struct{}), fault: fault}
			var recorded error
			socket := &streamSocket{Conn: conn, lifetime: ctx, closed: func(err error) { recorded = err }}
			done := make(chan error, 1)
			go func() { _, err := socket.Read(make([]byte, 1)); done <- err }()
			<-conn.reading
			cancel(cause)
			closeErr := socket.Close()
			var interruption *SocketInterruption
			if err := <-done; !errors.As(err, &interruption) || !interruption.StoppedBy(cause) ||
				interruption.StoppedBy(context.Canceled) || !errors.Is(err, net.ErrClosed) {
				t.Fatal("closed I/O lost its exact socket stop provenance", err)
			}
			if fault == nil && (closeErr != nil || recorded != nil) ||
				fault != nil && (!errors.Is(closeErr, fault) || !errors.Is(recorded, fault)) {
				t.Fatal("interrupted I/O hid or invented a physical cleanup failure", closeErr, recorded)
			}
		})
	}
}

func TestStreamSocketInterruptionDoesNotClassifyUnownedOrJoinedFailures(t *testing.T) {
	ctx, cancel := context.WithCancelCause(t.Context())
	defer cancel(nil)
	cause := errors.New("owned stop")
	cancel(cause)
	socket := &streamSocket{lifetime: ctx}
	if err := socket.result(net.ErrClosed); err != net.ErrClosed {
		t.Fatal("caller cancellation alone claimed a socket close", err)
	}
	socket.stop = cause
	independent := errors.New("independent socket I/O failure")
	for _, failure := range []error{io.EOF, io.ErrClosedPipe, independent, errors.Join(net.ErrClosed, independent), (*net.OpError)(nil)} {
		if err := socket.result(failure); err != failure {
			t.Fatal("owned close replaced an independent I/O failure", failure, err)
		}
	}
}

type expiringSocketConn struct {
	net.Conn
	entered  chan struct{}
	closed   chan struct{}
	readErr  error
	closeErr error
	once     sync.Once
}

func (c *expiringSocketConn) Read([]byte) (int, error) {
	close(c.entered)
	<-c.closed
	return 0, c.readErr
}

func (c *expiringSocketConn) Close() error {
	c.once.Do(func() { close(c.closed) })
	return c.closeErr
}

func TestStreamSocketInterruptionKeepsExactExpiryAndIndependentFailures(t *testing.T) {
	independent := errors.New("independent expired socket failure")
	for _, test := range []struct {
		name        string
		readErr     error
		closeErr    error
		interrupted bool
	}{
		{"owned read", net.ErrClosed, nil, true},
		{"joined read failure", errors.Join(net.ErrClosed, independent), nil, false},
		{"independent EOF", io.EOF, nil, false},
		{"physical close failure", net.ErrClosed, independent, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				ctx, cancel := context.WithTimeout(t.Context(), time.Second)
				raw := &expiringSocketConn{entered: make(chan struct{}), closed: make(chan struct{}), readErr: test.readErr, closeErr: test.closeErr}
				var recorded, closeErr error
				socket := &streamSocket{Conn: raw, lifetime: ctx, closed: func(err error) { recorded = err }}
				callbackDone := make(chan struct{})
				stop := context.AfterFunc(ctx, func() {
					defer close(callbackDone)
					closeErr = socket.Close()
				})
				defer func() {
					cancel()
					if !stop() {
						<-callbackDone
					}
				}()
				done := make(chan error, 1)
				go func() { _, err := socket.Read(make([]byte, 1)); done <- err }()
				<-raw.entered
				synctest.Wait()
				result := <-done
				<-callbackDone
				if context.Cause(ctx) != context.DeadlineExceeded {
					t.Fatal("socket did not stop at its original expiry", context.Cause(ctx))
				}
				var interruption *SocketInterruption
				if errors.As(result, &interruption) != test.interrupted {
					t.Fatal("expiry changed independent I/O classification", result)
				}
				if test.interrupted {
					if !interruption.StoppedBy(context.DeadlineExceeded) || interruption.StoppedBy(context.Canceled) {
						t.Fatal("expiry acquired ordinary abort provenance", result)
					}
				} else if result != test.readErr {
					t.Fatal("expiry replaced an independent I/O failure", result, test.readErr)
				}
				if closeErr != test.closeErr || recorded != test.closeErr {
					t.Fatal("expiry hid or replaced the physical close result", closeErr, recorded)
				}
			})
		})
	}
}

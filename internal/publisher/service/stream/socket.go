package stream

import (
	"context"
	"errors"
	"net"
	"os"
	"sync"
)

// streamSocket joins the first physical close and records its result even if a
// completed request removes the socket before visitor cleanup. wrapping a socket
// must not remove the native protocols' half-close support.
type streamSocket struct {
	net.Conn
	once     sync.Once
	closed   func(error)
	err      error
	lifetime context.Context
	mu       sync.Mutex
	stop     error
}

func (c *streamSocket) Close() error {
	c.once.Do(func() {
		if c.lifetime != nil {
			c.mu.Lock()
			c.stop = context.Cause(c.lifetime)
			c.mu.Unlock()
		}
		c.err = c.Conn.Close()
		c.closed(c.err)
	})
	return c.err
}

// SocketInterruption identifies I/O interrupted by this socket owner's close.
// it never replaces the physical close result or unrelated I/O failures.
type SocketInterruption struct {
	err  error
	stop error
}

func (e *SocketInterruption) Error() string              { return e.err.Error() }
func (e *SocketInterruption) Unwrap() error              { return e.err }
func (e *SocketInterruption) StoppedBy(cause error) bool { return e != nil && e.stop == cause }

func (c *streamSocket) result(err error) error {
	c.mu.Lock()
	stop := c.stop
	c.mu.Unlock()
	if stop == nil {
		return err
	}
	cause := err
	for range 16 {
		switch typed := cause.(type) {
		case *net.OpError:
			if typed == nil {
				return err
			}
			cause = typed.Err
		case *os.PathError:
			if typed == nil {
				return err
			}
			cause = typed.Err
		case *os.SyscallError:
			if typed == nil {
				return err
			}
			cause = typed.Err
		default:
			if cause == net.ErrClosed || cause == os.ErrClosed {
				return &SocketInterruption{err: err, stop: stop}
			}
			return err
		}
	}
	return err
}

func (c *streamSocket) Read(data []byte) (int, error) {
	n, err := c.Conn.Read(data)
	return n, c.result(err)
}

func (c *streamSocket) Write(data []byte) (int, error) {
	n, err := c.Conn.Write(data)
	return n, c.result(err)
}

func (c *streamSocket) CloseWrite() error {
	if conn, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return conn.CloseWrite()
	}
	return errors.ErrUnsupported
}

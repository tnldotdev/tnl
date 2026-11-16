package stream

import (
	"errors"
	"net"
	"sync"
)

// streamSocket joins the first physical close and records its result even if a
// completed request removes the socket before visitor cleanup. wrapping a socket
// must not remove the native protocols' half-close support.
type streamSocket struct {
	net.Conn
	once   sync.Once
	closed func(error)
	err    error
}

func (c *streamSocket) Close() error {
	c.once.Do(func() {
		c.err = c.Conn.Close()
		c.closed(c.err)
	})
	return c.err
}

func (c *streamSocket) CloseWrite() error {
	if conn, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return conn.CloseWrite()
	}
	return errors.ErrUnsupported
}

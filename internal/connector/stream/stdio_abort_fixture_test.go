package stream

import (
	"context"
	"net"
)

// the joined fixture owns its terminal stop too. do not start a tls close-alert
// write after that stop has closed the raw send direction; an entered write's
// failure still comes from its actual socket, not this admission fence.
type fixtureVisitorTLSConn struct {
	net.Conn
	ctx        context.Context
	readResult func(context.Context, error)
}

func (c *fixtureVisitorTLSConn) Read(data []byte) (int, error) {
	n, err := c.Conn.Read(data)
	if err != nil && c.readResult != nil {
		c.readResult(c.ctx, err)
	}
	return n, err
}

func (c *fixtureVisitorTLSConn) Write(data []byte) (int, error) {
	if cause := context.Cause(c.ctx); cause != nil {
		return 0, cause
	}
	return c.Conn.Write(data)
}

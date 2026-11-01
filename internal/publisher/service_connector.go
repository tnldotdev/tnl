package publisher

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"time"
)

// connectorServiceConn exposes only the forwarding methods we gate. in particular,
// io.Copy cannot bypass them through ReaderFrom/WriterTo, Unwrap or NetConn.
// physical cleanup remains available after authority has ended.
type connectorServiceConn struct {
	conn      net.Conn
	ctx       context.Context
	admission ServiceConnectorAdmission
	closeOnce sync.Once
	closeErr  error
	afterEOF  func()
}

func connectorCheck(ctx context.Context, admission ServiceConnectorAdmission) error {
	if err := context.Cause(ctx); err != nil {
		return err
	}
	_, err := admission.CheckUse(ctx)
	return err
}

func (c *connectorServiceConn) Read(p []byte) (int, error) {
	if err := connectorCheck(c.ctx, c.admission); err != nil {
		return 0, err
	}
	n, err := c.conn.Read(p)
	if n > 0 {
		// a raw read can finish after revocation, including a TLS-buffered read.
		// consuming bytes is not permission to hand them to the next parser/write.
		if current := connectorCheck(c.ctx, c.admission); current != nil {
			return 0, current
		}
	}
	if errors.Is(err, io.EOF) && c.afterEOF != nil {
		c.afterEOF()
	}
	return n, err
}

func (c *connectorServiceConn) Write(p []byte) (int, error) {
	if err := connectorCheck(c.ctx, c.admission); err != nil {
		return 0, err
	}
	return c.conn.Write(p)
}

func (c *connectorServiceConn) CloseWrite() error {
	if err := connectorCheck(c.ctx, c.admission); err != nil {
		return err
	}
	if closer, ok := c.conn.(interface{ CloseWrite() error }); ok {
		return closer.CloseWrite()
	}
	return errors.ErrUnsupported
}

func (c *connectorServiceConn) Close() error {
	c.closeOnce.Do(func() { c.closeErr = c.conn.Close() })
	return c.closeErr
}

func (c *connectorServiceConn) LocalAddr() net.Addr                { return c.conn.LocalAddr() }
func (c *connectorServiceConn) RemoteAddr() net.Addr               { return c.conn.RemoteAddr() }
func (c *connectorServiceConn) SetDeadline(at time.Time) error     { return c.conn.SetDeadline(at) }
func (c *connectorServiceConn) SetReadDeadline(at time.Time) error { return c.conn.SetReadDeadline(at) }
func (c *connectorServiceConn) SetWriteDeadline(at time.Time) error {
	return c.conn.SetWriteDeadline(at)
}

package publisher

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"time"
)

// nativeServiceConn exposes only the forwarding methods we gate. in particular,
// io.Copy cannot bypass them through ReaderFrom/WriterTo, Unwrap or NetConn.
// physical cleanup remains available after authority has ended.
type nativeServiceConn struct {
	conn      net.Conn
	ctx       context.Context
	admission ServiceNativeAdmission
	closeOnce sync.Once
	closeErr  error
	afterEOF  func()
}

func nativeCheck(ctx context.Context, admission ServiceNativeAdmission) error {
	if err := context.Cause(ctx); err != nil {
		return err
	}
	_, err := admission.CheckUse(ctx)
	return err
}

func (c *nativeServiceConn) Read(p []byte) (int, error) {
	if err := nativeCheck(c.ctx, c.admission); err != nil {
		return 0, err
	}
	n, err := c.conn.Read(p)
	if n > 0 {
		// a raw read can finish after revocation, including a TLS-buffered read.
		// consuming bytes is not permission to hand them to the next parser/write.
		if current := nativeCheck(c.ctx, c.admission); current != nil {
			return 0, current
		}
	}
	if errors.Is(err, io.EOF) && c.afterEOF != nil {
		c.afterEOF()
	}
	return n, err
}

func (c *nativeServiceConn) Write(p []byte) (int, error) {
	if err := nativeCheck(c.ctx, c.admission); err != nil {
		return 0, err
	}
	return c.conn.Write(p)
}

func (c *nativeServiceConn) CloseWrite() error {
	if err := nativeCheck(c.ctx, c.admission); err != nil {
		return err
	}
	if closer, ok := c.conn.(interface{ CloseWrite() error }); ok {
		return closer.CloseWrite()
	}
	return errors.ErrUnsupported
}

func (c *nativeServiceConn) Close() error {
	c.closeOnce.Do(func() { c.closeErr = c.conn.Close() })
	return c.closeErr
}

func (c *nativeServiceConn) LocalAddr() net.Addr                 { return c.conn.LocalAddr() }
func (c *nativeServiceConn) RemoteAddr() net.Addr                { return c.conn.RemoteAddr() }
func (c *nativeServiceConn) SetDeadline(at time.Time) error      { return c.conn.SetDeadline(at) }
func (c *nativeServiceConn) SetReadDeadline(at time.Time) error  { return c.conn.SetReadDeadline(at) }
func (c *nativeServiceConn) SetWriteDeadline(at time.Time) error { return c.conn.SetWriteDeadline(at) }

//go:build tnl_benchtrace

package publisher

import (
	"context"
	"errors"
	"net"
	"runtime/trace"
	"time"
)

// this probe wraps only promoted application copies, outside the admission lock.
// the optional getter returns correlation metadata, never authority or a socket.
// wrappers exist before trace arming so retained sessions can be observed later.
// matched controls need this same build: recording perturbs the copy workers.
func serviceBenchTraceCopy(admission ServiceConnectorAdmission, client, target net.Conn) (net.Conn, net.Conn) {
	identity, ok := admission.(interface{ DiagnosticVisitorConnectionID() string })
	if !ok {
		return client, target
	}
	id := identity.DiagnosticVisitorConnectionID()
	if id == "" {
		return client, target
	}
	return &serviceBenchTraceConn{conn: client, id: id,
			readBegin: "publisher.visitor.read.begin", readEnd: "publisher.visitor.read.end",
			writeBegin: "publisher.visitor.write.begin", writeEnd: "publisher.visitor.write.end"},
		&serviceBenchTraceConn{conn: target, id: id,
			readBegin: "publisher.target.read.begin", readEnd: "publisher.target.read.end",
			writeBegin: "publisher.target.write.begin", writeEnd: "publisher.target.write.end"}
}

// do not embed net.Conn or expose copy fast paths or unwrapping: the existing
// TLS, observation, and capability-checking connections remain inside this one.
type serviceBenchTraceConn struct {
	conn                 net.Conn
	id                   string
	readBegin, readEnd   string
	writeBegin, writeEnd string
}

func (c *serviceBenchTraceConn) log(category string, count int, failed bool) {
	if trace.IsEnabled() {
		trace.Logf(context.Background(), category, "visitor_connection_id=%s bytes=%d error=%t", c.id, count, failed)
	}
}

// begin and end check trace arming independently. a call begun before arming may
// have only an end, and disarming may leave only a begin; either is censored, not
// evidence of its missing boundary. events describe calls, not query boundaries.
func (c *serviceBenchTraceConn) Read(p []byte) (int, error) {
	c.log(c.readBegin, 0, false)
	n, err := c.conn.Read(p)
	c.log(c.readEnd, n, err != nil)
	return n, err
}

func (c *serviceBenchTraceConn) Write(p []byte) (int, error) {
	c.log(c.writeBegin, len(p), false)
	n, err := c.conn.Write(p)
	c.log(c.writeEnd, n, err != nil)
	return n, err
}

func (c *serviceBenchTraceConn) CloseWrite() error {
	if closer, ok := c.conn.(interface{ CloseWrite() error }); ok {
		return closer.CloseWrite()
	}
	return errors.ErrUnsupported
}

func (c *serviceBenchTraceConn) Close() error                   { return c.conn.Close() }
func (c *serviceBenchTraceConn) LocalAddr() net.Addr            { return c.conn.LocalAddr() }
func (c *serviceBenchTraceConn) RemoteAddr() net.Addr           { return c.conn.RemoteAddr() }
func (c *serviceBenchTraceConn) SetDeadline(at time.Time) error { return c.conn.SetDeadline(at) }
func (c *serviceBenchTraceConn) SetReadDeadline(at time.Time) error {
	return c.conn.SetReadDeadline(at)
}
func (c *serviceBenchTraceConn) SetWriteDeadline(at time.Time) error {
	return c.conn.SetWriteDeadline(at)
}

package tnldruntime

import (
	"errors"
	"io"
	"net"
	"sync"
	"time"

	"github.com/tnldotdev/tnl/internal/proxyproto"
)

// a Fly public control listener receives PROXY v2 before TLS. decode it in the
// connection's goroutine, not in Accept, so an idle connection cannot block
// other control requests. the private control listener does not use this wrapper.
type controlProxyListener struct{ net.Listener }

func (l controlProxyListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return &controlProxyConn{Conn: conn}, nil
}

type controlProxyConn struct {
	net.Conn
	once        sync.Once
	reader      io.Reader
	source      net.Addr
	destination net.Addr
	err         error
}

func (c *controlProxyConn) decode() {
	if err := c.Conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		c.err = err
		return
	}
	header, replay, err := proxyproto.Decode(c.Conn)
	c.err = errors.Join(err, c.Conn.SetReadDeadline(time.Time{}))
	if c.err != nil {
		return
	}
	c.reader = replay
	c.source = &net.TCPAddr{IP: net.IP(header.Source.Addr().AsSlice()), Port: int(header.Source.Port())}
	c.destination = &net.TCPAddr{IP: net.IP(header.Destination.Addr().AsSlice()), Port: int(header.Destination.Port())}
}

func (c *controlProxyConn) Read(buffer []byte) (int, error) {
	c.once.Do(c.decode)
	if c.err != nil {
		return 0, c.err
	}
	return c.reader.Read(buffer)
}

func (c *controlProxyConn) RemoteAddr() net.Addr {
	c.once.Do(c.decode)
	if c.source != nil {
		return c.source
	}
	return c.Conn.RemoteAddr()
}

func (c *controlProxyConn) LocalAddr() net.Addr {
	c.once.Do(c.decode)
	if c.destination != nil {
		return c.destination
	}
	return c.Conn.LocalAddr()
}

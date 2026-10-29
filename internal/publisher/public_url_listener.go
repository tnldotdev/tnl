package publisher

import (
	"io"
	"net"
	"net/netip"
	"sync"

	"github.com/tnldotdev/tnl/internal/transport/proxyproto"
)

type publicURLListener struct {
	connections chan net.Conn
	closed      chan struct{}
	mu          sync.Mutex
	isClosed    bool
	once        sync.Once
}

func newRouteListener() *publicURLListener {
	return &publicURLListener{connections: make(chan net.Conn, 64), closed: make(chan struct{})}
}

func (l *publicURLListener) Accept() (net.Conn, error) {
	select {
	case connection := <-l.connections:
		return connection, nil
	case <-l.closed:
		return nil, net.ErrClosed
	}
}

func (l *publicURLListener) Close() error {
	l.once.Do(func() {
		l.mu.Lock()
		l.isClosed = true
		close(l.closed)
		for {
			select {
			case connection := <-l.connections:
				_ = connection.Close()
			default:
				l.mu.Unlock()
				return
			}
		}
	})
	return nil
}

func (*publicURLListener) Addr() net.Addr { return publicURLAddress("tnl-route") }

func (l *publicURLListener) enqueue(connection net.Conn) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.isClosed {
		return false
	}
	select {
	case l.connections <- connection:
		return true
	default:
		return false
	}
}

type publicURLAddress string

func (publicURLAddress) Network() string  { return "tnl" }
func (a publicURLAddress) String() string { return string(a) }

type publicURLReaderConn struct {
	net.Conn
	reader io.Reader
}

func (c *publicURLReaderConn) Read(destination []byte) (int, error) {
	return c.reader.Read(destination)
}

type metadataConn struct {
	net.Conn
	header  proxyproto.Header
	denied  bool
	session *visitorSession
}

func (c *metadataConn) Close() error {
	if c.session != nil && c.session.cancel != nil {
		c.session.cancel()
	}
	return c.Conn.Close()
}

func (c *publicURLReaderConn) CloseWrite() error { return closeWrite(c.Conn) }
func (c *metadataConn) CloseWrite() error        { return closeWrite(c.Conn) }
func (c *doneConn) CloseWrite() error            { return closeWrite(c.Conn) }

func closeWrite(conn net.Conn) error {
	if half, ok := conn.(interface{ CloseWrite() error }); ok {
		return half.CloseWrite()
	}
	return nil
}

func (c *metadataConn) RemoteAddr() net.Addr { return tcpAddress(c.header.Source) }
func (c *metadataConn) LocalAddr() net.Addr  { return tcpAddress(c.header.Destination) }

func tcpAddress(endpoint netip.AddrPort) net.Addr {
	return &net.TCPAddr{IP: net.IP(endpoint.Addr().AsSlice()), Port: int(endpoint.Port())}
}

type doneConn struct {
	net.Conn
	done     chan struct{}
	once     sync.Once
	closeErr error
}

func newDoneConn(connection net.Conn) *doneConn {
	return &doneConn{Conn: connection, done: make(chan struct{})}
}

func (c *doneConn) Close() error {
	// TLS handshake cancellation and net/http may close concurrently. neither
	// may signal completion before the first close finishes retiring the stream.
	c.once.Do(func() {
		c.closeErr = c.Conn.Close()
		close(c.done)
	})
	return c.closeErr
}

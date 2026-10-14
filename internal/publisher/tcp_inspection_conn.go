package publisher

import (
	"errors"
	"net"
)

// tcpInspector observes one authenticated TCP connection in both directions.
// observers capture bounded metadata and never change the bytes being copied.
type tcpInspector interface {
	clientBytes([]byte)
	serverBytes([]byte)
	stop()
}

type tcpInspectionConn struct {
	net.Conn
	observer tcpInspector
}

func (c *tcpInspectionConn) Write(data []byte) (int, error) {
	c.observer.clientBytes(data)
	n, err := c.Conn.Write(data)
	if err != nil || n != len(data) {
		c.observer.stop()
	}
	return n, err
}

func (c *tcpInspectionConn) Read(data []byte) (int, error) {
	n, err := c.Conn.Read(data)
	if n > 0 {
		c.observer.serverBytes(data[:n])
	}
	if err != nil {
		c.observer.stop()
	}
	return n, err
}

func (c *tcpInspectionConn) CloseWrite() error {
	if halfClose, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return halfClose.CloseWrite()
	}
	return errors.ErrUnsupported
}

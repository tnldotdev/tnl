package publisher

import (
	"errors"
	"net"
)

// databaseInspector observes one authenticated TCP connection in both directions.
// observers capture bounded metadata and never change the bytes being copied.
type databaseInspector interface {
	clientBytes([]byte)
	serverBytes([]byte)
	stop()
}

type databaseInspectionConn struct {
	net.Conn
	observer databaseInspector
}

func (c *databaseInspectionConn) Write(data []byte) (int, error) {
	c.observer.clientBytes(data)
	n, err := c.Conn.Write(data)
	if err != nil || n != len(data) {
		c.observer.stop()
	}
	return n, err
}

func (c *databaseInspectionConn) Read(data []byte) (int, error) {
	n, err := c.Conn.Read(data)
	if n > 0 {
		c.observer.serverBytes(data[:n])
	}
	if err != nil {
		c.observer.stop()
	}
	return n, err
}

func (c *databaseInspectionConn) CloseWrite() error {
	if halfClose, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return halfClose.CloseWrite()
	}
	return errors.ErrUnsupported
}

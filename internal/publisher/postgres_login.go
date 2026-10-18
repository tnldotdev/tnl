package publisher

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
)

func closeWrite(connection net.Conn) error {
	if closer, ok := connection.(interface{ CloseWrite() error }); ok {
		return closer.CloseWrite()
	}
	return errors.ErrUnsupported
}

// postgresLoginConn holds the first authentication choice until it can exclude
// SCRAM-PLUS. neither its header nor proof reaches the private target on refusal.
// cancellation within visitor TLS is an ordinary startup packet and half-close.
type postgresLoginConn struct {
	net.Conn
	startup   bool
	done      bool
	allowPlus bool
	pending   []byte
	remaining int
}

func (c *postgresLoginConn) CloseWrite() error { return closeWrite(c.Conn) }

func (c *postgresLoginConn) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if len(c.pending) > 0 {
		n := copy(p, c.pending)
		clear(c.pending[:n])
		c.pending = c.pending[n:]
		return n, nil
	}
	if c.remaining > 0 {
		n, err := c.Conn.Read(p[:min(len(p), c.remaining)])
		c.remaining -= n
		return n, err
	}
	if c.done {
		return c.Conn.Read(p)
	}
	if !c.startup {
		var header [4]byte
		if _, err := io.ReadFull(c.Conn, header[:]); err != nil {
			return 0, err
		}
		length := binary.BigEndian.Uint32(header[:])
		if length < 8 || length > 64<<10 {
			return 0, errors.New("publisher: invalid PostgreSQL startup length")
		}
		c.startup = true
		c.remaining = int(length) - 4
		c.pending = header[:]
		return c.Read(p)
	}
	var header [5]byte
	if _, err := io.ReadFull(c.Conn, header[:]); err != nil {
		return 0, err
	}
	length := binary.BigEndian.Uint32(header[1:])
	if length < 4 || length > 64<<10 {
		// startup has ended; this guard is not an application protocol parser.
		c.done = true
		c.pending = header[:]
		return c.Read(p)
	}
	c.remaining = int(length) - 4
	if header[0] != 'p' {
		c.pending = header[:]
		return c.Read(p)
	}
	choice := make([]byte, min(c.remaining, len("SCRAM-SHA-256-PLUS\x00")))
	if _, err := io.ReadFull(c.Conn, choice); err != nil {
		return 0, err
	}
	if !c.allowPlus && bytes.Equal(choice, []byte("SCRAM-SHA-256-PLUS\x00")) {
		body := []byte("SFATAL\x00C28000\x00MPostgreSQL channel binding cannot cross publisher TLS termination; use channel_binding=disable\x00\x00")
		message := make([]byte, 5+len(body))
		message[0] = 'E'
		binary.BigEndian.PutUint32(message[1:], uint32(4+len(body)))
		copy(message[5:], body)
		_, _ = c.Conn.Write(message)
		clear(choice)
		return 0, errors.New("publisher: PostgreSQL SCRAM-PLUS is incompatible with publisher TLS termination")
	}
	c.remaining -= len(choice)
	c.pending = append(header[:], choice...)
	clear(choice)
	c.done = true
	return c.Read(p)
}

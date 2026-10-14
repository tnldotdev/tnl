package publisher

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"

	"github.com/jackc/pgx/v5/pgproto3"
)

const maxPostgresLoginMessage = 64 << 10

var errPostgresChannelBinding = errors.New("PostgreSQL channel binding cannot cross different TLS certificates")
var postgresPlusMethod = []byte("SCRAM-SHA-256-PLUS\x00")

// postgresAuthChoiceConn passes startup and ordinary traffic unchanged. when
// certificates differ, it rejects a PLUS choice before forwarding the proof.
type postgresAuthChoiceConn struct {
	net.Conn
	pending   []byte
	remaining int
	phase     uint8
}

func (c *postgresAuthChoiceConn) CloseWrite() error {
	return closeWrite(c.Conn)
}

func (c *postgresAuthChoiceConn) Read(data []byte) (int, error) {
	if len(data) == 0 {
		return 0, nil
	}
	if len(c.pending) != 0 {
		n := copy(data, c.pending)
		c.pending = c.pending[n:]
		return n, nil
	}
	if c.remaining > 0 {
		n, err := c.Conn.Read(data[:min(len(data), c.remaining)])
		c.remaining -= n
		return n, err
	}
	switch c.phase {
	case 0:
		var header [4]byte
		if _, err := io.ReadFull(c.Conn, header[:]); err != nil {
			return 0, err
		}
		length := binary.BigEndian.Uint32(header[:])
		if length >= 8 && length <= maxPostgresLoginMessage {
			c.phase = 1
			c.remaining = int(length) - len(header)
		} else {
			c.phase = 2
		}
		c.pending = header[:]
		return c.Read(data)
	case 1:
		var header [5]byte
		if _, err := io.ReadFull(c.Conn, header[:]); err != nil {
			return 0, err
		}
		length := binary.BigEndian.Uint32(header[1:])
		if header[0] != 'p' || length < 4 || length > maxPostgresLoginMessage {
			c.phase = 2
			if length >= 4 && length <= maxPostgresLoginMessage {
				c.remaining = int(length) - 4
			}
			c.pending = header[:]
			return c.Read(data)
		}
		bodyLength := int(length) - 4
		prefix := make([]byte, min(bodyLength, len(postgresPlusMethod)))
		if _, err := io.ReadFull(c.Conn, prefix); err != nil {
			return 0, err
		}
		if bytes.Equal(prefix, postgresPlusMethod) {
			message, err := (&pgproto3.ErrorResponse{
				Severity: "FATAL", Code: "28000",
				Message: "PostgreSQL channel binding cannot cross different TLS certificates; use channel_binding=disable or --visitor-tls-passthrough with a certificate the client can verify",
			}).Encode(nil)
			if err != nil {
				return 0, err
			}
			if _, err := c.Conn.Write(message); err != nil {
				return 0, err
			}
			return 0, errPostgresChannelBinding
		}
		c.phase = 2
		c.remaining = bodyLength - len(prefix)
		c.pending = append(header[:], prefix...)
		return c.Read(data)
	default:
		return c.Conn.Read(data)
	}
}

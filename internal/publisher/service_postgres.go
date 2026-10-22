package publisher

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
)

// frontend and target TLS have different channel bindings. native client
// settings explicitly disable channel binding while keeping verified TLS.
// SCRAM-PLUS is refused before a proof reaches the target; hiding the backend's
// PLUS offer would trigger SCRAM downgrade detection instead of fixing it.
func forwardPostgresAuthentication(client, backend net.Conn) error {
	var size [4]byte
	if _, err := io.ReadFull(client, size[:]); err != nil {
		return err
	}
	length := binary.BigEndian.Uint32(size[:])
	if length < 8 || length > 64<<10 {
		return ErrEndpoint
	}
	startup := make([]byte, int(length))
	copy(startup, size[:])
	defer clear(startup)
	if _, err := io.ReadFull(client, startup[4:]); err != nil {
		return err
	}
	if binary.BigEndian.Uint32(startup[4:8]) == 80877102 {
		// admission on this socket does not bind a backend PID/key to the
		// original principal or service. refuse even TLS-wrapped cancellation
		// until that ownership is established; never forward an unbound key.
		return ErrEndpoint
	}
	if _, err := backend.Write(startup); err != nil {
		return err
	}
	for range 64 {
		var header [5]byte
		if _, err := io.ReadFull(backend, header[:]); err != nil {
			return err
		}
		size := binary.BigEndian.Uint32(header[1:])
		if size < 4 || size > 1<<20 {
			return ErrEndpoint
		}
		body := make([]byte, int(size)-4)
		if _, err := io.ReadFull(backend, body); err != nil {
			clear(body)
			return err
		}
		code := uint32(0)
		if header[0] == 'R' {
			if len(body) < 4 {
				clear(body)
				return ErrEndpoint
			}
			code = binary.BigEndian.Uint32(body[:4])
		}
		_, err := client.Write(append(header[:], body...))
		clear(body)
		if err != nil {
			return err
		}
		if header[0] == 'E' {
			return ErrEndpoint
		}
		if header[0] != 'R' || code == 12 {
			continue
		}
		if code == 0 {
			return nil
		}
		var responseHeader [5]byte
		if _, err := io.ReadFull(client, responseHeader[:]); err != nil {
			return err
		}
		responseLength := binary.BigEndian.Uint32(responseHeader[1:])
		if responseHeader[0] != 'p' || responseLength < 4 || responseLength > 64<<10 {
			return ErrEndpoint
		}
		response := make([]byte, int(responseLength)+1)
		copy(response, responseHeader[:])
		if _, err := io.ReadFull(client, response[5:]); err != nil {
			clear(response)
			return err
		}
		if bytes.HasPrefix(response[5:], []byte("SCRAM-SHA-256-PLUS\x00")) {
			clear(response)
			body := []byte("SFATAL\x00C0A000\x00Mchannel binding cannot cross publisher TLS termination; use channel_binding=disable with verified TLS\x00\x00")
			packet := make([]byte, 5+len(body))
			packet[0] = 'E'
			binary.BigEndian.PutUint32(packet[1:], uint32(4+len(body)))
			copy(packet[5:], body)
			_, _ = client.Write(packet)
			return ErrEndpoint
		}
		_, err = backend.Write(response)
		clear(response)
		if err != nil {
			return err
		}
	}
	return ErrEndpoint
}

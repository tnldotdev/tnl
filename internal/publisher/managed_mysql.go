package publisher

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"io"
	"net"

	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/observability"
	"github.com/tnldotdev/tnl/internal/targettransport"
)

const managedMySQLSSL uint32 = 1 << 11
const managedMySQLProtocol41 uint32 = 1 << 9

type managedMySQLHandshake struct {
	request  []byte
	scramble []byte
	plugin   string
}

func managedMySQLPacket(reader io.Reader) ([]byte, error) {
	return targettransport.ReadMySQLPacket(reader, targettransport.MySQLMaxPacket)
}

func managedMySQLWrite(writer io.Writer, packet []byte, sequence byte) error {
	packet[3] = sequence
	_, err := io.Copy(writer, bytes.NewReader(packet))
	return err
}

func acceptMySQLTLS(client, backend net.Conn, targetTLS bool) (*managedMySQLHandshake, error) {
	packet, err := managedMySQLPacket(backend)
	if err != nil {
		return nil, err
	}
	defer clear(packet)
	if len(packet) > 64<<10 || packet[3] != 0 || len(packet) < 5 || packet[4] != 10 {
		return nil, ErrManagedTLS
	}
	end := bytes.IndexByte(packet[5:], 0)
	if end < 0 {
		return nil, ErrManagedTLS
	}
	start := 5 + end + 1
	capabilities := start + 4 + 8 + 1
	if len(packet) < capabilities+2+1+2+2+1+10+13 {
		return nil, ErrManagedTLS
	}
	flags := uint32(binary.LittleEndian.Uint16(packet[capabilities:])) | uint32(binary.LittleEndian.Uint16(packet[capabilities+5:]))<<16
	if flags&managedMySQLProtocol41 == 0 || targetTLS && flags&managedMySQLSSL == 0 {
		return nil, ErrManagedTLS
	}
	scramble := append([]byte{}, packet[start+4:start+12]...)
	scramble = append(scramble, packet[capabilities+18:capabilities+30]...)
	pluginStart := capabilities + 31
	plugin := ""
	if pluginStart < len(packet) {
		plugin = string(bytes.TrimRight(packet[pluginStart:], "\x00"))
	}
	// only the publisher's native TLS capability is advertised to the client.
	// target TLS is independently required and verified when configured.
	binary.LittleEndian.PutUint16(packet[capabilities:], uint16(flags|managedMySQLSSL))
	if err = managedMySQLWrite(client, packet, 0); err != nil {
		return nil, err
	}
	request, err := managedMySQLPacket(client)
	if err != nil {
		return nil, err
	}
	if len(request) != 36 || request[3] != 1 || binary.LittleEndian.Uint32(request[4:])&(managedMySQLSSL|managedMySQLProtocol41) != managedMySQLSSL|managedMySQLProtocol41 {
		clear(request)
		return nil, ErrManagedTLS
	}
	return &managedMySQLHandshake{request: request, scramble: scramble, plugin: plugin}, nil
}

func connectMySQLTarget(ctx context.Context, client net.Conn, backend net.Conn, handshake *managedMySQLHandshake, verification *tls.Config) (net.Conn, error) {
	if handshake == nil {
		return backend, ErrManagedTLS
	}
	defer clear(handshake.request)
	defer func() { clear(handshake.scramble) }()
	if verification != nil {
		_, negotiationDone := observability.PublisherOperation(ctx, "target_negotiation")
		err := managedMySQLWrite(backend, handshake.request, 1)
		negotiationDone(err)
		if err != nil {
			return backend, err
		}
		secured, err := (targettransport.Transport{Protocol: config.ProtocolMySQL, TLS: verification}).Handshake(ctx, backend)
		if err != nil {
			return backend, err
		}
		backend = secured
	}
	login, err := managedMySQLPacket(client)
	if err != nil {
		return backend, err
	}
	defer clear(login)
	if len(login) < 36 || login[3] != 2 || binary.LittleEndian.Uint32(login[4:]) != binary.LittleEndian.Uint32(handshake.request[4:]) {
		return backend, ErrManagedTLS
	}
	backSequence := byte(2)
	if verification == nil {
		if handshake.plugin == "sha256_password" {
			// this plugin sends the TLS client's clear password in its first
			// login; it cannot be sent to an unverified plaintext target.
			return backend, ErrManagedTLS
		}
		binary.LittleEndian.PutUint32(login[4:], binary.LittleEndian.Uint32(login[4:])&^managedMySQLSSL)
		backSequence = 1
	}
	if err := managedMySQLWrite(backend, login, backSequence); err != nil {
		return backend, err
	}
	backSequence++
	frontSequence := byte(3)
	for range 64 {
		packet, err := managedMySQLPacket(backend)
		if err != nil {
			return backend, err
		}
		if packet[3] != backSequence {
			clear(packet)
			return backend, ErrManagedTLS
		}
		backSequence++
		kind := packet[4]
		if kind == 0xfe {
			end := bytes.IndexByte(packet[5:], 0)
			if end < 0 {
				clear(packet)
				return backend, ErrManagedTLS
			}
			handshake.plugin = string(packet[5 : 5+end])
			if verification == nil && handshake.plugin == "sha256_password" {
				clear(packet)
				return backend, ErrManagedTLS
			}
			clear(handshake.scramble)
			handshake.scramble = bytes.TrimRight(bytes.Clone(packet[6+end:]), "\x00")
		}
		full := kind == 0x01 && len(packet) == 6 && packet[5] == 0x04
		fast := kind == 0x01 && len(packet) == 6 && packet[5] == 0x03
		if err = managedMySQLWrite(client, packet, frontSequence); err != nil {
			clear(packet)
			return backend, err
		}
		clear(packet)
		frontSequence++
		if kind == 0x00 {
			return backend, nil
		}
		if kind == 0xff {
			return backend, ErrManagedTLS
		}
		if fast {
			continue
		}
		response, err := managedMySQLPacket(client)
		if err != nil {
			return backend, err
		}
		if response[3] != frontSequence {
			clear(response)
			return backend, ErrManagedTLS
		}
		frontSequence++
		if full && verification == nil && handshake.plugin == "caching_sha2_password" {
			password := bytes.Clone(response[4:])
			clear(response)
			if len(password) < 1 || len(password) > 4096 || password[len(password)-1] != 0 || len(handshake.scramble) < 20 {
				clear(password)
				return backend, ErrManagedTLS
			}
			if err = managedMySQLWrite(backend, []byte{1, 0, 0, 0, 0x02}, backSequence); err != nil {
				clear(password)
				return backend, err
			}
			backSequence++
			keyPacket, err := managedMySQLPacket(backend)
			if err != nil {
				clear(password)
				return backend, err
			}
			if keyPacket[3] != backSequence || keyPacket[4] != 0x01 {
				clear(password)
				clear(keyPacket)
				return backend, ErrManagedTLS
			}
			backSequence++
			block, rest := pem.Decode(keyPacket[5:])
			if block == nil || len(bytes.TrimSpace(rest)) != 0 {
				clear(password)
				clear(keyPacket)
				return backend, ErrManagedTLS
			}
			parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
			clear(keyPacket)
			public, ok := parsed.(*rsa.PublicKey)
			if err != nil || !ok || public.N.BitLen() < 2048 || public.N.BitLen() > 4096 || public.E != 65537 {
				clear(password)
				return backend, ErrManagedTLS
			}
			for index := range password {
				password[index] ^= handshake.scramble[index%20]
			}
			encrypted, err := rsa.EncryptOAEP(sha1.New(), rand.Reader, public, password, nil)
			clear(password)
			if err != nil {
				return backend, err
			}
			response = append([]byte{byte(len(encrypted)), byte(len(encrypted) >> 8), byte(len(encrypted) >> 16), 0}, encrypted...)
		}
		err = managedMySQLWrite(backend, response, backSequence)
		clear(response)
		if err != nil {
			return backend, err
		}
		backSequence++
	}
	return backend, ErrManagedTLS
}

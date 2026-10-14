package clientruntime

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"
)

var postgresSSLRequest = [8]byte{0, 0, 0, 8, 4, 210, 22, 47}

// ProbeTCP checks the public visitor path without sending credentials or
// application commands. its result is transport readiness, not login or query
// success. ssh uses its host key rather than a public URL certificate.
func ProbeTCP(ctx context.Context, publicAddress, protocol string, roots *x509.CertPool) error {
	host, port, err := net.SplitHostPort(publicAddress)
	if err != nil || host == "" || port == "" {
		return errors.New("public TCP address is missing a hostname and port")
	}
	portNumber, err := strconv.Atoi(port)
	if err != nil || portNumber < 1 || portNumber > 65535 {
		return errors.New("public TCP address has an invalid port")
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	connection, err := (&net.Dialer{}).DialContext(ctx, "tcp", publicAddress)
	if err != nil {
		return fmt.Errorf("connect to public TCP address: %w", err)
	}
	defer connection.Close()
	if err := connection.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return err
	}
	stop := context.AfterFunc(ctx, func() { _ = connection.Close() })
	defer stop()
	verifyTLS := func() error {
		secured := tls.Client(connection, &tls.Config{MinVersion: tls.VersionTLS12, ServerName: host, RootCAs: roots})
		return secured.HandshakeContext(ctx)
	}
	switch protocol {
	case "postgres":
		if _, err := connection.Write(postgresSSLRequest[:]); err != nil {
			return err
		}
		var response [1]byte
		if _, err := io.ReadFull(connection, response[:]); err != nil {
			return err
		}
		if response[0] != 'S' {
			return errors.New("public PostgreSQL endpoint did not accept TLS negotiation")
		}
		return verifyTLS()
	case "mysql":
		var header [4]byte
		if _, err := io.ReadFull(connection, header[:]); err != nil {
			return err
		}
		length := int(header[0]) | int(header[1])<<8 | int(header[2])<<16
		if length < 2 || length > 64<<10 || header[3] != 0 {
			return errors.New("public MySQL endpoint sent an invalid greeting")
		}
		greeting := make([]byte, length)
		if _, err := io.ReadFull(connection, greeting); err != nil {
			return err
		}
		if greeting[0] != 10 {
			return errors.New("public MySQL endpoint sent an invalid protocol version")
		}
		// mysql starts in plaintext; its SSLRequest switches this same visitor
		// connection to TLS before any login bytes are sent.
		versionEnd := bytes.IndexByte(greeting[1:], 0)
		if versionEnd < 0 {
			return errors.New("public MySQL endpoint sent an invalid greeting")
		}
		capabilities := 1 + versionEnd + 1 + 4 + 8 + 1
		if len(greeting) < capabilities+2 || binary.LittleEndian.Uint16(greeting[capabilities:capabilities+2])&(1<<11) == 0 {
			return errors.New("public MySQL endpoint did not offer visitor TLS")
		}
		request := make([]byte, 36)
		request[0], request[3] = 32, 1
		binary.LittleEndian.PutUint32(request[4:8], 1<<11)
		if _, err := connection.Write(request); err != nil {
			return err
		}
		return verifyTLS()
	case "redis":
		return verifyTLS()
	case "ssh":
		reader := bufio.NewReader(io.LimitReader(connection, 4<<10))
		for range 5 {
			line, err := reader.ReadBytes('\n')
			if err != nil {
				return err
			}
			if bytes.HasPrefix(line, []byte("SSH-2.0-")) && len(line) <= 255 && strings.HasSuffix(string(line), "\r\n") {
				return nil
			}
		}
		return errors.New("public SSH endpoint did not send a protocol banner")
	default:
		return errors.New("public TCP readiness does not support this protocol")
	}
}

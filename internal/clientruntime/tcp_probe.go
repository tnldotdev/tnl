package clientruntime

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strings"
	"time"
)

// TCPProbeOptions is shared by local owner and remote CLI checks. Address is the
// public hostname:port, never the private target. TLS uses WebPKI by default;
// callers may supply visitor certificates for protected database services.
type TCPProbeOptions struct {
	Address   string
	Protocol  string
	TLSConfig *tls.Config
}

func ProbeTCP(ctx context.Context, service Service, options TCPProbeOptions) Observation {
	result := Observation{Target: service.Target, RegistrationID: service.RegistrationID, PublishRunNumber: service.PublishRunNumber, CheckedAt: time.Now().UTC(), Readiness: service.Readiness}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if options.Address == "" {
		options.Address = service.PublicURL
	}
	if options.Protocol == "" {
		options.Protocol = service.ServiceProtocol
	}
	if err := CheckPublicTCP(ctx, options); err != nil {
		result.Reason = "runtime.probe_failed"
	} else {
		result.Ready = true
	}
	return result
}

func CheckPublicTCP(ctx context.Context, options TCPProbeOptions) error {
	host, _, err := net.SplitHostPort(options.Address)
	if err != nil {
		return err
	}
	connection, err := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "tcp", options.Address)
	if err != nil {
		return err
	}
	defer connection.Close()
	deadline := time.Now().Add(5 * time.Second)
	if end, ok := ctx.Deadline(); ok && end.Before(deadline) {
		deadline = end
	}
	_ = connection.SetDeadline(deadline)
	stop := context.AfterFunc(ctx, func() { _ = connection.Close() })
	defer stop()
	if options.Protocol == "ssh" {
		return checkSSHBanner(connection)
	}
	config := &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12}
	if options.TLSConfig != nil {
		config = options.TLSConfig.Clone()
		if config.ServerName == "" {
			config.ServerName = host
		}
	}
	if config.InsecureSkipVerify {
		return errors.New("public readiness requires verified TLS")
	}
	// postgres and mysql negotiate visitor TLS using their native prefaces.
	switch options.Protocol {
	case "postgres":
		if _, err := connection.Write([]byte{0, 0, 0, 8, 4, 210, 22, 47}); err != nil {
			return err
		}
		var reply [1]byte
		if _, err := io.ReadFull(connection, reply[:]); err != nil {
			return err
		}
		if reply[0] != 'S' {
			return errors.New("postgres visitor TLS rejected")
		}
	case "mysql":
		greeting, err := mysqlPacket(connection)
		if err != nil || len(greeting) < 1 || greeting[0] != 10 {
			return errors.New("mysql greeting rejected")
		}
		// CLIENT_PROTOCOL_41 | CLIENT_SSL | CLIENT_SECURE_CONNECTION.
		packet := make([]byte, 36)
		packet[0], packet[3] = 32, 1
		binary.LittleEndian.PutUint32(packet[4:8], 0x00008a00)
		binary.LittleEndian.PutUint32(packet[8:12], 1<<20)
		packet[12] = 45
		if _, err := connection.Write(packet); err != nil {
			return err
		}
	case "redis":
	default:
		return errors.New("unsupported readiness protocol")
	}
	secure := tls.Client(connection, config)
	if err := secure.HandshakeContext(ctx); err != nil {
		return err
	}
	switch options.Protocol {
	case "postgres", "mysql":
		// a verified public protocol TLS handshake is the non-credentialed
		// readiness boundary; no database login or SQL is sent.
		return nil
	case "redis":
		if _, err := secure.Write([]byte("*1\r\n$4\r\nPING\r\n")); err != nil {
			return err
		}
		line, err := bufio.NewReader(io.LimitReader(secure, 1024)).ReadString('\n')
		if err != nil {
			return err
		}
		if line == "+PONG\r\n" || strings.HasPrefix(line, "-NOAUTH ") {
			return nil
		}
		return errors.New("redis readiness rejected")
	}
	return errors.New("public readiness rejected")
}

func checkSSHBanner(connection io.Reader) error {
	reader := bufio.NewReader(io.LimitReader(connection, 4096))
	for range 8 {
		line, err := reader.ReadString('\n')
		if err != nil {
			return err
		}
		if strings.HasPrefix(line, "SSH-2.0-") && len(line) <= 255 && strings.HasSuffix(line, "\r\n") {
			return nil
		}
	}
	return errors.New("SSH banner rejected")
}

func mysqlPacket(reader io.Reader) ([]byte, error) {
	var header [4]byte
	if _, err := io.ReadFull(reader, header[:]); err != nil {
		return nil, err
	}
	size := int(header[0]) | int(header[1])<<8 | int(header[2])<<16
	if size < 1 || size > 4096 || header[3] != 0 {
		return nil, errors.New("mysql greeting exceeds bounds")
	}
	body := make([]byte, size)
	_, err := io.ReadFull(reader, body)
	return body, err
}

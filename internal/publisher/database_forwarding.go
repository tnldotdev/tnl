package publisher

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strconv"
	"time"

	"github.com/tnldotdev/tnl/internal/diagnostic"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/router"
	"github.com/tnldotdev/tnl/internal/streamcopy"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

var postgresSSLRequest = [8]byte{0, 0, 0, 8, 4, 210, 22, 47}
var postgresGSSRequest = [8]byte{0, 0, 0, 8, 4, 210, 22, 48}

const mysqlClientSSL = 1 << 11

type databaseForwarding struct {
	protocol        controlv1.PublicURLServiceProtocol
	admission       *applicationAdmission
	publicPort      uint16
	target          string
	backendTLS      *tls.Config
	passthrough     bool
	onTargetFailure func()
}

func newDatabaseForwarding(config PublicURLServerConfig) (*databaseForwarding, error) {
	if config.ServiceProtocol == "" || config.ServiceProtocol == controlv1.Http {
		if config.PublicPort != 0 || config.TargetTLSName != "" || config.DatabaseTLSPassthrough {
			return nil, errors.New("publisher: HTTP public URL cannot configure database forwarding")
		}
		return nil, nil
	}
	if config.ServiceProtocol != controlv1.Postgres && config.ServiceProtocol != controlv1.Mysql ||
		config.PublicPort < 1024 || config.Handler != nil || len(config.Mounts) != 0 || config.ShareAccess != nil ||
		config.BrowserAccess != nil || config.Feedback != nil {
		return nil, errors.New("publisher: database forwarding configuration is invalid")
	}
	if config.DatabaseTLSPassthrough && (config.TargetTLSName != "" || config.TargetOptions.RootCAs != nil) {
		return nil, errors.New("publisher: passthrough target certificate is verified by the database client")
	}
	host, port, err := net.SplitHostPort(config.Target)
	if err != nil || host == "" {
		return nil, diagnostic.Wrap(diagnostic.TargetInvalid, errors.New("database target must be a host and port"))
	}
	value, err := strconv.Atoi(port)
	if err != nil || value < 1 || value > 65535 {
		return nil, diagnostic.Wrap(diagnostic.TargetInvalid, errors.New("database target port is invalid"))
	}
	tlsName := config.TargetTLSName
	if tlsName == "" {
		tlsName = host
	}
	return &databaseForwarding{
		protocol: config.ServiceProtocol, publicPort: config.PublicPort, target: config.Target,
		backendTLS: &tls.Config{MinVersion: tls.VersionTLS12, ServerName: tlsName,
			RootCAs: config.TargetOptions.RootCAs}, passthrough: config.DatabaseTLSPassthrough,
		onTargetFailure: config.OnTargetFailure,
	}, nil
}

func (d *databaseForwarding) forward(visitor net.Conn, publicTLS *tls.Config, hostname string) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	backend, err := (&net.Dialer{}).DialContext(ctx, "tcp", d.target)
	if err != nil {
		if d.onTargetFailure != nil {
			d.onTargetFailure()
		}
		return
	}
	defer backend.Close()
	_ = backend.SetDeadline(time.Now().Add(10 * time.Second))
	visitorTLS := publicTLS.Clone()
	visitorTLS.NextProtos = nil
	switch d.protocol {
	case controlv1.Postgres:
		_ = d.postgres(visitor, backend, visitorTLS, hostname)
	case controlv1.Mysql:
		_ = d.mysql(visitor, backend, visitorTLS, hostname)
	}
}

func (d *databaseForwarding) postgres(visitor, backend net.Conn, publicTLS *tls.Config, hostname string) error {
	var startup [8]byte
	if _, err := io.ReadFull(visitor, startup[:]); err != nil {
		return err
	}
	if startup == postgresGSSRequest {
		if _, err := visitor.Write([]byte{'N'}); err != nil {
			return err
		}
		if _, err := io.ReadFull(visitor, startup[:]); err != nil {
			return err
		}
	}
	if startup != postgresSSLRequest {
		return errors.New("publisher: PostgreSQL visitor TLS is required")
	}
	if _, err := io.Copy(backend, bytes.NewReader(postgresSSLRequest[:])); err != nil {
		d.targetFailed()
		return err
	}
	var answer [1]byte
	if _, err := io.ReadFull(backend, answer[:]); err != nil {
		d.targetFailed()
		return err
	}
	if answer[0] != 'S' {
		d.targetFailed()
		return errors.New("publisher: PostgreSQL target TLS is required")
	}
	if d.passthrough {
		if _, err := visitor.Write(answer[:]); err != nil {
			return err
		}
		return forwardDatabasePassthrough(visitor, backend, hostname, d.admission)
	}
	securedBackend := tls.Client(backend, d.backendTLS)
	if err := securedBackend.Handshake(); err != nil {
		d.targetFailed()
		return err
	}
	if _, err := visitor.Write(answer[:]); err != nil {
		return err
	}
	return forwardDatabaseTLS(visitor, securedBackend, publicTLS, d.admission)
}

func (d *databaseForwarding) mysql(visitor, backend net.Conn, publicTLS *tls.Config, hostname string) error {
	// mysql begins with a server greeting. preserve its scramble and capability
	// flags so the private target, not tnl, authenticates the visitor.
	greeting, err := readMySQLPacket(backend, 64<<10)
	if err != nil {
		d.targetFailed()
		return err
	}
	if _, err := io.Copy(visitor, bytes.NewReader(greeting)); err != nil {
		return err
	}
	request, err := readMySQLPacket(visitor, 32)
	if err != nil {
		return err
	}
	if len(request) != 36 || request[3] != 1 || binary.LittleEndian.Uint32(request[4:8])&mysqlClientSSL == 0 {
		return errors.New("publisher: MySQL visitor TLS is required")
	}
	if _, err := io.Copy(backend, bytes.NewReader(request)); err != nil {
		d.targetFailed()
		return err
	}
	if d.passthrough {
		return forwardDatabasePassthrough(visitor, backend, hostname, d.admission)
	}
	securedBackend := tls.Client(backend, d.backendTLS)
	if err := securedBackend.Handshake(); err != nil {
		d.targetFailed()
		return err
	}
	return forwardDatabaseTLS(visitor, securedBackend, publicTLS, d.admission)
}

func (d *databaseForwarding) targetFailed() {
	if d.onTargetFailure != nil {
		d.onTargetFailure()
	}
}

func readMySQLPacket(connection net.Conn, limit int) ([]byte, error) {
	var header [4]byte
	if _, err := io.ReadFull(connection, header[:]); err != nil {
		return nil, err
	}
	length := int(header[0]) | int(header[1])<<8 | int(header[2])<<16
	if length == 0 || length > limit {
		return nil, errors.New("publisher: invalid MySQL handshake packet")
	}
	packet := make([]byte, 4+length)
	copy(packet, header[:])
	_, err := io.ReadFull(connection, packet[4:])
	return packet, err
}

func forwardDatabaseTLS(visitor, backend net.Conn, publicTLS *tls.Config, admission *applicationAdmission) error {
	securedVisitor := tls.Server(visitor, publicTLS)
	if err := securedVisitor.Handshake(); err != nil {
		return err
	}
	if status, _ := admission.enter(time.Now()); status != 0 {
		return errors.New("publisher: database visitor capacity is exhausted")
	}
	defer admission.leave()
	_ = visitor.SetDeadline(time.Time{})
	_ = backend.SetDeadline(time.Time{})
	_, err := streamcopy.Copy(securedVisitor, backend)
	return err
}

func forwardDatabasePassthrough(visitor, backend net.Conn, hostname string, admission *applicationAdmission) error {
	hello, err := router.InspectClientHello(visitor)
	serverName, nameErr := naming.CanonicalizeHostname(hello.ServerName)
	if err != nil || nameErr != nil || serverName != hostname || hello.ACMETLSALPN {
		return errors.New("publisher: database TLS SNI does not match public URL")
	}
	if status, _ := admission.enter(time.Now()); status != 0 {
		return errors.New("publisher: database visitor capacity is exhausted")
	}
	defer admission.leave()
	if _, err := io.Copy(backend, bytes.NewReader(hello.Prefix)); err != nil {
		return err
	}
	_ = visitor.SetDeadline(time.Time{})
	_ = backend.SetDeadline(time.Time{})
	_, err = streamcopy.Copy(&publicURLReaderConn{Conn: visitor, reader: hello.Remainder}, backend)
	return err
}

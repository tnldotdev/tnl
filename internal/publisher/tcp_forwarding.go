package publisher

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"time"

	"github.com/tnldotdev/tnl/internal/diagnostic"
	"github.com/tnldotdev/tnl/internal/streamcopy"
	"github.com/tnldotdev/tnl/internal/tcpport"
	"github.com/tnldotdev/tnl/internal/tcptarget"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

var postgresSSLRequest = [8]byte{0, 0, 0, 8, 4, 210, 22, 47}
var postgresGSSRequest = [8]byte{0, 0, 0, 8, 4, 210, 22, 48}
var postgresCancelRequest = [8]byte{0, 0, 0, 16, 4, 210, 22, 46}

const mysqlClientSSL = 1 << 11

type tcpForwarding struct {
	protocol            controlv1.PublicURLServiceProtocol
	admission           *applicationAdmission
	admit               func() error
	publicPort          uint16
	target              string
	resolveTarget       func(context.Context) (string, error)
	backendTLS          *tls.Config
	onTargetFailure     func()
	onCancelUnsupported func()
	observeDatabase     func(DatabaseObservation)
}

func newTCPForwarding(config PublicURLServerConfig) (*tcpForwarding, error) {
	if config.ServiceProtocol == "" || config.ServiceProtocol == controlv1.Http {
		if config.PublicPort != 0 || config.TargetTLSName != "" || config.TargetTLS {
			return nil, errors.New("publisher: HTTP public URL cannot configure TCP forwarding")
		}
		return nil, nil
	}
	host, err := validateTCPForwarding(config)
	if err != nil {
		return nil, err
	}
	if !tcpport.Valid(int(config.PublicPort)) {
		return nil, errors.New("publisher: TCP public port is invalid")
	}
	tlsName := config.TargetTLSName
	if tlsName == "" {
		tlsName = host
	}
	var backendTLS *tls.Config
	if config.TargetTLS {
		backendTLS = &tls.Config{MinVersion: tls.VersionTLS12, ServerName: tlsName,
			RootCAs: config.TargetOptions.RootCAs}
	}
	return &tcpForwarding{
		protocol: config.ServiceProtocol, publicPort: config.PublicPort, target: config.Target,
		resolveTarget:       config.ResolveTarget,
		admit:               config.AdmitConnection,
		backendTLS:          backendTLS,
		onTargetFailure:     config.OnTargetFailure,
		onCancelUnsupported: config.OnCancelUnsupported,
		observeDatabase:     config.ObserveDatabase,
	}, nil
}

func supportsTCPForwarding(protocol controlv1.PublicURLServiceProtocol) bool {
	return protocol == controlv1.Postgres || protocol == controlv1.Mysql || protocol == controlv1.Redis || protocol == controlv1.Ssh
}

func validateTCPForwarding(config PublicURLServerConfig) (string, error) {
	if !supportsTCPForwarding(config.ServiceProtocol) || config.Handler != nil || len(config.Mounts) != 0 || config.ShareAccess != nil ||
		config.BrowserAccess != nil || config.Feedback != nil {
		return "", errors.New("publisher: TCP forwarding configuration is invalid")
	}
	if !config.TargetTLS && (config.TargetTLSName != "" || config.TargetOptions.RootCAs != nil) {
		return "", errors.New("publisher: target TLS options require target TLS")
	}
	host, err := tcptarget.Host(config.Target)
	if err != nil {
		return "", diagnostic.Wrap(diagnostic.TargetInvalid, err)
	}
	return host, nil
}

func (d *tcpForwarding) forward(visitor net.Conn, publicTLS *tls.Config) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	target := d.target
	if d.resolveTarget != nil {
		var resolveErr error
		target, resolveErr = d.resolveTarget(ctx)
		if resolveErr != nil || target == "" {
			d.targetFailed()
			return
		}
	}
	backend, err := (&net.Dialer{}).DialContext(ctx, "tcp", target)
	if err != nil {
		d.targetFailed()
		return
	}
	defer backend.Close()
	_ = backend.SetDeadline(time.Now().Add(10 * time.Second))
	visitorTLS := publicTLS.Clone()
	visitorTLS.NextProtos = nil
	switch d.protocol {
	case controlv1.Postgres:
		_ = d.postgres(visitor, backend, visitorTLS)
	case controlv1.Mysql:
		_ = d.mysql(visitor, backend, visitorTLS)
	case controlv1.Redis:
		_ = d.redis(visitor, backend, visitorTLS)
	case controlv1.Ssh:
		_ = d.ssh(visitor, backend)
	}
}

func (d *tcpForwarding) ssh(visitor, backend net.Conn) error {
	if d.backendTLS != nil {
		secured, err := d.connectTargetTLS(backend)
		if err != nil {
			return err
		}
		backend = secured
	}
	return copyTCPConnections(visitor, visitor, backend, d.admission)
}

func (d *tcpForwarding) redis(visitor, backend net.Conn, publicTLS *tls.Config) error {
	securedVisitor := tls.Server(visitor, publicTLS)
	if err := securedVisitor.Handshake(); err != nil {
		return err
	}
	if d.backendTLS != nil {
		secured, err := d.connectTargetTLS(backend)
		if err != nil {
			return err
		}
		backend = secured
	}
	return copyTCPConnections(visitor, securedVisitor, backend, d.admission)
}

func (d *tcpForwarding) postgres(visitor, backend net.Conn, publicTLS *tls.Config) error {
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
		if startup == postgresCancelRequest {
			var proof [8]byte
			if _, err := io.ReadFull(visitor, proof[:]); err != nil {
				return err
			}
			if d.onCancelUnsupported != nil {
				d.onCancelUnsupported()
			}
			return errors.New("publisher: plaintext PostgreSQL cancellation is not supported")
		}
		return errors.New("publisher: PostgreSQL visitor TLS is required")
	}
	if d.backendTLS != nil {
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
			return errors.New("publisher: PostgreSQL target must accept verified target TLS")
		}
		secured, err := d.connectTargetTLS(backend)
		if err != nil {
			return err
		}
		backend = secured
	}
	if _, err := visitor.Write([]byte{'S'}); err != nil {
		return err
	}
	return forwardDatabaseTLS(visitor, backend, publicTLS, d.admission, d.observeDatabase)
}

func (d *tcpForwarding) mysql(visitor, backend net.Conn, publicTLS *tls.Config) error {
	// mysql begins with a server greeting. preserve its scramble and capability
	// flags so the private target, not tnl, authenticates the visitor.
	greeting, err := readMySQLPacket(backend, 64<<10)
	if err != nil {
		d.targetFailed()
		return err
	}
	var scramble []byte
	if d.backendTLS == nil {
		scramble, err = advertiseMySQLTLS(greeting)
		if err != nil {
			return err
		}
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
	if d.backendTLS != nil {
		if _, err := io.Copy(backend, bytes.NewReader(request)); err != nil {
			d.targetFailed()
			return err
		}
		backend, err = d.connectTargetTLS(backend)
		if err != nil {
			return err
		}
	}
	securedVisitor := tls.Server(visitor, publicTLS)
	if err := securedVisitor.Handshake(); err != nil {
		return err
	}
	clientFlags := binary.LittleEndian.Uint32(request[4:8])
	if d.backendTLS == nil {
		if err := forwardMySQLAuthentication(securedVisitor, backend, scramble, &clientFlags); err != nil {
			return err
		}
	}
	if d.observeDatabase != nil {
		var observer *mysqlInspector
		if d.backendTLS != nil {
			observer = newMySQLInspectorDuringAuth(clientFlags, d.observeDatabase)
		} else {
			observer = newMySQLInspector(clientFlags, d.observeDatabase)
		}
		backend = &databaseInspectionConn{Conn: backend, observer: observer}
	}
	return copyTCPConnections(visitor, securedVisitor, backend, d.admission)
}

func (d *tcpForwarding) connectTargetTLS(backend net.Conn) (net.Conn, error) {
	secured := tls.Client(backend, d.backendTLS)
	if err := secured.Handshake(); err != nil {
		d.targetFailed()
		return nil, err
	}
	return secured, nil
}

func (d *tcpForwarding) targetFailed() {
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

func forwardDatabaseTLS(visitor, backend net.Conn, publicTLS *tls.Config, admission *applicationAdmission,
	observe func(DatabaseObservation)) error {
	var visitorCertificate []byte
	if publicTLS.GetCertificate != nil {
		publicTLS = publicTLS.Clone()
		getCertificate := publicTLS.GetCertificate
		publicTLS.GetCertificate = func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			certificate, err := getCertificate(hello)
			if err == nil && certificate != nil && len(certificate.Certificate) != 0 {
				visitorCertificate = certificate.Certificate[0]
			}
			return certificate, err
		}
	}
	securedVisitor := tls.Server(visitor, publicTLS)
	if err := securedVisitor.Handshake(); err != nil {
		return err
	}
	var client net.Conn = securedVisitor
	if targetTLS, ok := backend.(*tls.Conn); !ok || len(targetTLS.ConnectionState().PeerCertificates) == 0 ||
		!bytes.Equal(visitorCertificate, targetTLS.ConnectionState().PeerCertificates[0].Raw) {
		client = &postgresAuthChoiceConn{Conn: securedVisitor}
	}
	if observe != nil {
		backend = &databaseInspectionConn{Conn: backend, observer: newPostgresInspector(observe)}
	}
	return copyTCPConnections(visitor, client, backend, admission)
}

func copyTCPConnections(visitor, securedVisitor, backend net.Conn, admission *applicationAdmission) error {
	if status, _ := admission.enter(time.Now()); status != 0 {
		return errors.New("publisher: TCP visitor capacity is exhausted")
	}
	defer admission.leave()
	_ = visitor.SetDeadline(time.Time{})
	_ = backend.SetDeadline(time.Time{})
	_, err := streamcopy.Copy(securedVisitor, backend)
	return err
}

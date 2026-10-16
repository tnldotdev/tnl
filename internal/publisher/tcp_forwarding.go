package publisher

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"time"

	"github.com/tnldotdev/tnl/internal/diagnostic"
	"github.com/tnldotdev/tnl/internal/inspection"
	"github.com/tnldotdev/tnl/internal/livevisitor"
	"github.com/tnldotdev/tnl/internal/protocolinspection"
	"github.com/tnldotdev/tnl/internal/streamcopy"
	"github.com/tnldotdev/tnl/internal/tcpport"
	"github.com/tnldotdev/tnl/internal/tcptarget"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

var postgresSSLRequest = [8]byte{0, 0, 0, 8, 4, 210, 22, 47}
var postgresGSSRequest = [8]byte{0, 0, 0, 8, 4, 210, 22, 48}

const mysqlClientSSL = 1 << 11

type tcpForwarding struct {
	protocol        controlv1.PublicURLServiceProtocol
	admission       *applicationAdmission
	publicPort      uint16
	target          string
	resolveTarget   func(context.Context) (string, string, error)
	backendTLS      *tls.Config
	onTargetFailure func()
	authorize       AuthorizeVisitorCertificate
	revalidate      RevalidateVisitorCertificate
	liveVisitors    livevisitor.Group
	liveSlots       chan struct{}
	observe         inspection.Observer
	warn            func(string)
	warningOnce     sync.Once
}

func newTCPForwarding(config PublicURLServerConfig) (*tcpForwarding, error) {
	if config.ServiceProtocol == "" || config.ServiceProtocol == controlv1.Http {
		if config.PublicPort != 0 || config.TargetTLS {
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
		tlsName = config.TargetOptions.ServerName
	}
	if tlsName == "" {
		tlsName = host
	}
	var backendTLS *tls.Config
	if config.TargetTLS {
		backendTLS = &tls.Config{MinVersion: tls.VersionTLS12, ServerName: tlsName,
			RootCAs: config.TargetOptions.RootCAs}
	}
	observe := config.ObserveSummary
	if config.InspectionMode == "none" {
		observe = nil
	}
	return &tcpForwarding{
		protocol: config.ServiceProtocol, publicPort: config.PublicPort, target: config.Target, resolveTarget: config.ResolveTarget,
		backendTLS:      backendTLS,
		onTargetFailure: config.OnTargetFailure,
		authorize:       config.AuthorizeVisitorCertificate,
		revalidate:      config.RevalidateVisitorCertificate,
		observe:         observe, warn: config.OnWarning,
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
	if !config.TargetTLS && (config.TargetTLSName != "" || config.TargetOptions.ServerName != "" || config.TargetOptions.RootCAs != nil) {
		return "", errors.New("publisher: target TLS options require target TLS")
	}
	host, err := tcptarget.Host(config.Target)
	if err != nil {
		return "", diagnostic.Wrap(diagnostic.TargetInvalid, err)
	}
	return host, nil
}

func (d *tcpForwarding) forward(visitor net.Conn, publicTLS *tls.Config, session *visitorSession) {
	base := session.life
	if base == nil {
		base = context.Background()
	}
	ctx, cancel := context.WithTimeout(base, 10*time.Second)
	defer cancel()
	target := d.target
	if d.resolveTarget != nil {
		var identity string
		var err error
		target, identity, err = d.resolveTarget(ctx)
		if err != nil || target == "" || identity == "" {
			d.targetFailed()
			return
		}
		if _, err := tcptarget.Host(target); err != nil {
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
	if d.authorize != nil || d.revalidate != nil {
		visitorTLS.ClientAuth = tls.RequestClientCert
	}
	switch d.protocol {
	case controlv1.Postgres:
		_ = d.postgres(ctx, visitor, backend, visitorTLS, session)
	case controlv1.Mysql:
		_ = d.mysql(ctx, visitor, backend, visitorTLS, session)
	case controlv1.Redis:
		_ = d.redis(ctx, visitor, backend, visitorTLS, session)
	case controlv1.Ssh:
		_ = d.ssh(ctx, visitor, backend, session)
	}
}

func (d *tcpForwarding) ssh(ctx context.Context, visitor, backend net.Conn, session *visitorSession) error {
	if d.backendTLS != nil {
		secured, err := d.connectTargetTLS(backend)
		if err != nil {
			return err
		}
		backend = secured
	}
	release, err := d.admit(ctx, session)
	if err != nil {
		return err
	}
	defer release()
	return copyTCPConnections(visitor, visitor, backend)
}

func (d *tcpForwarding) redis(ctx context.Context, visitor, backend net.Conn, publicTLS *tls.Config, session *visitorSession) error {
	securedVisitor := tls.Server(visitor, publicTLS)
	if err := securedVisitor.Handshake(); err != nil {
		return err
	}
	stopAuthorization, err := d.authorizeTLS(ctx, session, securedVisitor, backend)
	if err != nil {
		return err
	}
	defer stopAuthorization()
	if d.backendTLS != nil {
		secured, err := d.connectTargetTLS(backend)
		if err != nil {
			return err
		}
		backend = secured
	}
	release, err := d.admit(ctx, session)
	if err != nil {
		return err
	}
	defer release()
	monitor := protocolinspection.New("redis", d.observe)
	return copyTCPConnections(visitor, protocolinspection.Wrap(securedVisitor, monitor, true), protocolinspection.Wrap(backend, monitor, false))
}

func (d *tcpForwarding) postgres(ctx context.Context, visitor, backend net.Conn, publicTLS *tls.Config, session *visitorSession) error {
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
		if binary.BigEndian.Uint32(startup[:4]) == 16 && binary.BigEndian.Uint32(startup[4:]) == 80877102 {
			d.warningOnce.Do(func() {
				if d.warn != nil {
					d.warn("plaintext PostgreSQL cancellation was rejected; use a client that encrypts cancellation requests")
				}
			})
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
	// capture the certificate actually selected for this handshake, rather than
	// consulting a possibly renewed certificate after the handshake completes.
	var visitorLeaf []byte
	publicTLS = publicTLS.Clone()
	selectCertificate := publicTLS.GetCertificate
	publicTLS.GetCertificate = func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		var certificate *tls.Certificate
		var err error
		if selectCertificate != nil {
			certificate, err = selectCertificate(hello)
		} else if len(publicTLS.Certificates) > 0 {
			certificate = &publicTLS.Certificates[0]
		}
		if certificate != nil && len(certificate.Certificate) > 0 {
			visitorLeaf = certificate.Certificate[0]
		}
		return certificate, err
	}
	secured := tls.Server(visitor, publicTLS)
	if err := secured.HandshakeContext(ctx); err != nil {
		return err
	}
	stopAuthorization, err := d.authorizeTLS(ctx, session, secured, backend)
	if err != nil {
		return err
	}
	defer stopAuthorization()
	release, err := d.admit(ctx, session)
	if err != nil {
		return err
	}
	defer release()
	monitor := protocolinspection.New("postgres", d.observe)
	guard := &postgresLoginConn{Conn: secured, allowPlus: samePostgresTLSCertificate(visitorLeaf, backend)}
	return copyTCPConnections(visitor, protocolinspection.Wrap(guard, monitor, true), protocolinspection.Wrap(backend, monitor, false))
}

// PostgreSQL uses tls-server-end-point channel binding. PLUS remains compatible
// only when verified target TLS presents the exact same leaf certificate.
func samePostgresTLSCertificate(visitorLeaf []byte, backend net.Conn) bool {
	target, ok := backend.(*tls.Conn)
	if !ok || len(target.ConnectionState().PeerCertificates) == 0 {
		return false
	}
	return len(visitorLeaf) > 0 && bytes.Equal(visitorLeaf, target.ConnectionState().PeerCertificates[0].Raw)
}

func (d *tcpForwarding) mysql(ctx context.Context, visitor, backend net.Conn, publicTLS *tls.Config, session *visitorSession) error {
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
	stopAuthorization, err := d.authorizeTLS(ctx, session, securedVisitor, backend)
	if err != nil {
		return err
	}
	defer stopAuthorization()
	release, err := d.admit(ctx, session)
	if err != nil {
		return err
	}
	defer release()
	var flags uint32
	if d.backendTLS == nil {
		var err error
		flags, err = forwardMySQLAuthenticationFlags(securedVisitor, backend, scramble)
		if err != nil {
			return err
		}
	} else {
		flags, err = forwardMySQLTLSAuthentication(securedVisitor, backend)
		if err != nil {
			return err
		}
	}
	monitor := protocolinspection.New("mysql", d.observe)
	if monitor != nil {
		monitor.MySQLFlags(flags)
	}
	return copyTCPConnections(visitor, protocolinspection.Wrap(securedVisitor, monitor, true), protocolinspection.Wrap(backend, monitor, false))
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

func copyTCPConnections(visitor, securedVisitor, backend net.Conn) error {
	_ = visitor.SetDeadline(time.Time{})
	_ = backend.SetDeadline(time.Time{})
	_, err := streamcopy.Copy(securedVisitor, backend)
	return err
}

func (d *tcpForwarding) admit(ctx context.Context, session *visitorSession) (func(), error) {
	release, status, _ := d.admission.acquire(ctx)
	if status != 0 {
		return nil, errors.New("publisher: TCP visitor capacity is exhausted")
	}
	if err := session.admit(ctx); err != nil {
		d.admission.refund()
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		d.admission.refund()
		return nil, err
	}
	return release, nil
}

func (d *tcpForwarding) authorizeTLS(ctx context.Context, session *visitorSession, secured *tls.Conn, backend net.Conn) (func(), error) {
	if d.authorize != nil {
		if err := d.authorize(ctx, session.visitor, secured.ConnectionState()); err != nil {
			return nil, err
		}
	}
	if d.revalidate == nil {
		if d.authorize != nil {
			return func() {}, nil
		}
		if session.visitor.Header.AccessPending {
			return nil, errors.New("publisher: denied database visitor requires live certificate authorization")
		}
		return func() {}, nil
	}
	state := secured.ConnectionState()
	key, err := visitorAuthorizationKey(session.visitor, state)
	if err != nil {
		return nil, err
	}
	// reserve watcher capacity before creating any checker or session worker.
	// the existing application concurrency limit also bounds pending checks.
	if d.liveSlots != nil {
		select {
		case d.liveSlots <- struct{}{}:
		default:
			return nil, errors.New("publisher: TCP visitor capacity is exhausted")
		}
	}
	releaseSlot := func() {
		if d.liveSlots != nil {
			<-d.liveSlots
		}
	}
	lease, _, err := d.liveVisitors.Acquire(ctx, key, func(ctx context.Context) (livevisitor.Decision, error) {
		return d.revalidate(ctx, session.visitor, state)
	})
	if err != nil {
		releaseSlot()
		return nil, err
	}
	stop, err := session.watchAuthorization(lease, secured.NetConn(), backend)
	if err != nil {
		releaseSlot()
		return nil, err
	}
	var once sync.Once
	return func() { once.Do(func() { stop(); releaseSlot() }) }, nil
}

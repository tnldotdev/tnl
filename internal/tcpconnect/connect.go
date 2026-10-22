// package tcpconnect owns the loopback visitor endpoint of private tunnels.
package tcpconnect

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"time"

	serviceconfig "github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/controlclient"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/muxsession"
	"github.com/tnldotdev/tnl/internal/observability"
	"github.com/tnldotdev/tnl/internal/opaqueid"
	"github.com/tnldotdev/tnl/internal/streamcopy"
	"github.com/tnldotdev/tnl/internal/targettransport"
	"github.com/tnldotdev/tnl/internal/tunnel"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

var ErrPrivateConnection = errors.New("private service: authenticated connection is unavailable")

// Signer binds one tagged subject to its public key and proof operation. the
// workload adapter retains its ephemeral private key in workloadclient.
type Signer struct {
	Subject   tunnelv1.VisitorSubject
	PublicKey ed25519.PublicKey
	Sign      func([]byte) []byte `json:"-"`
}

func (Signer) String() string   { return "private connector signer" }
func (Signer) GoString() string { return "private connector signer" }

type Assignment struct {
	SessionID, PrivateServiceID string
	Subject                     tunnelv1.VisitorSubject
	IngressID                   string
	Endpoint                    muxsession.Endpoint
	Credential                  string
	ExpiresAt                   time.Time
	TransportTLS                *tls.Config
}

func (Assignment) String() string   { return "private connector assignment" }
func (Assignment) GoString() string { return "private connector assignment" }

// Run is a current control-selected publisher and its approved TLS metadata.
// selection never grants a stream: ingress checks the live grant separately.
type Run struct {
	PrivateServiceID, PrivateRunID string
	RunNumber                      uint64
	ValidUntil                     time.Time
	Protocol                       string
	TrustRevision                  int64
	ManagedTLS                     *controlv1.ManagedServiceTLS
	ServiceTLS                     *tls.Config `json:"-"`
}

func (Run) String() string   { return "selected private service run" }
func (Run) GoString() string { return "selected private service run" }

type Control interface {
	PrivateConnectorSigner(context.Context, string) (Signer, error)
	PrivateConnectorAssignment(context.Context, string, tunnelv1.VisitorSubject, uint8) (Assignment, error)
	ResolvePrivateService(context.Context, string) (Run, error)
}

type Config struct {
	Control                                Control
	PrivateServiceID, IdentityID, Protocol string
	// TrustRevision is the approved metadata revision. selected metadata is
	// authoritative; target trust is owned only by the publisher.
	TrustRevision int64
	Ready         func() error
	// infrastructure trust is independent of the optional target CA bundle.
	TransportTLS   *tls.Config
	MaxConnections int
	ManagedTLS     *controlv1.ManagedServiceTLS
	ServiceTLS     *tls.Config `json:"-"`
	// an owner may supply one shared shutdown budget for all path releases.
	CleanupContext func() context.Context `json:"-"`
}

func (Config) String() string   { return "private connector configuration" }
func (Config) GoString() string { return "private connector configuration" }

type connectorPath struct {
	*tunnel.PrivateConnectorSession
	transport tunnel.Transport
	mu        sync.Mutex
	active    int
	draining  bool
	changed   chan struct{}
	lifetime  context.Context
	cancel    context.CancelFunc
	watchDone chan struct{}
	release   func() error
	closeOnce sync.Once
	closeErr  error
}

func (p *connectorPath) Close() error {
	p.closeOnce.Do(func() {
		p.cancel()
		p.closeErr = p.PrivateConnectorSession.Close()
		<-p.watchDone
		if p.release != nil {
			p.closeErr = errors.Join(p.closeErr, p.release())
		}
	})
	return p.closeErr
}

func (p *connectorPath) Transport() tunnel.Transport { return p.transport }
func (p *connectorPath) Serve(ctx context.Context) error {
	lifetime := time.Until(p.Accepted.ExpiresAt)
	timer := time.NewTimer(lifetime - min(30*time.Second, lifetime/4))
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return context.Cause(ctx)
	case <-p.Done():
		return p.Err()
	case <-timer.C:
		return tunnel.ErrRotateSession
	}
}

func (p *connectorPath) acquire() (func(), error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.draining || !p.Accepted.ExpiresAt.After(time.Now()) {
		return nil, ErrPrivateConnection
	}
	p.active++
	return sync.OnceFunc(func() { p.mu.Lock(); p.active--; close(p.changed); p.changed = make(chan struct{}); p.mu.Unlock() }), nil
}

func (p *connectorPath) Drain(ctx context.Context) error {
	p.mu.Lock()
	p.draining = true
	for p.active != 0 {
		changed := p.changed
		p.mu.Unlock()
		select {
		case <-ctx.Done():
			return context.Cause(ctx)
		case <-changed:
		}
		p.mu.Lock()
	}
	p.mu.Unlock()
	return nil
}

// Serve starts two independently authenticated ingress paths before reporting
// readiness. each local connection opens exactly one authorized stream;
// a failed live stream is closed, never migrated or replayed on the other path.
func Serve(ctx context.Context, listener net.Listener, config Config) (result error) {
	if listener == nil {
		return ErrPrivateConnection
	}
	address, ok := listener.Addr().(*net.TCPAddr)
	if !ok || !address.IP.IsLoopback() {
		return ErrPrivateConnection
	}
	return serveConnections(ctx, config, false, func(ctx context.Context, forward func(context.Context, net.Conn) error) error {
		return serveLoopback(ctx, listener, config.MaxConnections, config.Ready, func(ctx context.Context, local net.Conn) { _ = forward(ctx, local) })
	})
}

// Stream carries exactly one opaque stream without a listener. it owns local,
// joins both copy directions and all transport workers, and never reopens a
// stream after admission or replays application bytes after a failure.
func Stream(ctx context.Context, local net.Conn, config Config) error {
	if local == nil || config.Protocol != "tcp" {
		return ErrPrivateConnection
	}
	defer local.Close()
	stop := context.AfterFunc(ctx, func() { _ = local.Close() })
	defer stop()
	return serveConnections(ctx, config, true, func(ctx context.Context, forward func(context.Context, net.Conn) error) error {
		return forward(ctx, local)
	})
}

type connectionConsumer func(context.Context, func(context.Context, net.Conn) error) error

func serveConnections(ctx context.Context, config Config, single bool, consume connectionConsumer) (result error) {
	startupCtx, finishStartup := observability.ClientOperation(ctx, "connector.startup")
	defer func() { finishStartup(result) }()
	if config.Control == nil || !opaqueid.Valid(config.PrivateServiceID, opaqueid.PrivateServicePrefix) ||
		(config.IdentityID != "" && !opaqueid.Valid(config.IdentityID, opaqueid.IdentityPrefix)) || !validProtocol(config.Protocol) || config.TrustRevision < 1 {
		return ErrPrivateConnection
	}
	if config.TransportTLS != nil && config.TransportTLS.InsecureSkipVerify {
		return ErrPrivateConnection
	}
	if config.ManagedTLS == nil || config.ManagedTLS.Hostname == "" || config.ManagedTLS.Port < 1024 || config.ManagedTLS.Port > 65535 {
		return ErrPrivateConnection
	}
	if config.MaxConnections == 0 {
		config.MaxConnections = 64
	}
	if config.MaxConnections < 1 {
		return ErrPrivateConnection
	}
	cleanupContext := func() context.Context {
		if config.CleanupContext != nil {
			return config.CleanupContext()
		}
		return observability.Independent(context.WithoutCancel(ctx))
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(cleanupContext(), 5*time.Second)
		defer cancel()
		if closer, ok := config.Control.(interface{ CloseContext(context.Context) error }); ok {
			result = errors.Join(result, closer.CloseContext(cleanup))
		} else if closer, ok := config.Control.(interface{ Close() error }); ok {
			result = errors.Join(result, closer.Close())
		}
	}()
	if config.ServiceTLS == nil || config.ServiceTLS.InsecureSkipVerify || len(config.ServiceTLS.Certificates) != 0 || config.ServiceTLS.GetClientCertificate != nil {
		return ErrPrivateConnection
	}
	serveCtx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)
	signer, err := config.Control.PrivateConnectorSigner(startupCtx, config.IdentityID)
	if err != nil {
		return err
	}
	if signer.Subject.Validate() != nil || signer.Subject.IdentityID != config.IdentityID || len(signer.PublicKey) != ed25519.PublicKeySize || signer.Sign == nil {
		return ErrPrivateConnection
	}
	var assignmentMu sync.Mutex
	var assignedIngress [2]string
	attempted := make(map[string]bool)
	paths, err := tunnel.NewSlots(observability.LinkContext(serveCtx, startupCtx), tunnel.SlotsConfig{Connect: func(ctx context.Context, slot uint8, preferTCP bool) (_ tunnel.SlotSession, result error) {
		ctx, finish := observability.ClientOperation(ctx, "connector.path.connect")
		defer func() { finish(result) }()
		assignment, err := config.Control.PrivateConnectorAssignment(ctx, config.PrivateServiceID, signer.Subject, slot)
		if err != nil {
			_, definition, known := failure.Describe(err)
			// assignment conflicts retire this attempt, not another slot's live
			// authorization. the adapter discards a confirmed stale request key.
			if single || known && definition.Retry != failure.RetryLater && !errors.Is(err, controlclient.ErrStatusConflict) {
				cancel(err)
			}
			return nil, err
		}
		assignmentMu.Lock()
		used := attempted[assignment.SessionID]
		if !used {
			attempted[assignment.SessionID] = true
		}
		assignmentMu.Unlock()
		if used {
			return nil, ErrPrivateConnection
		}
		release := func() error {
			if control, ok := config.Control.(assignmentReleaser); ok {
				bounded, cancel := context.WithTimeout(cleanupContext(), 5*time.Second)
				defer cancel()
				cleanup, finish := observability.ClientOperation(bounded, "connector.path.release")
				err := control.ReleasePrivateConnectorAssignment(cleanup, assignment.SessionID)
				finish(err)
				return err
			}
			return nil
		}
		owned := true
		defer func() {
			if owned {
				_ = release()
			}
		}()
		if !opaqueid.Valid(assignment.SessionID, opaqueid.PrivateConnectorSessionPrefix) || assignment.PrivateServiceID != config.PrivateServiceID || assignment.Subject != signer.Subject ||
			!assignment.ExpiresAt.After(time.Now()) || assignment.IngressID == "" || assignment.Endpoint.ServerName == "" || assignment.Endpoint.Address == "" {
			return nil, ErrPrivateConnection
		}
		assignmentMu.Lock()
		distinct := assignedIngress[1-slot] != assignment.IngressID
		if distinct {
			assignedIngress[slot] = assignment.IngressID
		}
		assignmentMu.Unlock()
		if !distinct {
			return nil, ErrPrivateConnection
		}
		roots := config.TransportTLS
		if assignment.TransportTLS != nil {
			if assignment.TransportTLS.InsecureSkipVerify || assignment.TransportTLS.ServerName != assignment.Endpoint.ServerName {
				return nil, ErrPrivateConnection
			}
			roots = assignment.TransportTLS
		}
		if roots == nil {
			return nil, ErrPrivateConnection
		}
		nonce, err := tunnelv1.NewConnectorSessionNonce()
		if err != nil {
			return nil, err
		}
		hello := tunnelv1.PrivateConnectorSessionHello{ProtocolVersion: tunnelv1.Version, Kind: "private_connector_session",
			PrivateServiceID: config.PrivateServiceID, SessionID: assignment.SessionID, Credential: assignment.Credential,
			Subject: signer.Subject, Nonce: nonce}
		digest, err := hello.Claim().Digest()
		if err != nil {
			return nil, err
		}
		hello.Signature = signer.Sign(digest)
		if !ed25519.Verify(signer.PublicKey, digest, hello.Signature) {
			return nil, ErrPrivateConnection
		}
		primary := tunnel.Candidate{Connector: muxsession.PrivateQUICConnector{TLSConfig: roots}, Endpoint: assignment.Endpoint, Transport: tunnel.TransportQUIC}
		fallback := tunnel.Candidate{Connector: muxsession.PrivateMuxTLSConnector{TLSConfig: roots}, Endpoint: assignment.Endpoint, Transport: tunnel.TransportTLSTCP}
		if preferTCP {
			primary, fallback = fallback, primary
		}
		session, transport, err := tunnel.RacePrivateConnector(ctx, primary, fallback, 250*time.Millisecond, hello)
		if err != nil {
			return nil, err
		}
		if session.Accepted.ExpiresAt.After(assignment.ExpiresAt) {
			_ = session.Close()
			return nil, ErrPrivateConnection
		}
		lifetime, cancel := context.WithCancel(observability.Independent(context.WithoutCancel(ctx)))
		path := &connectorPath{PrivateConnectorSession: session, transport: transport, changed: make(chan struct{}), lifetime: lifetime, cancel: cancel, watchDone: make(chan struct{}), release: release}
		go func() {
			defer close(path.watchDone)
			select {
			case <-session.Done():
				cancel()
			case <-lifetime.Done():
			}
		}()
		owned = false
		return path, nil
	}})
	if err != nil {
		return err
	}
	defer paths.Close()
	for slot := range uint8(2) {
		if err := paths.Set(slot, "ingress"); err != nil {
			return err
		}
	}
	startup := time.NewTimer(30 * time.Second)
	defer startup.Stop()
	for {
		ready, changed := paths.Snapshot()
		if ready[0] != nil && ready[1] != nil {
			break
		}
		select {
		case <-serveCtx.Done():
			if ctx.Err() != nil {
				return nil
			}
			return context.Cause(serveCtx)
		case <-changed:
		case <-startup.C:
			return failure.Wrap("prepare connector paths", failure.ConnectionUnavailable, context.DeadlineExceeded)
		}
	}
	var next atomic.Uint64
	forward := func(forwardCtx context.Context, local net.Conn) error {
		// resolve approved metadata before opening one publisher stream. native
		// clients negotiate TLS through it; opaque clients use tnl's TLS helper.
		run, err := config.Control.ResolvePrivateService(forwardCtx, config.PrivateServiceID)
		if err != nil {
			return err
		}
		if run.PrivateServiceID != config.PrivateServiceID || !opaqueid.Valid(run.PrivateRunID, opaqueid.PrivateRunPrefix) || run.RunNumber == 0 ||
			run.ManagedTLS == nil || !run.ValidUntil.After(time.Now()) {
			return ErrPrivateConnection
		}
		protocol := run.Protocol
		if !validProtocol(protocol) || run.TrustRevision < 1 {
			return ErrPrivateConnection
		}
		if protocol != config.Protocol || run.TrustRevision != config.TrustRevision || !sameManagedTLS(run.ManagedTLS, config.ManagedTLS) {
			err := metadataReload(config.PrivateServiceID, config.TrustRevision, run.TrustRevision)
			cancel(err)
			return err
		}
		run.ServiceTLS = config.ServiceTLS
		if forwardCtx.Err() != nil {
			return context.Cause(forwardCtx)
		}
		current, _ := paths.Snapshot()
		first := next.Add(1) % 2
		for attempt := range uint64(2) {
			path, ok := current[(first+attempt)%2].(*connectorPath)
			if !ok {
				continue
			}
			provider, committed, err := openPrivate(forwardCtx, path, run)
			if err != nil {
				if committed {
					return err
				}
				continue
			}
			defer provider.Close()
			if local == nil {
				// opaque TLS is already verified by openPrivate. native protocols
				// negotiate their own TLS through this same admitted stream.
				if config.Protocol == "tcp" {
					return nil
				}
				verification := config.ServiceTLS.Clone()
				verification.ServerName = run.ManagedTLS.Hostname
				return (targettransport.Transport{Protocol: serviceconfig.ProtocolName(config.Protocol), TLS: verification}).PreflightConnection(forwardCtx, provider)
			}
			connectionCtx, cancelConnection := context.WithCancel(forwardCtx)
			defer cancelConnection()
			stopPath := context.AfterFunc(path.lifetime, cancelConnection)
			defer stopPath()
			stop := context.AfterFunc(connectionCtx, func() { _ = local.Close(); _ = provider.Close() })
			defer stop()
			_, err = streamcopy.Copy(local, provider)
			return err
		}
		return ErrPrivateConnection
	}
	if !single {
		probe, cancel := context.WithTimeout(serveCtx, 10*time.Second)
		err := forward(probe, nil)
		cancel()
		if err != nil {
			reason := failure.ConnectionUnavailable
			var certificateError *tls.CertificateVerificationError
			reasonOf, _ := failure.ReasonOf(err)
			if reasonOf == failure.ServerDenied {
				return err
			}
			if errors.As(err, &certificateError) || reasonOf == failure.TargetTLSRejected {
				reason = failure.ConnectionTLSRejected
			}
			return failure.Wrap("verify native service TLS", reason, err)
		}
		next.Store(0)
	}
	finishStartup(nil)
	return consume(observability.LinkContext(serveCtx, startupCtx), forward)
}

func validProtocol(protocol string) bool {
	return protocol == "http" || protocol == "tcp" || protocol == "mysql" || protocol == "postgres" || protocol == "kubernetes"
}

func openPrivate(ctx context.Context, path *connectorPath, run Run) (result net.Conn, committed bool, err error) {
	ctx, endSetup := observability.Start(ctx, "connector.visitor_setup")
	defer func() { endSetup(err) }()
	release, err := path.acquire()
	if err != nil {
		return nil, false, err
	}
	defer func() {
		if err != nil {
			release()
		}
	}()
	setup, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	stopPath := context.AfterFunc(path.lifetime, cancel)
	defer stopPath()
	stream, err := path.OpenStream(setup)
	if err != nil {
		return nil, false, err
	}
	defer func() {
		if err != nil {
			_ = stream.Close()
		}
	}()
	deadline, _ := setup.Deadline()
	if err = stream.SetDeadline(deadline); err != nil {
		return nil, false, err
	}
	stop := context.AfterFunc(setup, func() { _ = stream.SetDeadline(time.Now()) })
	defer stop()
	entry := tunnelv1.PrivateVisitorEntry{ProtocolVersion: tunnelv1.Version, Kind: tunnelv1.PrivateVisitorStream,
		PrivateServiceID: run.PrivateServiceID, PrivateRunID: run.PrivateRunID, RunNumber: run.RunNumber}
	entry.TraceContext = observability.WireTrace(ctx)
	if err = tunnelv1.WritePrivateVisitorEntry(stream, entry); err != nil {
		return nil, false, err
	}
	accepted, err := tunnelv1.ReadPrivateVisitorAccepted(stream)
	if err != nil {
		return nil, false, err
	}
	if accepted.ConnectorSessionID != path.Accepted.SessionID || accepted.Subject != path.Accepted.Subject || accepted.SourceIP != path.Accepted.SourceIP {
		return nil, true, ErrPrivateConnection
	}
	if run.ManagedTLS == nil {
		return nil, false, ErrPrivateConnection
	}
	{
		if run.Protocol == "tcp" {
			if run.ServiceTLS == nil || run.ServiceTLS.InsecureSkipVerify {
				return nil, false, ErrPrivateConnection
			}
			verification := run.ServiceTLS.Clone()
			verification.ServerName = run.ManagedTLS.Hostname
			verification.MinVersion = max(verification.MinVersion, tls.VersionTLS12)
			secured := tls.Client(stream, verification)
			committed = true
			if err = secured.HandshakeContext(setup); err != nil {
				return nil, true, err
			}
			if err = stream.SetDeadline(time.Time{}); err != nil {
				return nil, true, err
			}
			return &privateConn{Conn: secured, release: release}, true, nil
		}
		if err = stream.SetDeadline(time.Time{}); err != nil {
			return nil, false, err
		}
		return &privateConn{Conn: stream, release: release}, true, nil
	}
}

type privateConn struct {
	net.Conn
	release func()
}

func sameManagedTLS(left, right *controlv1.ManagedServiceTLS) bool {
	if left == nil || right == nil {
		return left == right
	}
	return left.Hostname == right.Hostname && left.Port == right.Port && left.Public == right.Public
}

func (c *privateConn) Close() error { defer c.release(); return c.Conn.Close() }
func (c *privateConn) CloseWrite() error {
	if writer, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return writer.CloseWrite()
	}
	return errors.ErrUnsupported
}

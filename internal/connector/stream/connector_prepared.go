package stream

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"net"
	"sync"
	"time"

	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/observability"
	"github.com/tnldotdev/tnl/internal/transport/muxsession"
	"github.com/tnldotdev/tnl/internal/transport/streamcopy"
	"github.com/tnldotdev/tnl/internal/transport/tunnel"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

// PreparedConnector owns one already signed connector opening and its stream. opaque TCP
// completes visitor TLS here; other protocols retain application-owned negotiation.
// it is single-use: local arrival cannot select a run, sign,
// call control, reset setup time, or replace the target after live bytes fail.
// the pair/session owner must close these children before replacing its run.
type PreparedConnector struct {
	ctx                context.Context
	conn               net.Conn
	mu                 sync.Mutex
	stream             preparedStreamPhase
	permission         preparedPermissionPhase
	stop               func() bool
	callbackDone       chan struct{}
	physicalOnce       sync.Once
	physicalErr        error
	stdio              *stdioStream
	closeOnce          sync.Once
	closeErr           error
	work               sync.WaitGroup
	permissionUpdates  chan preparedPermissionRenewal
	permissionCancel   context.CancelCauseFunc
	permissionStop     *preparedPermissionStop
	permissionUntil    time.Time
	permissionErr      error
	stdioClosedOnAbort bool
}

// stream consumption and permission renewal are independent lifecycles. a
// pending renewal retains its one wakeup through the active proof and any
// queued replacement; a denied proof never returns to the usable phase.
type preparedStreamPhase interface{ preparedStreamPhase() }
type streamPrepared struct{}
type streamForwarding struct{}
type streamClosed struct{}

func (streamPrepared) preparedStreamPhase()   {}
func (streamForwarding) preparedStreamPhase() {}
func (streamClosed) preparedStreamPhase()     {}

type preparedPermissionPhase interface{ preparedPermissionPhase() }
type permissionUsable struct{}
type permissionQueued struct{ wait chan struct{} }
type permissionRenewing struct{ wait chan struct{} }
type permissionDenied struct{}

func (permissionUsable) preparedPermissionPhase()   {}
func (permissionQueued) preparedPermissionPhase()   {}
func (permissionRenewing) preparedPermissionPhase() {}
func (permissionDenied) preparedPermissionPhase()   {}

func (p *PreparedConnector) closedLocked() bool {
	_, closed := p.stream.(streamClosed)
	return closed
}

func (p *PreparedConnector) permissionWaitLocked() chan struct{} {
	switch state := p.permission.(type) {
	case permissionQueued:
		return state.wait
	case permissionRenewing:
		return state.wait
	default:
		return nil
	}
}

func (p *PreparedConnector) permissionDeniedLocked() bool {
	_, denied := p.permission.(permissionDenied)
	return denied
}

type preparedPermissionRenewal struct {
	writer interface {
		Renew(context.Context, tunnelv1.ConnectorPermissionUpdate) error
	}
	update tunnelv1.ConnectorPermissionUpdate
	until  time.Time
}

// each prepared stream identifies its own finished renewal work. a caller's
// cancellation, a denial, or a transport failure is not this shutdown cause.
type preparedPermissionStop struct{ owner *PreparedConnector }

func (*preparedPermissionStop) Error() string {
	return "the prepared stream finished its permission work"
}

// PrepareConnector consumes a source-prepared opening without RPC or signing.
// setup retains the caller's original preparation deadline; lifetime owns the
// promoted stream after preparation succeeds. stopping setup cannot close it.
// the publisher independently checks the signed token, exact relay-attested
// pair, current policy and C.
func PrepareConnector(lifetime, setup context.Context, session muxsession.Session, run Run, entry tunnelv1.ConnectorPeerVisitorEntry) (_ *PreparedConnector, result error) {
	setup, finish := observability.ClientOperation(setup, "connector.visitor_setup")
	defer func() { finish(result) }()
	ctx := lifetime
	if ctx == nil || ctx.Err() != nil || session == nil || !validProtocol(run.Protocol) || run.Endpoint == nil || run.ServiceTLS == nil || run.ServiceTLS.InsecureSkipVerify || len(run.ServiceTLS.Certificates) != 0 || run.ServiceTLS.GetClientCertificate != nil || !run.ValidUntil.After(time.Now()) ||
		run.ServiceID != entry.ServiceID || run.ServiceRunID != entry.ServiceRunID || run.RunNumber != entry.RunNumber || run.TrustRevision < 1 || uint64(run.TrustRevision) != entry.MetadataRevision {
		return nil, ErrServiceConnection
	}
	public, keyErr := base64.RawURLEncoding.Strict().DecodeString(entry.Permission.PublicKey)
	signature, signatureErr := base64.RawURLEncoding.Strict().DecodeString(entry.Permission.Signature)
	message, messageErr := tunnelv1.ConnectorPeerProofMessage(entry, nil)
	if keyErr != nil || signatureErr != nil || messageErr != nil || len(public) != ed25519.PublicKeySize || !ed25519.Verify(public, message, signature) {
		return nil, ErrServiceConnection
	}
	setup, cancel := context.WithTimeout(setup, 10*time.Second)
	defer cancel()
	raw, err := session.OpenStream(setup)
	if err != nil {
		return nil, err
	}
	var selected *stdioStream
	if operation := stdioOperationFor(lifetime); operation != nil {
		selected, err = operation.bind(raw)
		if err != nil {
			return nil, errors.Join(err, raw.Close())
		}
		raw = selected
	}
	setupDone := make(chan struct{})
	stopSetup := context.AfterFunc(setup, func() { defer close(setupDone); _ = raw.Close() })
	setupStopped := false
	defer func() {
		if !setupStopped && !stopSetup() {
			<-setupDone
		}
	}()
	owned := false
	defer func() {
		if !owned {
			_ = raw.Close()
		}
	}()
	deadline, _ := setup.Deadline()
	if run.ValidUntil.Before(deadline) {
		deadline = run.ValidUntil
	}
	if err := raw.SetDeadline(deadline); err != nil {
		return nil, err
	}
	entry.TraceContext = observability.WireTrace(setup)
	if _, err := tunnelv1.WriteConnectorPeerVisitorOpening(raw, entry, nil); err != nil {
		return nil, err
	}
	// application and control streams have independent delivery. preparation is
	// not eligible for renewal until the publisher confirms this exact admission.
	if err := tunnelv1.ReadConnectorPeerVisitorAccepted(raw, entry.VisitorConnectionID); err != nil {
		return nil, err
	}
	var connection net.Conn = raw
	if run.Protocol == "tcp" {
		trust := run.ServiceTLS.Clone()
		trust.ServerName = run.Endpoint.Hostname
		trust.MinVersion = max(trust.MinVersion, tls.VersionTLS12)
		secured := tls.Client(raw, trust)
		if err := secured.HandshakeContext(setup); err != nil {
			return nil, failure.Wrap("prepare connector visitor TLS", failure.ConnectionTLSRejected, err)
		}
		connection = secured
	}
	if ctx.Err() != nil || !run.ValidUntil.After(time.Now()) {
		return nil, ErrServiceConnection
	}
	if err := raw.SetDeadline(time.Time{}); err != nil {
		return nil, err
	}
	// clearing a transport deadline may race with timeout cleanup. promotion
	// requires both the original budget and exclusive ownership of that cleanup.
	if setup.Err() != nil || !time.Now().Before(deadline) || !stopSetup() {
		return nil, ErrServiceConnection
	}
	setupStopped = true
	p := &PreparedConnector{ctx: ctx, conn: connection, stdio: selected, stream: streamPrepared{}, permission: permissionUsable{}, callbackDone: make(chan struct{}), permissionUntil: run.ValidUntil}
	p.stop = context.AfterFunc(ctx, func() { defer close(p.callbackDone); _ = p.closePhysical() })
	p.mu.Lock()
	p.startPermissionWorkerLocked()
	p.mu.Unlock()
	owned = true
	return p, nil
}

func (p *PreparedConnector) closePhysical() error {
	p.physicalOnce.Do(func() { p.physicalErr = p.conn.Close() })
	return p.physicalErr
}

func (p *PreparedConnector) finish() {
	p.closeOnce.Do(func() {
		p.mu.Lock()
		p.stream = streamClosed{}
		if pending := p.permissionWaitLocked(); pending != nil {
			close(pending)
			p.permission = permissionUsable{}
		}
		if p.permissionCancel != nil {
			p.permissionCancel(p.permissionStop)
		}
		p.mu.Unlock()
		p.closeErr = p.closePhysical()
		if !p.stop() {
			<-p.callbackDone
		}
	})
}

// one worker and one replaceable pending proof belong to this prepared visitor.
// a future-policy ACK wait cannot delay the owner's next refresh or its siblings.
func (p *PreparedConnector) queuePermission(renewal preparedPermissionRenewal) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closedLocked() || p.ctx.Err() != nil || p.permissionDeniedLocked() || !p.permissionUntil.IsZero() && !p.permissionUntil.After(time.Now()) {
		return ErrServiceConnection
	}
	if p.permissionWaitLocked() == nil {
		p.permission = permissionQueued{wait: make(chan struct{})}
	}
	p.startPermissionWorkerLocked()
	select {
	case p.permissionUpdates <- renewal:
	default:
		// immutable newer authority replaces only queued work, never the proof
		// currently awaiting its publisher decision or that decision's fence.
		select {
		case <-p.permissionUpdates:
		default:
		}
		p.permissionUpdates <- renewal
	}
	return nil
}

func (p *PreparedConnector) startPermissionWorkerLocked() {
	if p.permissionUpdates != nil {
		return
	}
	ctx, cancel := context.WithCancelCause(p.ctx)
	p.permissionCancel = cancel
	p.permissionStop = &preparedPermissionStop{owner: p}
	p.permissionUpdates = make(chan preparedPermissionRenewal, 1)
	p.work.Add(1)
	go p.renewPermissions(ctx, p.permissionUpdates)
}

func (p *PreparedConnector) suspendPermission() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closedLocked() || p.ctx.Err() != nil || p.permissionDeniedLocked() || !p.permissionUntil.IsZero() && !p.permissionUntil.After(time.Now()) {
		return ErrServiceConnection
	}
	if p.permissionWaitLocked() == nil {
		p.permission = permissionQueued{wait: make(chan struct{})}
	}
	p.startPermissionWorkerLocked()
	return nil
}

func (p *PreparedConnector) renewPermissions(ctx context.Context, updates <-chan preparedPermissionRenewal) {
	defer p.work.Done()
	for {
		p.mu.Lock()
		until := p.permissionUntil
		p.mu.Unlock()
		wait, stopWait := context.WithCancel(ctx)
		if !until.IsZero() {
			stopWait()
			wait, stopWait = context.WithDeadline(ctx, until)
		}
		select {
		case <-wait.Done():
			if cause := context.Cause(wait); cause != p.permissionStop {
				p.mu.Lock()
				p.permissionErr = cause
				p.mu.Unlock()
			}
			stopWait()
			p.finish()
			return
		case renewal := <-updates:
			stopWait()
			// the writer owns the short exchange budget so a staged packet binding
			// can pause delivery without borrowing the unacknowledged new authority.
			bound := renewal.until
			if !until.IsZero() {
				bound = earliestConnectorDeadline(bound, until)
			}
			call, cancel := context.WithDeadline(ctx, bound)
			err := p.renewPermission(call, func() error { return renewal.writer.Renew(call, renewal.update) }, renewal.until)
			cancel()
			if errors.Is(err, tunnel.ErrConnectorPermissionStale) {
				continue // keep the write fence until a fresh binding proof is ACKed.
			}
			if err != nil {
				p.mu.Lock()
				if err != p.permissionStop || context.Cause(ctx) != p.permissionStop {
					p.permissionErr = err
				}
				p.mu.Unlock()
				p.finish() // the owner joins this worker; it never joins itself.
				return
			}
		}
	}
}

func (p *PreparedConnector) Close() error {
	if p == nil {
		return nil
	}
	p.finish()
	p.work.Wait()
	p.mu.Lock()
	permissionErr := p.permissionErr
	p.mu.Unlock()
	return errors.Join(p.closeErr, permissionErr)
}

// renewPermission fences only new writes for this visitor until the publisher
// acknowledges its signed update. an already-entered write never delays control
// renewal. denial leaves a permanent fence before any waiting write is released.
func (p *PreparedConnector) renewPermission(ctx context.Context, renew func() error, nextUntil time.Time) error {
	p.mu.Lock()
	if cause := context.Cause(ctx); cause != nil {
		p.mu.Unlock()
		return cause
	}
	if p.closedLocked() || p.ctx.Err() != nil || p.permissionDeniedLocked() {
		p.mu.Unlock()
		return ErrServiceConnection
	}
	if _, renewing := p.permission.(permissionRenewing); renewing {
		p.mu.Unlock()
		return ErrServiceConnection
	}
	pending := p.permissionWaitLocked()
	if pending == nil {
		pending = make(chan struct{})
	}
	p.permission = permissionRenewing{wait: pending}
	p.mu.Unlock()
	err := renew()
	p.mu.Lock()
	if err == nil && !p.permissionUntil.IsZero() && !p.permissionUntil.After(time.Now()) {
		err = context.DeadlineExceeded
	}
	if err == nil {
		if !nextUntil.After(time.Now()) {
			err = context.DeadlineExceeded
		} else {
			p.permissionUntil = nextUntil
		}
	}
	stale := errors.Is(err, tunnel.ErrConnectorPermissionStale)
	if p.closedLocked() {
		// finish already released this waiter's channel.
		p.permission = permissionUsable{}
	} else if stale {
		// a replaced binding is not a denial. retain the same write fence
		// until a proof for the current binding is acknowledged.
		p.permission = permissionQueued{wait: pending}
	} else if err != nil {
		p.permission = permissionDenied{}
		close(pending)
	} else if len(p.permissionUpdates) == 0 {
		p.permission = permissionUsable{}
		close(pending)
	} else {
		p.permission = permissionQueued{wait: pending}
	}
	p.mu.Unlock()
	return err
}

func (p *PreparedConnector) waitPermission(ctx context.Context) error {
	for {
		p.mu.Lock()
		pending := p.permissionWaitLocked()
		invalid := p.closedLocked() || p.ctx.Err() != nil || ctx.Err() != nil || p.permissionDeniedLocked() || !p.permissionUntil.IsZero() && !p.permissionUntil.After(time.Now())
		p.mu.Unlock()
		if invalid {
			return ErrServiceConnection
		}
		if pending == nil {
			return nil
		}
		select {
		case <-pending:
		case <-ctx.Done():
			return context.Cause(ctx)
		case <-p.ctx.Done():
			return context.Cause(p.ctx)
		}
	}
}

// Forward consumes this one prepared stream and joins both copy directions.
// failure is final; the session's siblings and packet endpoint remain owned by
// their existing owner, not by this local connection.
func (p *PreparedConnector) Forward(ctx context.Context, local net.Conn) (result error) {
	if p == nil || local == nil {
		return ErrServiceConnection
	}
	p.mu.Lock()
	if _, prepared := p.stream.(streamPrepared); !prepared || p.ctx.Err() != nil || ctx.Err() != nil {
		p.mu.Unlock()
		return ErrServiceConnection
	}
	p.stream = streamForwarding{}
	p.work.Add(1)
	p.mu.Unlock()
	defer p.work.Done()
	life, cancel := context.WithCancel(ctx)
	ownerDone := make(chan struct{})
	stopOwner := context.AfterFunc(p.ctx, func() { defer close(ownerDone); cancel() })
	defer func() {
		cancel()
		if !stopOwner() {
			<-ownerDone
		}
	}()
	closed := make(chan struct{})
	stop := context.AfterFunc(life, func() { defer close(closed); _ = local.Close(); _ = p.closePhysical() })
	defer func() {
		if !stop() {
			<-closed
		}
	}()
	defer local.Close()
	defer func() { p.finish(); result = errors.Join(result, p.closeErr) }()
	_, err := streamcopy.Copy(local, &preparedConnectorUse{owner: p, ctx: life})
	return err
}

var _ interface{ Close() error } = (*PreparedConnector)(nil)

// the existing prepared owner is the dispatch fence too. no separate stamp or
// policy mirror is needed, and optimized io.Copy methods cannot escape it.
type preparedConnectorUse struct {
	owner *PreparedConnector
	ctx   context.Context
}

func (c *preparedConnectorUse) current() error {
	c.owner.mu.Lock()
	defer c.owner.mu.Unlock()
	// the first copy worker closed this prepared stream after the selected
	// stdio reset. its sibling can observe that local close before its read
	// returns the reset; tag only this close, not an unrelated permission loss.
	if c.owner.stdioClosedOnAbort && c.owner.closedLocked() && c.owner.ctx.Err() == nil && c.ctx.Err() == nil && !c.owner.permissionDeniedLocked() && (c.owner.permissionUntil.IsZero() || c.owner.permissionUntil.After(time.Now())) {
		return &stdioPreparedAbortError{owner: c.owner.stdio.owner, stream: c.owner.stdio}
	}
	if c.owner.closedLocked() || c.owner.ctx.Err() != nil || c.ctx.Err() != nil || c.owner.permissionDeniedLocked() || !c.owner.permissionUntil.IsZero() && !c.owner.permissionUntil.After(time.Now()) {
		return ErrServiceConnection
	}
	return nil
}
func (c *preparedConnectorUse) Read(p []byte) (int, error) {
	if err := c.current(); err != nil {
		return 0, err
	}
	n, err := c.owner.conn.Read(p)
	if n > 0 {
		if current := c.current(); current != nil {
			return 0, current
		}
	}
	return n, err
}
func (c *preparedConnectorUse) Write(p []byte) (int, error) {
	if err := c.owner.waitPermission(c.ctx); err != nil {
		return 0, err
	}
	return c.owner.conn.Write(p)
}
func (c *preparedConnectorUse) CloseWrite() error {
	if err := c.owner.waitPermission(c.ctx); err != nil {
		return err
	}
	if writer, ok := c.owner.conn.(interface{ CloseWrite() error }); ok {
		return writer.CloseWrite()
	}
	return errors.ErrUnsupported
}
func (c *preparedConnectorUse) Close() error {
	c.owner.mu.Lock()
	if selected := c.owner.stdio; selected != nil && !c.owner.closedLocked() {
		o := selected.owner
		o.mu.Lock()
		c.owner.stdioClosedOnAbort = o.expected && o.resetStarted && o.selected == selected
		o.mu.Unlock()
	}
	c.owner.stream = streamClosed{}
	c.owner.mu.Unlock()
	return c.owner.closePhysical()
}
func (c *preparedConnectorUse) LocalAddr() net.Addr            { return c.owner.conn.LocalAddr() }
func (c *preparedConnectorUse) RemoteAddr() net.Addr           { return c.owner.conn.RemoteAddr() }
func (c *preparedConnectorUse) SetDeadline(at time.Time) error { return c.owner.conn.SetDeadline(at) }
func (c *preparedConnectorUse) SetReadDeadline(at time.Time) error {
	return c.owner.conn.SetReadDeadline(at)
}
func (c *preparedConnectorUse) SetWriteDeadline(at time.Time) error {
	return c.owner.conn.SetWriteDeadline(at)
}

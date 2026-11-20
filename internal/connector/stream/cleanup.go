package stream

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"net/http"
	"sync"
	"time"

	clientcontrol "github.com/tnldotdev/tnl/internal/client/control"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/observability"
	"github.com/tnldotdev/tnl/internal/transport/tunnel"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

// this result comes only from an exact, decoded relay renewal denial without an
// independent transport/cleanup error. it remains a serving failure after join.
type connectorReceivedLegDenial struct {
	owner *connectorConnection
	err   error
}

func (e *connectorReceivedLegDenial) Error() string { return e.err.Error() }
func (e *connectorReceivedLegDenial) Unwrap() error { return e.err }

// a current authority decision fences new terminal work as well as serving.
// it cannot complete an exchange that entered earlier or erase its failure.
func (p *connectorConnection) denyTerminalAuthority(err error) {
	p.mu.Lock()
	p.terminalDenied = errors.Join(p.terminalDenied, err)
	p.mu.Unlock()
}

func (p *connectorConnection) observeControlDenial(err error) {
	var problem *clientcontrol.ProblemError
	if errors.As(err, &problem) && problem != nil &&
		(problem.Status == http.StatusUnauthorized && problem.Problem.Code == controlv1.Unauthenticated ||
			problem.Status == http.StatusForbidden && problem.Problem.Code == controlv1.Forbidden) {
		p.denyTerminalAuthority(err)
	}
}

// the existing connection and adapter share one first-stop cleanup budget.
type connectorCleanup struct {
	mu        sync.Mutex
	caller    context.Context
	base      context.Context
	source    func() context.Context
	authority time.Time
	until     time.Time
	ctx       context.Context
	cancel    context.CancelFunc
}

func newConnectorCleanup(ctx context.Context, source func() context.Context) *connectorCleanup {
	return &connectorCleanup{caller: ctx, base: observability.Independent(context.WithoutCancel(ctx)), source: source}
}

func (c *connectorCleanup) observe(until time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.until.IsZero() {
		c.authority = until
	}
}

func (c *connectorCleanup) begin() {
	c.beginAt(time.Now())
}

func (c *connectorCleanup) beginAt(at time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.until.IsZero() {
		c.until = at.Add(5 * time.Second)
		// signed retirement is negative work with retained proof, not another
		// serving operation. retain the actual caller deadline, not the expired
		// authority horizon; bound still fences packet/terminal work by authority.
		if parent, ok := c.caller.Deadline(); ok {
			c.until = earliestConnectorDeadline(c.until, parent)
		}
		// borrowed cleanup belongs to its composing owner. only a standalone
		// connector hands its stop budget to the final process flush.
		if c.source == nil {
			c.until = observability.ShutdownDeadline(c.caller, c.until)
		}
	}
}

func (c *connectorCleanup) context() context.Context {
	c.begin()
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.ctx == nil {
		parent := c.base
		if c.source != nil {
			parent = c.source()
		}
		c.ctx, c.cancel = context.WithDeadline(parent, c.until)
	}
	return c.ctx
}

func (c *connectorCleanup) bound(until time.Time) time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.authority.IsZero() {
		until = earliestConnectorDeadline(until, c.authority)
	}
	if c.ctx != nil {
		deadline, _ := c.ctx.Deadline()
		return earliestConnectorDeadline(until, deadline)
	}
	if !c.until.IsZero() {
		return earliestConnectorDeadline(until, c.until)
	}
	return until
}

func (c *connectorCleanup) close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.cancel != nil {
		c.cancel()
	}
}

func (p *connectorConnection) captureRetirement(pair controlv1.ConnectorPeerPair) error {
	key, err := connectorPairSecret(pair.SessionKey)
	if err != nil {
		return err
	}
	// validate scope through the defining adapter, without issuing a timestamped
	// request that could expire while the owner is still serving.
	body := controlv1.ConnectorPeerPairRetireRequest{
		ServiceRunId: pair.ServiceRunId, RunNumber: pair.RunNumber, PublisherIdentityId: pair.PublisherIdentityId,
		DeliveryId: pair.DeliveryId, IdempotencyKey: p.owner, RequestedAt: time.Now().UTC().Truncate(time.Microsecond),
	}
	if _, err := controlv1.ConnectorPeerPairRetireProof(pair.ServiceId, pair.PairId, body); err != nil {
		return err
	}
	p.retirement = &connectorRetirement{pair: pair, key: key, signer: p.signer}
	return nil
}

type connectorRetirement struct {
	pair   controlv1.ConnectorPeerPair
	key    [32]byte
	signer Signer
}

// only the authority watcher produces this stop for its exact connection.
// consumers can distinguish its idle children from independent operation errors.
type connectorAuthorityExpiry struct {
	owner *connectorConnection
	until time.Time
}

func (e *connectorAuthorityExpiry) Error() string {
	return "connector authority expired: " + ErrServiceConnection.Error()
}
func (*connectorAuthorityExpiry) Unwrap() error { return ErrServiceConnection }

func (*connectorRetirement) String() string   { return "private connector retirement" }
func (*connectorRetirement) GoString() string { return "private connector retirement" }

func (r *connectorRetirement) retire(ctx context.Context, control Control, owner string) error {
	if err := context.Cause(ctx); err != nil {
		return err
	}
	body := controlv1.ConnectorPeerPairRetireRequest{
		ServiceRunId: r.pair.ServiceRunId, RunNumber: r.pair.RunNumber, PublisherIdentityId: r.pair.PublisherIdentityId,
		DeliveryId: r.pair.DeliveryId, IdempotencyKey: owner, RequestedAt: time.Now().UTC().Truncate(time.Microsecond),
	}
	proof, err := controlv1.ConnectorPeerPairRetireProof(r.pair.ServiceId, r.pair.PairId, body)
	if err != nil {
		return err
	}
	mac, err := proof.SessionProof(r.key[:])
	if err != nil {
		return err
	}
	message, err := proof.Message(mac)
	if err != nil {
		return err
	}
	signature := r.signer.Sign(message)
	if err := proof.VerifySignature(ed25519.PublicKey(r.signer.PublicKey), mac, signature); err != nil {
		return err
	}
	body.SessionProof, body.Signature = base64.RawURLEncoding.EncodeToString(mac), base64.RawURLEncoding.EncodeToString(signature)
	if err := context.Cause(ctx); err != nil {
		return err
	}
	receipt, err := requestConnectorPair(ctx, func() (controlv1.ConnectorPeerPairRetirement, error) {
		return control.RetireConnectorPeerPair(ctx, r.pair.ServiceId, r.pair.PairId, body)
	})
	if err != nil {
		return err
	}
	return receipt.ValidateFor(r.pair.ServiceId, r.pair.PairId, body)
}

func connectorTerminalKey(entry tunnelv1.ConnectorPeerVisitorEntry) tunnelv1.ConnectorVisitorTerminalKey {
	return tunnelv1.ConnectorVisitorTerminalKey{VisitorConnectionID: entry.VisitorConnectionID, DeliveryGeneration: entry.DeliveryGeneration}
}

func (p *connectorConnection) terminalUse(use *connectorUse, operation error) (result error) {
	defer func() {
		if use.prepared != nil {
			cleanupErr := p.preparedRetirementResult(use.prepared, use.prepared.releaseTerminal())
			p.recordUseCleanup(cleanupErr)
			result = errors.Join(result, cleanupErr)
		}
	}()
	if !use.admitted || p.permissions == nil {
		return operation
	}
	p.mu.Lock()
	denied := p.terminalDenied
	if denied != nil {
		p.mu.Unlock()
		// no exchange entered under this denied authority. retain the visitor's
		// operation and require signed retirement under the negative-work budget.
		if operation != nil {
			return operation
		}
		return errors.Join(ErrServiceConnection, denied)
	}
	// a stopped coordinator cannot reactivate its suspended packet binding.
	// report that unavailable exchange now, leaving the original cleanup budget
	// for authenticated retirement rather than waiting on an impossible reply.
	unavailable := p.ctx.Err() != nil && p.recoveryState == connectorRebinding
	until := earliestConnectorDeadline(time.Now().Add(5*time.Second), p.until, p.run.ValidUntil)
	if !p.permission.ExpiresAt.IsZero() {
		until = earliestConnectorDeadline(until, p.permission.ExpiresAt)
	}
	p.mu.Unlock()
	if use.prepared != nil {
		use.prepared.mu.Lock()
		until = earliestConnectorDeadline(until, use.prepared.permissionUntil)
		selected := use.prepared.stdio
		use.prepared.mu.Unlock()
		if selected != nil {
			until = selected.owner.cleanupBound(until)
		}
	} else {
		until = earliestConnectorDeadline(until, use.until)
	}
	if !until.After(time.Now()) {
		// no terminal exchange has entered: this admission no longer grants
		// terminal authority. retain the visitor's failure, then require signed
		// pair retirement and local joins under the separate stop budget.
		if operation == nil {
			return ErrServiceConnection
		}
		return operation
	}
	if unavailable {
		p.recordUseCleanup(ErrServiceConnection)
		return errors.Join(operation, ErrServiceConnection)
	}
	until = p.cleanup.bound(until)
	ctx, finish := context.WithDeadline(p.packetCtx, until)
	defer finish()
	var err error
	var exchange tunnel.ConnectorTerminalExchange
	if operation == nil {
		exchange, err = p.permissions.Complete(ctx, use.terminalKey)
	} else {
		exchange, err = p.permissions.Abort(ctx, use.terminalKey)
	}
	if p.ctx.Err() != nil {
		p.recordTerminalCleanup(exchange, err)
	}
	return errors.Join(operation, err)
}

func (p *connectorConnection) closePreparedForRetirement(prepared *PreparedConnector) error {
	return p.preparedRetirementResult(prepared, prepared.Close())
}

func (p *connectorConnection) preparedRetirementResult(prepared *PreparedConnector, result error) error {
	p.mu.Lock()
	now := time.Now()
	expired := !p.until.After(now) || !p.run.ValidUntil.After(now) || !p.permission.ExpiresAt.After(now)
	p.mu.Unlock()
	prepared.mu.Lock()
	defer prepared.mu.Unlock()
	// the permission worker was idle when this exact pair owner stopped. keep
	// its serving cause for direct callers, but require only physical cleanup
	// here. neither joined results nor an entered renewal get this provenance.
	if stopped, ok := prepared.permissionErr.(*preparedPermissionOwnerStop); ok && stopped != nil &&
		stopped.owner == prepared && stopped.lifetime == p.ctx && prepared.ctx == p.ctx && p.ctx.Err() != nil {
		return errors.Join(prepared.closeErr, prepared.physicalErr)
	}
	if !expired {
		return result
	}
	// Close still exposes expiry to its direct caller. only pair-owner
	// retirement distinguishes this exact idle stop from failed cleanup.
	// never inspect the physical error tree or an entered renewal's result.
	if cause, ok := prepared.permissionErr.(*preparedPermissionExpiry); ok &&
		cause.owner == prepared && cause.until.Equal(prepared.permissionUntil) {
		if cause.cause == nil && !cause.until.After(now) {
			return errors.Join(prepared.closeErr, prepared.physicalErr)
		}
		// a refreshed pair can expire before this visitor's last acknowledged
		// permission. the idle worker stopped on the pair's fence, not its timer.
		if authority, ok := cause.cause.(*connectorAuthorityExpiry); ok &&
			prepared.ctx == p.ctx && authority.owner == p && authority == context.Cause(p.ctx) && !authority.until.After(now) {
			return errors.Join(prepared.closeErr, prepared.physicalErr)
		}
	}
	return result
}

func (p *connectorConnection) recordTerminalCleanup(exchange tunnel.ConnectorTerminalExchange, err error) {
	// a fully observed remote failure belongs to this visitor's result, which
	// terminalUse still returns. it is not a failed owner cleanup operation.
	if exchange.Matched && exchange.ObservedWritten && exchange.Result.Outcome == tunnelv1.ConnectorTerminalFailed &&
		failure.Only(err, tunnel.ErrConnectorTerminalFailed) {
		return
	}
	p.recordUseCleanup(err)
}

func (p *connectorConnection) recordUseCleanup(err error) {
	if err == nil || failure.Only(err, context.Canceled) {
		return
	}
	p.mu.Lock()
	p.useErr = errors.Join(p.useErr, err)
	p.mu.Unlock()
}

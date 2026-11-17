package stream

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"sync"
	"time"

	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/observability"
	"github.com/tnldotdev/tnl/internal/transport/tunnel"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

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
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.until.IsZero() {
		c.until = time.Now().Add(5 * time.Second)
		if !c.authority.IsZero() {
			c.until = earliestConnectorDeadline(c.until, c.authority)
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

func (p *connectorConnection) terminalUse(use *connectorUse, operation error) error {
	if !use.admitted || p.permissions == nil {
		return operation
	}
	p.mu.Lock()
	// a stopped coordinator cannot reactivate its suspended packet binding.
	// report that unavailable exchange now, leaving the original cleanup budget
	// for authenticated retirement rather than waiting on an impossible reply.
	unavailable := p.ctx.Err() != nil && p.recoveryState == connectorRebinding
	until := earliestConnectorDeadline(time.Now().Add(5*time.Second), p.until, p.run.ValidUntil)
	if !p.permission.ExpiresAt.IsZero() {
		until = earliestConnectorDeadline(until, p.permission.ExpiresAt)
	}
	p.mu.Unlock()
	if unavailable {
		p.recordUseCleanup(ErrServiceConnection)
		return errors.Join(operation, ErrServiceConnection)
	}
	if use.prepared != nil {
		use.prepared.mu.Lock()
		until = earliestConnectorDeadline(until, use.prepared.permissionUntil)
		use.prepared.mu.Unlock()
	} else {
		until = earliestConnectorDeadline(until, use.until)
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

package stream

import (
	"context"
	"crypto/rand"
	"errors"
	"net/http"
	"sync"
	"time"

	clienttelemetry "github.com/tnldotdev/tnl/internal/client/telemetry"
	telemetryv1 "github.com/tnldotdev/tnl/pkg/api/integrations/telemetry/v1"

	clientcontrol "github.com/tnldotdev/tnl/internal/client/control"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/transport/peer"
	"github.com/tnldotdev/tnl/internal/transport/tunnel"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

type connectorRebindPhase struct {
	request controlv1.ConnectorPeerPairRebindRequest
	started time.Time
}

// inspection permits traffic on the current binding; rebinding fences it until
// the coordinator installs a newer authorized binding. only recovery can advance
// either state back to ready.
type connectorRecoveryState uint8

const (
	connectorBindingReady connectorRecoveryState = iota
	connectorInspecting
	connectorRebinding
)

// only the recovery coordinator mutates phase requests or pending legs. the
// retained connection still owns authority, application uses, and inner QUIC.
type connectorRebindOperation struct {
	prepare, activate, abort *connectorRebindPhase
	pair                     controlv1.ConnectorPeerPair
	until                    time.Time
	initial                  [2]tunnelv1.ConnectorHandoffID
	legs                     [2]*connectorRelayLeg
	installed                [2]bool
	activated                [2]bool
	staged, retired          bool
}

func connectorBindingRevision(pair controlv1.ConnectorPeerPair) peer.BindingRevision {
	return peer.BindingRevision{PairID: pair.PairId, Generation: pair.DeliveryGeneration, OperationID: pair.OperationId, Challenge: pair.BindingChallenge}
}

func connectorTerminalProtocol(err error) bool {
	var protocol *tunnel.ProtocolError
	return errors.As(err, &protocol) && connectorReconnectError(err) == terminateConnection
}

func connectorPhaseConflict(err error) bool {
	var problem *clientcontrol.ProblemError
	return errors.As(err, &problem) && problem.Status == http.StatusConflict && problem.Problem.Code == controlv1.Conflict && connectorBindingChanged(err)
}

func connectorBindingChanged(err error) bool {
	changed, denied := false, false
	var visit func(error)
	visit = func(cause error) {
		if problem, ok := cause.(*clientcontrol.ProblemError); ok {
			changed = changed || problem.Status == http.StatusConflict && (problem.Problem.Code == controlv1.Conflict || problem.Problem.Code == controlv1.StaleNetworkBinding)
			denied = denied || problem.Status == http.StatusUnauthorized || problem.Status == http.StatusForbidden
		}
		if protocol, ok := cause.(*tunnel.ProtocolError); ok {
			denied = denied || connectorReconnectError(protocol) == terminateConnection
		}
		switch wrapped := cause.(type) {
		case interface{ Unwrap() []error }:
			for _, child := range wrapped.Unwrap() {
				visit(child)
			}
		case interface{ Unwrap() error }:
			visit(wrapped.Unwrap())
		}
	}
	visit(err)
	return changed && !denied
}

func connectorRecoveryWait(cause error) error {
	return errors.Join(&tunnel.ProtocolError{Code: tunnelv1.Unavailable}, cause)
}

func (p *connectorConnection) requestRecovery(next connectorRecoveryState) {
	p.mu.Lock()
	if next <= p.recoveryState {
		p.mu.Unlock()
		return
	}
	p.recoveryState = next
	if next == connectorRebinding && p.recoveryStarted.IsZero() {
		p.recoveryStarted = time.Now()
	}
	if next == connectorRebinding {
		p.openings = nil
		if p.connectivity != nil {
			p.connectivity.Suspend()
		}
	}
	until, stop := p.until, p.bindingCancel
	active := make([]*PreparedConnector, 0, len(p.active))
	if next == connectorRebinding {
		for use := range p.active {
			if use.prepared != nil {
				active = append(active, use.prepared)
			}
		}
	}
	p.notifyLocked()
	p.mu.Unlock()
	if next == connectorRebinding {
		if stop != nil {
			stop()
		}
		if p.permissions != nil {
			if err := p.permissions.Suspend(until); err != nil {
				p.cancel(err)
				return
			}
		}
		for _, prepared := range active {
			if err := prepared.suspendPermission(); err != nil {
				_ = prepared.Close()
			}
		}
		if p.endpoint != nil {
			p.endpoint.SuspendBinding()
		}
	}
	select {
	case p.recover <- struct{}{}:
	default:
	}
}

func (p *connectorConnection) newRebindPhase(phase controlv1.ConnectorPeerPairRebindPhase, operation string, generation int64, relays []controlv1.ConnectorPeerPairRelay, challenge string, proofs []controlv1.ConnectorPeerPairPathProof) (*connectorRebindPhase, error) {
	p.mu.Lock()
	run, pair := p.run, p.pair
	current := p.ownerCurrentLocked()
	p.mu.Unlock()
	if !current {
		return nil, ErrServiceConnection
	}
	started := time.Now()
	request, err := connectorRebindRequest(p.signer, run, pair, p.owner, phase, operation, generation, relays, challenge, proofs)
	return &connectorRebindPhase{request: request, started: started}, err
}

func (p *connectorConnection) callRebind(phase *connectorRebindPhase) (controlv1.ConnectorPeerPairRebindState, time.Time, error) {
	p.mu.Lock()
	run, original, until, highWater := p.run, p.pair, p.until, p.highWater
	current := p.ownerCurrentLocked()
	p.mu.Unlock()
	if !current {
		return controlv1.ConnectorPeerPairRebindState{}, time.Time{}, ErrServiceConnection
	}
	call, stop := context.WithDeadline(p.ctx, minConnectorCall(until))
	defer stop()
	state, err := p.config.Control.RebindConnectorPeerPair(call, run.ServiceID, original.PairId, phase.request)
	if err != nil {
		return state, time.Time{}, err
	}
	pendingUntil, err := validateConnectorRebindState(call, p.signer, run, original, phase.request, state, phase.started, highWater)
	if err != nil {
		return state, time.Time{}, err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.ownerCurrentLocked() {
		return state, time.Time{}, ErrServiceConnection
	}
	p.highWater = state.HighWaterGeneration
	return state, pendingUntil, nil
}

func (p *connectorConnection) inspectBinding() (controlv1.ConnectorPeerPairRebindState, time.Time, error) {
	if p.inspection == nil {
		phase, err := p.newRebindPhase(controlv1.ConnectorPeerPairInspect, "", p.highWater, nil, "", nil)
		if err != nil {
			return controlv1.ConnectorPeerPairRebindState{}, time.Time{}, err
		}
		p.inspection = phase
	}
	state, until, err := p.callRebind(p.inspection)
	if err == nil {
		p.inspection = nil
	}
	return state, until, err
}

func (p *connectorConnection) retirePending(op *connectorRebindOperation) {
	if op.retired {
		return
	}
	op.retired = true
	p.endpoint.SuspendBinding()
	for slot, leg := range op.legs {
		_ = p.paths[slot].carrier.Install(nil)
		if leg != nil {
			_ = leg.Close()
			op.legs[slot] = nil
		}
	}
}

func (p *connectorConnection) abandonPending(op *connectorRebindOperation) error {
	p.retirePending(op)
	state, _, err := p.inspectBinding()
	if err != nil {
		return err
	}
	if state.Operation == nil || state.Operation.OperationId != op.prepare.request.OperationId {
		return ErrServiceConnection
	}
	if state.Operation.Status == controlv1.ConnectorPeerPairOperationPending {
		if op.abort == nil {
			op.abort, err = p.newRebindPhase(controlv1.ConnectorPeerPairAbort, state.Operation.OperationId, state.Operation.DeliveryGeneration, nil, "", nil)
			if err != nil {
				return err
			}
		}
		state, _, err = p.callRebind(op.abort)
		if err != nil {
			if connectorPhaseConflict(err) {
				return connectorRecoveryWait(err)
			}
			return err
		}
	}
	if state.Pending != nil || state.Active == nil {
		return ErrServiceConnection
	}
	// a lost activation reply may already have committed. retain that authority
	// projection for the next CAS, never resume this locally expired binding.
	p.mu.Lock()
	p.pair = *state.Active
	p.run.PairReady = &controlv1.ConnectorPeerPairReady{PublisherIdentityId: p.pair.PublisherIdentityId, Relays: p.pair.Relays}
	p.rebind = nil
	p.recoveryState = connectorRebinding
	p.notifyLocked()
	p.mu.Unlock()
	return connectorRecoveryWait(nil)
}

func (p *connectorConnection) recoverBinding() error {
	p.mu.Lock()
	recovery := p.recoveryState
	op := p.rebind
	current := p.ownerCurrentLocked()
	p.mu.Unlock()
	if !current {
		return ErrServiceConnection
	}
	if recovery == connectorBindingReady {
		return nil
	}
	if op == nil {
		state, _, err := p.inspectBinding()
		if err != nil {
			return err
		}
		if state.Active == nil || state.Pending != nil {
			return ErrServiceConnection
		}
		p.mu.Lock()
		unchanged := p.recoveryState == connectorInspecting && state.Active.DeliveryGeneration == p.pair.DeliveryGeneration && state.Active.BindingState == controlv1.ConnectorPeerPairBindingActive &&
			len(state.ReadyRelays) == 2 && state.ReadyRelays[0] == p.pair.Relays[0] && state.ReadyRelays[1] == p.pair.Relays[1] && state.Active.SourceIp != nil && *state.Active.SourceIp == p.source
		if unchanged {
			p.recoveryState = connectorBindingReady
			for slot := range p.paths {
				if p.paths[slot].needsInspection {
					p.paths[slot].inspected, p.paths[slot].needsInspection = true, false
				}
			}
			p.notifyLocked()
		}
		p.mu.Unlock()
		if unchanged {
			return nil
		}
		p.requestRecovery(connectorRebinding)
		if len(state.ReadyRelays) != 2 {
			return connectorRecoveryWait(nil)
		}
		operation, err := opaqueid.New(opaqueid.IdempotencyPrefix)
		if err != nil {
			return err
		}
		prepare, err := p.newRebindPhase(controlv1.ConnectorPeerPairPrepare, operation, state.HighWaterGeneration, state.ReadyRelays, "", nil)
		if err != nil {
			return err
		}
		op = &connectorRebindOperation{prepare: prepare}
		for slot := range op.initial {
			if _, err := rand.Read(op.initial[slot][:]); err != nil {
				return err
			}
		}
		p.mu.Lock()
		p.rebind = op
		p.mu.Unlock()
	}
	if op.retired || !op.until.IsZero() && !op.until.After(time.Now()) {
		return p.abandonPending(op)
	}
	if op.pair.PairId == "" {
		state, until, err := p.callRebind(op.prepare)
		if err != nil {
			if connectorBindingChanged(err) {
				return p.reconcileRebind(op)
			}
			return err
		}
		if state.Pending == nil || state.Operation == nil || state.Operation.Status != controlv1.ConnectorPeerPairOperationPending {
			return p.abandonPending(op)
		}
		op.pair, op.until = *state.Pending, until
	}
	if !op.staged {
		// no new leg worker can enter after requestRecovery cancels this binding.
		p.legUses.Wait()
		for _, path := range p.paths {
			if path.leg != nil {
				_ = path.leg.Close()
			}
		}
		if err := p.endpoint.StageBinding(connectorBindingRevision(op.pair)); err != nil {
			return err
		}
		op.staged = true
	}
	if err := p.connectPendingLegs(op); err != nil {
		return err
	}
	proofs, ready := p.endpoint.BindingProofs(connectorBindingRevision(op.pair))
	if !ready {
		return connectorRecoveryWait(nil)
	}
	if op.activate == nil {
		state, _, err := p.inspectBinding()
		if err != nil {
			return err
		}
		if state.Pending == nil || state.Pending.OperationId != op.pair.OperationId {
			return p.abandonPending(op)
		}
		if state.Pending.PublisherPreparedUntil == nil || state.Pending.PublisherProvedUntil == nil || !state.Pending.PublisherProvedUntil.After(state.Pending.ObservedAt) {
			return connectorRecoveryWait(nil)
		}
		wire := make([]controlv1.ConnectorPeerPairPathProof, 0, len(proofs))
		for _, proof := range proofs {
			wire = append(wire, controlv1.ConnectorPeerPairPathProof{ConnectionSlot: proof.ConnectionSlot, ProbeNonce: proof.ProbeNonce, ReplyFrame: proof.ReplyFrame})
		}
		op.activate, err = p.newRebindPhase(controlv1.ConnectorPeerPairActivate, op.pair.OperationId, op.pair.DeliveryGeneration, nil, op.pair.BindingChallenge, wire)
		if err != nil {
			return err
		}
	}
	state, _, err := p.callRebind(op.activate)
	if err != nil {
		if connectorBindingChanged(err) {
			return p.reconcileRebind(op)
		}
		return err
	}
	return p.installActiveBinding(op, state)
}

// a signed phase can lose its assignment race without losing owner authority.
// inspect before choosing another operation; uncertain transport errors instead
// keep retrying the exact phase so a late commit cannot be overtaken.
func (p *connectorConnection) reconcileRebind(op *connectorRebindOperation) error {
	state, until, err := p.inspectBinding()
	if err != nil {
		return err
	}
	if state.Operation == nil || state.Operation.OperationId != op.prepare.request.OperationId {
		if state.Pending != nil || state.HighWaterGeneration != op.prepare.request.ExpectedGeneration || op.staged {
			return ErrServiceConnection
		}
		p.mu.Lock()
		p.rebind = nil
		p.notifyLocked()
		p.mu.Unlock()
		return connectorRecoveryWait(nil)
	}
	if state.Pending == nil {
		return p.abandonPending(op)
	}
	if op.pair.PairId == "" {
		op.pair = *state.Pending
		op.until = earliestConnectorDeadline(until, op.prepare.started.Add(state.PendingUntil.Sub(state.Pending.ObservedAt)))
	}
	if !op.until.After(time.Now()) {
		return p.abandonPending(op)
	}
	return connectorRecoveryWait(nil)
}

func (p *connectorConnection) connectPendingLegs(op *connectorRebindOperation) error {
	key, err := connectorPairSecret(op.pair.Key)
	if err != nil {
		return err
	}
	var starts sync.WaitGroup
	var failures [2]error
	for slot := range op.legs {
		if leg := op.legs[slot]; leg != nil && leg.session.Err() != nil {
			_ = leg.Close()
			op.legs[slot], op.installed[slot], op.activated[slot] = nil, false, false
		}
		if op.legs[slot] != nil {
			continue
		}
		starts.Go(func() {
			call, stop := context.WithDeadline(p.ctx, minConnectorCall(op.until))
			defer stop()
			op.legs[slot], failures[slot] = dialConnectorLeg(call, p.ctx, p.config, p.signer, op.pair, key, slot, nil, op.initial[slot])
			if failures[slot] == nil {
				failures[slot] = context.Cause(call)
			}
			if failures[slot] != nil && op.legs[slot] != nil {
				_ = op.legs[slot].Close()
				op.legs[slot] = nil
			}
		})
	}
	starts.Wait()
	if err := errors.Join(failures[:]...); err != nil {
		if disposition := connectorReconnectError(err); disposition == rebindConnection || disposition == retirePath {
			p.retirePending(op)
			return connectorRecoveryWait(err)
		}
		return err
	}
	if op.legs[0].receipt.SourceIP != op.legs[1].receipt.SourceIP {
		p.retirePending(op)
		return connectorRecoveryWait(nil)
	}
	if !op.activated[0] || !op.activated[1] {
		state, _, err := p.inspectBinding()
		if err != nil {
			return err
		}
		if state.Pending == nil || state.Pending.OperationId != op.pair.OperationId {
			return p.abandonPending(op)
		}
		if state.Pending.PublisherPreparedUntil == nil || !state.Pending.PublisherPreparedUntil.After(state.Pending.ObservedAt) {
			return connectorRecoveryWait(nil)
		}
		for slot, leg := range op.legs {
			if op.activated[slot] {
				continue
			}
			call, stop := context.WithDeadline(p.ctx, minConnectorCall(op.until))
			err := activateConnectorLeg(call, leg, nil, op.initial[slot])
			stop()
			if err != nil {
				_ = leg.Close()
				op.legs[slot], op.installed[slot] = nil, false
				if disposition := connectorReconnectError(err); disposition == rebindConnection || disposition == retirePath {
					p.retirePending(op)
					return connectorRecoveryWait(err)
				}
				return err
			}
			op.activated[slot] = true
		}
	}
	for slot, leg := range op.legs {
		if op.installed[slot] {
			continue
		}
		if err := p.endpoint.InstallBindingCarrier(connectorBindingRevision(op.pair), slot, connectorLegCarrier{leg}); err != nil {
			return err
		}
		op.installed[slot] = true
	}
	return nil
}

func (p *connectorConnection) installActiveBinding(op *connectorRebindOperation, state controlv1.ConnectorPeerPairRebindState) error {
	active := state.Active
	if active == nil || state.Pending != nil || state.Operation == nil || state.Operation.Status != controlv1.ConnectorPeerPairOperationActive ||
		active.OperationId != op.pair.OperationId || active.DeliveryGeneration != op.pair.DeliveryGeneration || active.BindingChallenge != op.pair.BindingChallenge || active.Key != op.pair.Key ||
		active.Relays[0] != op.pair.Relays[0] || active.Relays[1] != op.pair.Relays[1] || active.SourceIp == nil || *active.SourceIp != op.legs[0].receipt.SourceIP ||
		active.PublisherPreparedUntil == nil {
		return ErrServiceConnection
	}
	if !op.until.After(time.Now()) {
		return p.abandonPending(op)
	}
	installedUntil := earliestConnectorDeadline(op.until, op.activate.started.Add(active.PublisherPreparedUntil.Sub(active.ObservedAt)), op.legs[0].until, op.legs[1].until)
	if !installedUntil.After(time.Now()) {
		return p.abandonPending(op)
	}
	p.mu.Lock()
	if !p.ownerCurrentLocked() {
		p.mu.Unlock()
		return ErrServiceConnection
	}
	p.mu.Unlock()
	if err := p.endpoint.ActivateBinding(connectorBindingRevision(*active)); err != nil {
		return err
	}
	if err := p.permissions.Resume(); err != nil {
		p.endpoint.SuspendBinding()
		return err
	}
	p.mu.Lock()
	p.pair, p.source = *active, *active.SourceIp
	p.key, _ = connectorPairSecret(active.Key)
	p.preparedUntil, p.reportedUntil = installedUntil, *active.PublisherPreparedUntil
	p.run.PairReady = &controlv1.ConnectorPeerPairReady{PublisherIdentityId: active.PublisherIdentityId, Relays: active.Relays}
	p.bindingCtx, p.bindingCancel = context.WithCancel(p.ctx)
	for slot, leg := range op.legs {
		p.paths[slot].leg, p.paths[slot].inspected, p.paths[slot].needsInspection = leg, false, false
		p.paths[slot].probeAfter = time.Now().Add(3 * time.Second)
		op.legs[slot] = nil
	}
	uses := make([]*connectorUse, 0, len(p.active))
	for use := range p.active {
		use.entry.DeliveryGeneration, use.entry.SourceIP = active.DeliveryGeneration, p.source
		if use.prepared != nil {
			uses = append(uses, use)
		}
	}
	p.rebind, p.recoveryState = nil, connectorBindingReady
	if !p.recoveryStarted.IsZero() {
		p.config.telemetry.Record(telemetryv1.Recovery, clienttelemetry.Path(p.paths[0].leg.transport), telemetryv1.Succeeded, time.Since(p.recoveryStarted))
		p.recoveryStarted = time.Time{}
	}
	if p.connectivity != nil {
		p.connectivity.SetBinding(connectorConnectivityBinding(*active))
	}
	permission, bound := p.permission, earliestConnectorDeadline(p.until, p.run.ValidUntil, p.permission.ExpiresAt)
	p.notifyLocked()
	p.mu.Unlock()
	p.renewActive(uses, permission, bound)
	return p.fillOpenings()
}

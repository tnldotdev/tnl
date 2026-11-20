package service

import (
	"context"
	"encoding/base64"
	"errors"
	"sync"
	"time"

	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/observability"
	"github.com/tnldotdev/tnl/internal/security/credentials"
	"github.com/tnldotdev/tnl/internal/security/visitortoken"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

type ConnectorPeerControl interface {
	peerDeliveryControl
	WaitPublisherRun(context.Context, controlv1.PublisherWatchRun) (int64, error)
	ListConnectorPeerPairs(context.Context, string, string, string, credentials.ServiceRunToken) (controlv1.ConnectorPeerPairCandidates, error)
	ConfirmConnectorPeerPairPrepared(context.Context, string, string, string, controlv1.ConnectorPeerPairPrepared, credentials.ServiceRunToken) error
}

type peerPreparation struct {
	candidate controlv1.ConnectorPeerPairCandidate
	peer      *PeerSession
	ctx       context.Context
	cancel    context.CancelFunc
	done      chan struct{}
}

// ServeConnectorPeers discovers and installs exact pairs before application arrival.
// the bounded workers do not own serving authority: each retained peer keeps its
// deadline, replay history and streams while a control request is outstanding.
func (b *Bound) ServeConnectorPeers(ctx context.Context, control ConnectorPeerControl, token credentials.ServiceRunToken) (result error) {
	if b == nil || control == nil || token == "" {
		return ErrPrivateStream
	}
	life, cancel := context.WithCancel(ctx)
	jobs := make(chan peerPreparation, maxConnectorPeerOwners)
	results := make(chan error, maxConnectorPeerOwners)
	var workers, serving sync.WaitGroup
	for range 4 {
		workers.Go(func() {
			// drain canceled queued jobs as well: their owner reservations
			// remain fenced until the same worker publishes their join.
			for job := range jobs {
				func() {
					defer b.finishPeerPreparation(job)
					b.prepareConnectorPeer(job, control, token, &serving, results)
				}()
			}
		})
	}
	defer func() {
		cancel()
		close(jobs)
		workers.Wait()
		serving.Wait()
		for {
			select {
			case err := <-results:
				result = errors.Join(result, err)
			default:
				return
			}
		}
	}()
	// a hint stays outstanding until every page has been applied. if the
	// authorized fetch fails, retry it without advancing the bookmark.
	hints := make(chan int64)
	applied := make(chan struct{})
	watchDone := make(chan error, 1)
	go func() {
		watchDone <- watchConnectorPeers(life, control, controlv1.PublisherWatchRun{
			ServiceId: b.prepared.Preparation.ServiceId, ServiceRunId: b.prepared.Preparation.ServiceRunId,
			RunNumber: b.prepared.Preparation.RunNumber, RunToken: token.String(),
		}, hints, applied)
	}()
	defer func() {
		cancel()
		if watchDone != nil {
			result = errors.Join(result, serviceWorkerError(<-watchDone, context.Canceled))
		}
	}()
	timer := time.NewTimer(time.Hour)
	timer.Stop()
	defer timer.Stop()
	var awaiting bool
	for {
		select {
		case <-life.Done():
			return nil
		case err := <-results:
			return err
		case err := <-watchDone:
			watchDone = nil
			return err
		case <-hints:
			awaiting = true
		case <-timer.C:
		}
		timer.Stop()
		after := ""
		active := false
		for {
			call, stop := context.WithTimeout(life, 2*time.Second)
			started := time.Now()
			page, err := control.ListConnectorPeerPairs(call, b.prepared.Preparation.ServiceId, b.prepared.Preparation.ServiceRunId, after, token)
			if err == nil {
				err = context.Cause(call)
			}
			stop()
			if err != nil {
				if life.Err() != nil {
					return serviceWorkerError(err, life.Err())
				}
				if !transientControlError(err) {
					return err
				}
				timer.Reset(time.Second)
				break
			}
			if !validPeerCandidates(page, after) {
				return failure.Wrap("reconcile connector peer pairs", failure.ServerResponseInvalid, ErrPrivateStream)
			}
			if err := b.observePeerOwners(started, page); err != nil {
				return err
			}
			for _, candidate := range page.Items {
				active = active || candidate.Disposition == controlv1.ConnectorPeerPairDispositionCandidate
				if job, ok := b.reservePeerPreparation(life, candidate); ok {
					// at most one job per existing bounded owner node can
					// be queued or entered, so this buffer cannot overflow.
					jobs <- job
				}
			}
			if page.NextAfter != nil {
				after = *page.NextAfter
				continue
			}
			if awaiting {
				select {
				case applied <- struct{}{}:
				case <-life.Done():
					return nil
				}
				awaiting = false
			}
			// known candidates need delivery retries and installed peers need
			// current owner observations even without a new change notice.
			if active {
				timer.Reset(time.Second)
			}
			break
		}
	}
}

func watchConnectorPeers(ctx context.Context, control ConnectorPeerControl, scope controlv1.PublisherWatchRun, hints chan<- int64, applied <-chan struct{}) error {
	for ctx.Err() == nil {
		revision, err := control.WaitPublisherRun(ctx, scope)
		if ctx.Err() != nil {
			return serviceWorkerError(err, ctx.Err())
		}
		if err != nil && !transientControlError(err) {
			return err
		}
		if err == nil {
			select {
			case hints <- revision:
			case <-ctx.Done():
				return nil
			}
			select {
			case <-applied:
			case <-ctx.Done():
				return nil
			}
			if revision >= 0 {
				scope.ConnectorRevision = &revision
				continue
			}
			scope.ConnectorRevision = nil
		}
		// unavailable scopes can still fetch retained, negative-only facts.
		// a failed wait or missing scope must not spin or renew authority.
		timer := time.NewTimer(time.Second)
		select {
		case <-timer.C:
		case <-ctx.Done():
			timer.Stop()
			return nil
		}
	}
	return nil
}

func validPeerCandidates(page controlv1.ConnectorPeerPairCandidates, after string) bool {
	if page.Items == nil || len(page.Items) > maxConnectorPeerOwners {
		return false
	}
	for _, item := range page.Items {
		if !opaqueid.Valid(item.PairId, "cpp_") || item.PairId <= after || item.DeliveryGeneration < 1 {
			return false
		}
		switch item.Disposition {
		case controlv1.ConnectorPeerPairDispositionCandidate:
			if item.OwnerRevision != 1 || item.Retirement != nil {
				return false
			}
		case controlv1.ConnectorPeerPairDispositionRetired:
			r := item.Retirement
			if item.OwnerRevision != 2 || item.OwnerAuthority != nil || r == nil ||
				r.RetiredAt.IsZero() || r.ObservedAt.IsZero() || r.RetainedUntil.IsZero() ||
				r.RetiredAt.After(r.ObservedAt) || !r.ObservedAt.Before(r.RetainedUntil) ||
				r.RetainedUntil.Sub(r.RetiredAt) > 5*time.Minute+5*time.Second {
				return false
			}
		default:
			return false
		}
		if observation := item.OwnerAuthority; observation != nil {
			duration := observation.ExpiresAt.Sub(observation.ObservedAt)
			if observation.ObservedAt.IsZero() || observation.ExpiresAt.IsZero() || duration <= 0 || duration > 5*time.Minute {
				return false
			}
		}
		after = item.PairId
	}
	return page.NextAfter == nil || len(page.Items) == maxConnectorPeerOwners && *page.NextAfter == after
}

func (b *Bound) peerNeedsPreparation(candidate controlv1.ConnectorPeerPairCandidate) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.peerNeedsPreparationLocked(candidate)
}

func (b *Bound) peerNeedsPreparationLocked(candidate controlv1.ConnectorPeerPairCandidate) bool {
	if b.closed || candidate.Disposition != controlv1.ConnectorPeerPairDispositionCandidate || candidate.OwnerRevision != 1 || candidate.Retirement != nil {
		return false
	}
	if p := b.connectorPeers[candidate.PairId]; p != nil {
		if p.ownerRetired || p.unbound || p.preparationDone != nil || candidate.DeliveryGeneration < p.highwater || p.deliveryState == peerDeliveryRetired && candidate.DeliveryGeneration == p.highwater {
			return false
		}
		// renewing local delivery does not confirm installation at control. a
		// failed confirmation must retry against the last confirmed deadline.
		return p.currentLocked() && candidate.DeliveryGeneration >= p.network.generation && (p.pending != nil || candidate.DeliveryGeneration > p.network.generation || p.deliveryState != peerDeliveryActive || p.installedUntil.IsZero() || time.Until(p.installedUntil) < 15*time.Second || time.Until(p.lease.until) < 15*time.Second)
	}
	for _, slot := range b.packetSlots {
		if slot == nil {
			return false
		}
		select {
		case <-slot.packets.Done():
			return false
		default:
		}
	}
	return true
}

func (b *Bound) reservePeerPreparation(ctx context.Context, candidate controlv1.ConnectorPeerPairCandidate) (peerPreparation, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.prunePeerOwnersLocked(time.Now())
	if ctx.Err() != nil || !b.peerNeedsPreparationLocked(candidate) {
		return peerPreparation{}, false
	}
	p := b.connectorPeers[candidate.PairId]
	if p == nil {
		if len(b.connectorPeers) >= maxConnectorPeerOwners {
			return peerPreparation{}, false
		}
		p = b.newPeerOwnerLocked(ctx, candidate.PairId)
	}
	life, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	p.preparationDone, p.stopPreparation = done, cancel
	return peerPreparation{candidate: candidate, peer: p, ctx: life, cancel: cancel, done: done}, true
}

func (b *Bound) finishPeerPreparation(job peerPreparation) {
	job.cancel()
	b.mu.Lock()
	unbound := job.peer.unbound
	b.mu.Unlock()
	if unbound {
		job.peer.Close()
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	close(job.done)
	if job.peer.preparationDone == job.done {
		job.peer.preparationDone, job.peer.stopPreparation = nil, nil
		// no verified binding escaped a failed unbound preparation. a
		// retirement, unlike that failed read, must retain its owner fence.
		if job.peer.unbound && !job.peer.ownerRetired && b.connectorPeers[job.candidate.PairId] == job.peer {
			delete(b.connectorPeers, job.candidate.PairId)
		}
	}
}

func (b *Bound) prepareConnectorPeer(job peerPreparation, control ConnectorPeerControl, token credentials.ServiceRunToken, serving *sync.WaitGroup, results chan<- error) {
	ctx, candidate, p := job.ctx, job.candidate, job.peer
	b.mu.Lock()
	current := ctx.Err() == nil && !b.closed && !p.ownerRetired && p.ctx.Err() == nil && b.connectorPeers[candidate.PairId] == p && p.preparationDone == job.done
	unbound := p.unbound
	b.mu.Unlock()
	if !current {
		return
	}
	call, stop := context.WithTimeout(ctx, 2*time.Second)
	binding, err := PreparePeerBinding(call, control, b.prepared.Preparation.ServiceId, b.prepared.Preparation.ServiceRunId, candidate.PairId, candidate.DeliveryGeneration, token)
	stop()
	if err != nil || ctx.Err() != nil {
		return
	}
	_, finish := observability.PublisherOperation(ctx, "peer_install")
	installation := ErrPrivateStream
	defer func() { finish(installation) }()
	if unbound {
		// an operation ID identifies a rebind candidate, never a new owner.
		if binding.operation != "" || binding.state != controlv1.ConnectorPeerPairBindingActive {
			return
		}
		p, err = b.BindPeer(ctx, binding)
		if err == nil {
			serving.Go(func() {
				err := p.Serve(p.ctx)
				b.mu.Lock()
				retired := p.ownerRetired
				b.mu.Unlock()
				if retired {
					err = serviceWorkerError(err, ErrPrivateStream)
				}
				err = serviceWorkerError(err, context.Canceled)
				if err != nil {
					// a first failed owner fences new preparation, bounding
					// this error queue by the same retained owner count.
					b.mu.Lock()
					b.closed = true
					b.mu.Unlock()
					results <- err
				}
			})
		}
	} else {
		switch binding.state {
		case controlv1.ConnectorPeerPairBindingActive:
			b.mu.Lock()
			pending := p.pending != nil
			b.mu.Unlock()
			if pending {
				err = p.activateBinding(binding)
			} else {
				err = p.Renew(binding)
			}
		case controlv1.ConnectorPeerPairBindingSuspended:
			b.mu.Lock()
			current := p.deliveryBindingLocked().peerNetworkBinding
			b.mu.Unlock()
			p.detachDelivery(current)
			return
		default:
			err = p.stageBinding(binding)
		}
	}
	if err != nil {
		return
	}
	confirm, done := context.WithTimeout(ctx, 2*time.Second)
	defer done()
	select {
	case <-p.ready:
	case <-p.ctx.Done():
		return
	case <-confirm.Done():
		return
	}
	b.mu.Lock()
	installed := p.deliveryBindingLocked()
	current = p.currentLocked() && ctx.Err() == nil && p.preparationDone == job.done && installed.generation == binding.generation && installed.peerNetworkBinding.sameOperation(binding.peerNetworkBinding) && (p.pending == nil || p.deliveryState == peerDeliveryPrepared)
	b.mu.Unlock()
	if !current {
		return
	}
	// a newly created workload may precede the next background policy snapshot.
	// installation cannot advertise readiness until that local snapshot includes
	// its current parent lease. arrivals neither fetch policy nor retry admission.
	if !b.connectorPeerPolicyCurrent(binding) {
		return
	}
	installation = nil
	report := controlv1.ConnectorPeerPairPrepared{
		DeliveryId: base64.RawURLEncoding.EncodeToString(binding.delivery[:]), DeliveryGeneration: binding.generation, BindingExpiresAt: installed.authorityUntil,
		Phase: controlv1.ConnectorPeerPairPreparedInstalled, OperationId: binding.operation, BindingChallenge: binding.challenge,
	}
	err = control.ConfirmConnectorPeerPairPrepared(confirm, binding.serviceID, binding.runID, binding.pairID, report, token)
	if err != nil || confirm.Err() != nil {
		return
	}
	b.mu.Lock()
	if p.currentLocked() && p.lease == binding.peerLease {
		p.installedUntil = binding.until
	}
	packets, pending := p.packets, p.pending != nil
	b.mu.Unlock()
	if !pending || packets == nil {
		return
	}
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		b.mu.Lock()
		current = p.currentLocked() && ctx.Err() == nil && p.preparationDone == job.done &&
			p.pending != nil && p.deliveryState == peerDeliveryPrepared && p.pending.generation == binding.generation &&
			p.pending.peerNetworkBinding.sameOperation(binding.peerNetworkBinding)
		b.mu.Unlock()
		if !current {
			return
		}
		if proofs, ready := packets.BindingProofs(binding.revision()); ready {
			report.Phase = controlv1.ConnectorPeerPairPreparedProved
			for _, proof := range proofs {
				report.PathProofs = append(report.PathProofs, controlv1.ConnectorPeerPairPathProof{ConnectionSlot: proof.ConnectionSlot, ProbeNonce: proof.ProbeNonce, ReplyFrame: proof.ReplyFrame})
			}
			_ = control.ConfirmConnectorPeerPairPrepared(confirm, binding.serviceID, binding.runID, binding.pairID, report, token)
			return
		}
		select {
		case <-p.ctx.Done():
			return
		case <-confirm.Done():
			return
		case <-ticker.C:
		}
	}
}

func (b *Bound) connectorPeerPolicyCurrent(binding PeerBinding) bool {
	view, enabled, _ := b.prepared.policy.Current()
	if !enabled || view.MetadataRevision != b.prepared.metadataRevision {
		return false
	}
	if binding.subject.Kind == tunnelv1.VisitorWorkloadSession {
		parent, found := view.Workload(binding.subject.WorkloadSessionID)
		return found && parent.ExpiresAt.After(view.AuthorityTime(time.Now()))
	}
	if binding.subject.Kind == tunnelv1.VisitorRegisteredKey {
		id := (visitortoken.RegisteredKey{GrantID: binding.subject.GrantID, KeyID: binding.subject.KeyID}).AuthorityID()
		parent, found := view.RegisteredKey(id)
		return found && parent.ExpiresAt.After(view.AuthorityTime(time.Now()))
	}
	return true
}

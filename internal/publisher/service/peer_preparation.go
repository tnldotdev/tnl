package service

import (
	"context"
	"encoding/base64"
	"sync"
	"time"

	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/observability"
	"github.com/tnldotdev/tnl/internal/security/credentials"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

type ConnectorPeerControl interface {
	peerDeliveryControl
	ListConnectorPeerPairs(context.Context, string, string, string, credentials.ServiceRunToken) (controlv1.ConnectorPeerPairCandidates, error)
	ConfirmConnectorPeerPairPrepared(context.Context, string, string, string, controlv1.ConnectorPeerPairPrepared, credentials.ServiceRunToken) error
}

// ServeConnectorPeers discovers and installs exact pairs before application arrival.
// the bounded workers do not own serving authority: each retained peer keeps its
// deadline, replay history and streams while a control request is outstanding.
func (b *Bound) ServeConnectorPeers(ctx context.Context, control ConnectorPeerControl, token credentials.ServiceRunToken) error {
	if b == nil || control == nil || token == "" {
		return ErrPrivateStream
	}
	life, cancel := context.WithCancel(ctx)
	jobs := make(chan controlv1.ConnectorPeerPairCandidate, maxConnectorPeerOwners)
	finished := make(chan string, maxConnectorPeerOwners)
	var workers, serving sync.WaitGroup
	for range 4 {
		workers.Go(func() {
			for {
				select {
				case <-life.Done():
					return
				case candidate := <-jobs:
					b.prepareConnectorPeer(life, control, token, candidate, &serving)
					select {
					case finished <- candidate.PairId:
					case <-life.Done():
						return
					}
				}
			}
		})
	}
	defer func() { cancel(); workers.Wait(); serving.Wait() }()
	timer := time.NewTimer(0)
	defer timer.Stop()
	after := ""
	pending := make(map[string]bool)
	for {
		select {
		case <-life.Done():
			return nil
		case id := <-finished:
			delete(pending, id)
		case <-timer.C:
			call, stop := context.WithTimeout(life, 2*time.Second)
			page, err := control.ListConnectorPeerPairs(call, b.prepared.Preparation.ServiceId, b.prepared.Preparation.ServiceRunId, after, token)
			if err == nil {
				err = context.Cause(call)
			}
			stop()
			if err != nil {
				if life.Err() != nil {
					return nil
				}
				if !transientControlError(err) {
					return err
				}
				timer.Reset(time.Second)
				continue
			}
			if !validPeerCandidates(page, after) {
				return failure.Wrap("reconcile connector peer pairs", failure.ServerResponseInvalid, ErrPrivateStream)
			}
			for _, candidate := range page.Items {
				if !pending[candidate.PairId] && len(pending) < maxConnectorPeerOwners && b.peerNeedsPreparation(candidate) {
					pending[candidate.PairId] = true
					jobs <- candidate
				}
			}
			after = ""
			if page.NextAfter != nil {
				after = *page.NextAfter
			}
			timer.Reset(time.Second)
		}
	}
}

func validPeerCandidates(page controlv1.ConnectorPeerPairCandidates, after string) bool {
	if page.Items == nil || len(page.Items) > maxConnectorPeerOwners {
		return false
	}
	for _, item := range page.Items {
		if !opaqueid.Valid(item.PairId, "cpp_") || item.PairId <= after || item.DeliveryGeneration < 1 {
			return false
		}
		after = item.PairId
	}
	return page.NextAfter == nil || len(page.Items) == maxConnectorPeerOwners && *page.NextAfter == after
}

func (b *Bound) peerNeedsPreparation(candidate controlv1.ConnectorPeerPairCandidate) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return false
	}
	if p := b.connectorPeers[candidate.PairId]; p != nil {
		return p.currentLocked() && p.binding.generation == candidate.DeliveryGeneration && (!p.prepared || !b.peerRelaysCurrentLocked(p.binding) || time.Until(p.binding.until) < 15*time.Second)
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

func (b *Bound) prepareConnectorPeer(ctx context.Context, control ConnectorPeerControl, token credentials.ServiceRunToken, candidate controlv1.ConnectorPeerPairCandidate, serving *sync.WaitGroup) {
	call, stop := context.WithTimeout(ctx, 2*time.Second)
	binding, err := PreparePeerBinding(call, control, b.prepared.Preparation.ServiceId, b.prepared.Preparation.ServiceRunId, candidate.PairId, candidate.DeliveryGeneration, token)
	stop()
	if err != nil || ctx.Err() != nil {
		return
	}
	_, finish := observability.PublisherOperation(ctx, "peer_install")
	installation := ErrPrivateStream
	defer func() { finish(installation) }()
	b.mu.Lock()
	p := b.connectorPeers[candidate.PairId]
	b.mu.Unlock()
	if p == nil {
		p, err = b.BindPeer(ctx, binding)
		if err == nil {
			serving.Go(func() { defer p.Close(); _ = p.ServeRelayPackets(ctx) })
		}
	} else {
		err = p.Renew(binding)
	}
	if err != nil {
		return
	}
	confirm, done := context.WithTimeout(ctx, 2*time.Second)
	defer done()
	select {
	case <-p.packetReady:
	case <-p.ctx.Done():
		return
	case <-confirm.Done():
		return
	}
	b.mu.Lock()
	current := p.currentLocked() && p.binding.until.Equal(binding.until)
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
	err = control.ConfirmConnectorPeerPairPrepared(confirm, binding.serviceID, binding.runID, binding.pairID, controlv1.ConnectorPeerPairPrepared{
		DeliveryId: base64.RawURLEncoding.EncodeToString(binding.delivery[:]), DeliveryGeneration: binding.generation, BindingExpiresAt: binding.authorityUntil,
	}, token)
	if err != nil || confirm.Err() != nil {
		return
	}
	b.mu.Lock()
	if p.currentLocked() && p.binding.until.Equal(binding.until) {
		p.prepared = true
	}
	b.mu.Unlock()
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
	return true
}

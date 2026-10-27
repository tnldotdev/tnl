package service

import (
	"context"
	"encoding/base64"
	"sync"
	"time"

	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/security/credentials"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

// NativePeerControl separates discovery, authorized binding, and installation
// reporting. each operation uses only the current service run token.
type NativePeerControl interface {
	peerDeliveryControl
	ListNativePeerPairs(context.Context, string, string, string, credentials.ServiceRunToken) (controlv1.NativePeerPairCandidates, error)
	ConfirmNativePeerPairPrepared(context.Context, string, string, string, controlv1.NativePeerPairPrepared, credentials.ServiceRunToken) error
}

const peerPreparationWorkers = 4

// ServeNativePeers reconciles bounded candidate pages outside application
// arrival. four workers prepare or renew bindings while live delivery sessions
// retain their own fixed deadlines. cancellation joins both kinds of work.
func (b *Bound) ServeNativePeers(ctx context.Context, control NativePeerControl, token credentials.ServiceRunToken) error {
	if b == nil || b.boundState == nil || !b.nativePeers || control == nil || token == "" {
		return ErrPrivateStream
	}
	b.mu.Lock()
	if b.closed || b.peerPreparationStarted {
		b.mu.Unlock()
		return ErrPrivateStream
	}
	b.peerPreparationStarted = true
	b.mu.Unlock()
	life, cancel := context.WithCancel(ctx)
	jobs := make(chan controlv1.NativePeerPairCandidate, maxPublisherPeerSessions)
	finished := make(chan string, maxPublisherPeerSessions)
	var workers, delivery sync.WaitGroup
	for range peerPreparationWorkers {
		workers.Go(func() {
			for {
				select {
				case <-life.Done():
					return
				case candidate := <-jobs:
					b.prepareNativePeer(life, control, token, candidate, &delivery)
					select {
					case finished <- candidate.PairId:
					case <-life.Done():
						return
					}
				}
			}
		})
	}
	defer func() {
		cancel()
		workers.Wait()
		delivery.Wait()
	}()
	after := ""
	pending := make(map[string]struct{}, maxPublisherPeerSessions)
	timer := time.NewTimer(0)
	defer timer.Stop()
	for {
		select {
		case <-life.Done():
			return nil
		case id := <-finished:
			delete(pending, id)
		case <-timer.C:
			call, done := context.WithTimeout(life, 2*time.Second)
			page, err := control.ListNativePeerPairs(call, b.prepared.Preparation.ServiceId, b.prepared.Preparation.ServiceRunId, after, token)
			if err == nil {
				err = call.Err()
			}
			done()
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
				return failure.Wrap("reconcile native peer pairs", failure.ServerResponseInvalid, ErrPrivateStream)
			}
			for _, candidate := range page.Items {
				if _, exists := pending[candidate.PairId]; exists || len(pending) >= maxPublisherPeerSessions || !b.peerNeedsPreparation(candidate) {
					continue
				}
				pending[candidate.PairId] = struct{}{}
				jobs <- candidate // pending bounds queued and in-progress jobs together.
			}
			after = ""
			if page.NextAfter != nil {
				after = *page.NextAfter
			}
			timer.Reset(time.Second)
		}
	}
}

func validPeerCandidates(page controlv1.NativePeerPairCandidates, after string) bool {
	if page.Items == nil || len(page.Items) > maxPublisherPeerSessions {
		return false
	}
	for _, candidate := range page.Items {
		if !opaqueid.Valid(candidate.PairId, "npp_") || candidate.PairId <= after || candidate.DeliveryGeneration < 1 {
			return false
		}
		after = candidate.PairId
	}
	return page.NextAfter == nil || len(page.Items) == maxPublisherPeerSessions && *page.NextAfter == after
}

func (b *Bound) peerNeedsPreparation(candidate controlv1.NativePeerPairCandidate) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return false
	}
	b.prunePeersLocked(time.Now())
	if p := b.peers[candidate.PairId]; p != nil {
		return !p.closed && p.binding.generation == candidate.DeliveryGeneration &&
			(!p.publisherPrepared || p.binding.expiresAt.Before(time.Now().Add(15*time.Second)))
	}
	if len(b.peers) >= maxPublisherPeerSessions {
		return false
	}
	for slot, claimed := range b.packetSlots {
		if claimed == nil || claimed.packets == nil || claimed.packets.ctx.Err() != nil ||
			claimed.ref != b.assignments[b.connections[slot].PublisherConnectionId] {
			return false
		}
	}
	return true
}

func (b *Bound) peerPacketSlotsCurrentLocked(binding PeerBinding) bool {
	for slot, claimed := range b.packetSlots {
		if claimed == nil || claimed.packets == nil || claimed.packets.ctx.Err() != nil ||
			claimed.ref != b.assignments[binding.relays[slot].PublisherConnectionId] {
			return false
		}
	}
	return true
}

func (b *Bound) prepareNativePeer(ctx context.Context, control NativePeerControl, token credentials.ServiceRunToken, candidate controlv1.NativePeerPairCandidate, delivery *sync.WaitGroup) {
	call, done := context.WithTimeout(ctx, 2*time.Second)
	binding, err := PreparePeerBinding(call, control, b.prepared.Preparation.ServiceId, b.prepared.Preparation.ServiceRunId,
		candidate.PairId, candidate.DeliveryGeneration, token)
	done()
	if err != nil || ctx.Err() != nil {
		// missing claims and transient failures do not extend the old deadline.
		// independently maintained local visitor policy still fences revocation.
		return
	}
	b.mu.Lock()
	p := b.peers[candidate.PairId]
	b.mu.Unlock()
	if p != nil {
		if p.Renew(binding) != nil {
			return
		}
	} else {
		p, err = b.BindPeer(ctx, binding)
		if err != nil {
			return
		}
		delivery.Go(func() {
			defer p.Close()
			_ = p.ServeRelayPackets(ctx)
		})
	}
	// the relay receipt alone cannot establish publisher readiness. wait for
	// both exact registrations and the inner listener before reporting it.
	confirm, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	select {
	case <-p.packetReady:
	case <-p.ctx.Done():
		return
	case <-confirm.Done():
		return
	}
	b.mu.Lock()
	current := !p.closed && p.ctx.Err() == nil && p.binding.expiresAt.Equal(binding.expiresAt) &&
		b.peerBindingCurrentLocked(binding, time.Now()) && b.peerPacketSlotsCurrentLocked(binding)
	b.mu.Unlock()
	if !current {
		return
	}
	err = control.ConfirmNativePeerPairPrepared(confirm, binding.serviceID, binding.serviceRunID, binding.pairID,
		controlv1.NativePeerPairPrepared{DeliveryId: base64.RawURLEncoding.EncodeToString(binding.deliveryID[:]),
			DeliveryGeneration: binding.generation, BindingExpiresAt: binding.authorityExpiresAt}, token)
	if err != nil || confirm.Err() != nil {
		return
	}
	b.mu.Lock()
	if !p.closed && p.ctx.Err() == nil && p.binding.expiresAt.Equal(binding.expiresAt) &&
		b.peerBindingCurrentLocked(binding, time.Now()) && b.peerPacketSlotsCurrentLocked(binding) {
		p.publisherPrepared = true
	}
	b.mu.Unlock()
}

package service

import (
	"time"

	"github.com/tnldotdev/tnl/internal/transport/peer"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

// delivery state is separate from retained owner authority. staging and prepared
// permit probes only; retired keeps the failed pending revision for stale checks.
type peerDeliveryState uint8

const (
	peerDeliverySuspended peerDeliveryState = iota
	peerDeliveryActive
	peerDeliveryStaging
	peerDeliveryPrepared
	peerDeliveryRetired
)

func (b PeerBinding) revision() peer.BindingRevision {
	return peer.BindingRevision{PairID: b.pairID, Generation: b.generation, OperationID: b.operation, Challenge: b.challenge}
}

func (b peerNetworkBinding) sameOperation(other peerNetworkBinding) bool {
	b.state, other.state = "", ""
	b.source = other.source
	return b == other
}

func (p *PeerSession) deliveryBindingLocked() PeerBinding {
	if p.pending != nil {
		return *p.pending
	}
	return p.bindingLocked()
}

// detachDelivery cuts obsolete packet delivery, never the retained owner or its
// admissions. a concurrently installed newer binding cannot be detached by an
// older heartbeat or a delayed Claimed.Close.
func (p *PeerSession) detachDelivery(expected peerNetworkBinding) {
	p.installMu.Lock()
	defer p.installMu.Unlock()
	p.detachDeliveryUnderInstall(expected)
}

func (p *PeerSession) detachDeliveryUnderInstall(expected peerNetworkBinding) {
	b := p.bound
	b.mu.Lock()
	if p.deliveryBindingLocked().peerNetworkBinding != expected {
		b.mu.Unlock()
		return
	}
	p.deliveryState = peerDeliverySuspended
	if p.pending != nil {
		p.deliveryState = peerDeliveryRetired
	}
	if p.packets != nil {
		p.packets.SuspendBinding()
	}
	paths := p.packetPaths
	until := p.owner.until
	close(p.changed)
	p.changed = make(chan struct{})
	b.mu.Unlock()
	if err := p.permissionGate.Suspend(until); err != nil {
		p.stop()
	}
	for _, path := range paths {
		if path != nil {
			_ = path.Install(nil)
		}
	}
}

// stageBinding installs a control-delivered candidate into the same packet
// endpoint. a missing, expired, or retired owner is never replaced here.
func (p *PeerSession) stageBinding(binding PeerBinding) (result error) {
	p.installMu.Lock()
	defer p.installMu.Unlock()
	b := p.bound
	b.mu.Lock()
	valid := p.currentLocked() && b.peerCurrentLocked(binding) && b.peerRelaysCurrentLocked(binding) &&
		binding.peerIdentity == p.identity && binding.state != controlv1.ConnectorPeerPairBindingActive && binding.state != controlv1.ConnectorPeerPairBindingSuspended &&
		binding.operation != "" && p.packets != nil
	if !valid {
		b.mu.Unlock()
		return ErrPrivateStream
	}
	if p.pending != nil && binding.generation == p.pending.generation {
		same := binding.peerNetworkBinding.sameOperation(p.pending.peerNetworkBinding) && p.pending.until.After(time.Now()) && p.deliveryState == peerDeliveryPrepared
		if same {
			p.pending.until = peerDeadline(p.pending.until, binding.until)
			close(p.changed)
			p.changed = make(chan struct{})
		}
		b.mu.Unlock()
		if same {
			return nil
		}
		return ErrPrivateStream
	}
	if binding.generation <= p.highwater {
		b.mu.Unlock()
		return ErrPrivateStream
	}
	p.highwater, p.pending, p.deliveryState = binding.generation, &binding, peerDeliveryStaging
	packets := p.packets
	until := p.owner.until
	close(p.changed)
	p.changed = make(chan struct{})
	b.mu.Unlock()
	defer func() {
		if result != nil {
			p.detachDeliveryUnderInstall(binding.peerNetworkBinding)
		}
	}()
	if err := p.permissionGate.Suspend(until); err != nil {
		return err
	}
	if err := packets.StageBinding(binding.revision()); err != nil {
		return err
	}
	paths, slots, err := b.peerCarriers(binding)
	if err != nil {
		return err
	}
	for index, path := range paths {
		if err := packets.InstallBindingCarrier(binding.revision(), index, path); err != nil {
			closePeerCarriers(paths)
			return err
		}
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if !p.currentLocked() || p.pending == nil || p.deliveryState != peerDeliveryStaging || !p.pending.until.After(time.Now()) || !p.pending.peerNetworkBinding.sameOperation(binding.peerNetworkBinding) || b.packetSlots != slots || !b.peerRelaysCurrentLocked(binding) {
		return ErrPrivateStream
	}
	p.deliverySlots = slots
	p.deliveryState = peerDeliveryPrepared
	return nil
}

// activateBinding follows an explicit authenticated active delivery observation.
// it reuses every admission and guard, changes only source and binding facts,
// and never extends a stream's permission or setup deadline.
func (p *PeerSession) activateBinding(binding PeerBinding) error {
	p.installMu.Lock()
	defer p.installMu.Unlock()
	b := p.bound
	b.mu.Lock()
	valid := p.currentLocked() && b.peerCurrentLocked(binding) && b.peerRelaysCurrentLocked(binding) &&
		binding.peerIdentity == p.identity && binding.state == controlv1.ConnectorPeerPairBindingActive && p.pending != nil &&
		p.deliveryState == peerDeliveryPrepared && p.pending.peerNetworkBinding.sameOperation(binding.peerNetworkBinding) && p.pending.until.After(time.Now()) && p.packets != nil && b.packetSlots == p.deliverySlots
	if !valid {
		b.mu.Unlock()
		return ErrPrivateStream
	}
	if _, ready := p.packets.BindingProofs(binding.revision()); !ready {
		b.mu.Unlock()
		return ErrPrivateStream
	}
	if !b.prepared.policy.ConnectorSourceCurrent(binding.source, p.identity.trustRevision) {
		b.mu.Unlock()
		return ErrPrivateStream
	}
	var denied []*connectorAdmission
	for a := range p.streams {
		if a.admitted && !a.retiring {
			if err := a.guard.RebindSource(binding.source, p.identity.trustRevision); err != nil {
				a.retiring = true
				denied = append(denied, a)
			}
		}
	}
	if len(denied) != 0 {
		b.mu.Unlock()
		for _, a := range denied {
			a.stopAndClose()
		}
		return ErrPrivateStream
	}
	if err := p.packets.ActivateBinding(binding.revision()); err != nil {
		b.mu.Unlock()
		return err
	}
	p.installedUntil = peerDeadline(p.pending.until, binding.until)
	p.network, p.lease, p.pending, p.deliveryState = binding.peerNetworkBinding, binding.peerLease, nil, peerDeliveryActive
	p.observeOwnerLocked(binding.peerLease)
	for a := range p.streams {
		if a.admitted && !a.retiring {
			a.entry.DeliveryGeneration, a.entry.SourceIP = binding.generation, binding.source.String()
			a.audit.SourceIP = binding.source.String()
			a.audit.DeliveryGeneration = binding.generation
		}
	}
	close(p.changed)
	p.changed = make(chan struct{})
	b.mu.Unlock()
	if err := p.permissionGate.Resume(); err != nil {
		p.packets.SuspendBinding()
		p.stop()
		return err
	}
	return nil
}

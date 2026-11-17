package stream

import (
	"time"

	"github.com/tnldotdev/tnl/internal/transport/peer"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

func connectorConnectivityBinding(pair controlv1.ConnectorPeerPair) peer.ConnectivityBinding {
	return peer.ConnectivityBinding{Revision: connectorBindingRevision(pair), DeliveryID: pair.DeliveryId,
		RelayAddresses: [2]string{pair.Relays[0].RelayAddress, pair.Relays[1].RelayAddress}}
}

func (p *connectorConnection) authorityCurrentLocked(now time.Time) bool {
	return (p.permissions == nil || p.permissions.Err() == nil) && p.until.After(now) &&
		p.run.ValidUntil.After(now) && p.permission.ExpiresAt.After(now)
}

// serving admission stops immediately. retained packet delivery can finish its
// existing terminal work only within the original authority and cleanup fences.
func (p *connectorConnection) admitDirectPacket(packet tunnelv1.PeerPacket) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	now := time.Now()
	if !p.authorityCurrentLocked(now) || p.recoveryState == connectorRebinding ||
		!p.preparedUntil.After(now) || packet.BindingGeneration != uint64(p.pair.DeliveryGeneration) {
		return false
	}
	if p.packetCtx != nil {
		if p.packetCtx.Err() != nil {
			return false
		}
		if until, bounded := p.packetCtx.Deadline(); bounded && !until.After(now) {
			return false
		}
	}
	if !p.closing && p.ctx.Err() == nil {
		return true
	}
	if p.packetCtx == nil || p.packetCtx.Err() != nil || p.cleanup == nil || p.endpoint == nil {
		return false
	}
	binding, active := p.endpoint.CurrentBinding()
	if !active || binding != connectorBindingRevision(p.pair) {
		return false
	}
	// inspect the first-stop budget without starting, renewing, or replacing it.
	p.cleanup.mu.Lock()
	until, cleanupContext := p.cleanup.until, p.cleanup.ctx
	p.cleanup.mu.Unlock()
	if until.IsZero() || !until.After(now) || cleanupContext != nil && cleanupContext.Err() != nil {
		return false
	}
	return p.cleanup.bound(until).After(now)
}

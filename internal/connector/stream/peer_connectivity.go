package stream

import (
	"github.com/tnldotdev/tnl/internal/transport/peer"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

func connectorConnectivityBinding(pair controlv1.ConnectorPeerPair) peer.ConnectivityBinding {
	return peer.ConnectivityBinding{Revision: connectorBindingRevision(pair), DeliveryID: pair.DeliveryId,
		RelayAddresses: [2]string{pair.Relays[0].RelayAddress, pair.Relays[1].RelayAddress}}
}

// direct delivery retains the same independently checked authority fences as
// relay delivery, including when a deadline watch has not yet been scheduled.
func (p *connectorConnection) admitDirectPacket(packet tunnelv1.PeerPacket) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.currentLocked() && packet.BindingGeneration == uint64(p.pair.DeliveryGeneration)
}

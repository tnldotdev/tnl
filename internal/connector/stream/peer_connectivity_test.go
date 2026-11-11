package stream

import (
	"context"
	"testing"
	"time"

	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

func TestConnectorDirectPacketAdmissionKeepsIndependentDeadlines(t *testing.T) {
	for _, fence := range []string{"pair", "run", "visitor", "installation", "generation", "binding", "cancellation"} {
		t.Run(fence, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			until := time.Now().Add(time.Minute)
			p := &connectorConnection{ctx: ctx, until: until, preparedUntil: until,
				run: Run{ValidUntil: until}, pair: controlv1.ConnectorPeerPair{DeliveryGeneration: 3},
				permission: controlv1.VisitorTokenResponse{ExpiresAt: until}}
			packet := tunnelv1.PeerPacket{BindingGeneration: 3, Kind: tunnelv1.PeerData}
			if !p.admitDirectPacket(packet) {
				t.Fatal("current direct packet was rejected")
			}
			expired := time.Now().Add(-time.Second)
			switch fence {
			case "pair":
				p.until = expired
			case "run":
				p.run.ValidUntil = expired
			case "visitor":
				p.permission.ExpiresAt = expired
			case "installation":
				p.preparedUntil = expired
			case "generation":
				packet.BindingGeneration++
			case "binding":
				p.recoveryState = connectorRebinding
			case "cancellation":
				cancel()
			}
			// no deadline watch runs: receipt itself must enforce the fence.
			if p.admitDirectPacket(packet) {
				t.Fatal("direct delivery bypassed its authority fence")
			}
		})
	}
}

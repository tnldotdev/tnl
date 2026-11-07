package relay

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/transport/tunnel"
	relayv1 "github.com/tnldotdev/tnl/pkg/api/control/private/relay/v1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

func TestConnectorClaimStaleRelayRequiresRebindingWithoutDelivery(t *testing.T) {
	for _, change := range []struct {
		name  string
		apply func(*relayv1.RelayLease)
	}{
		{"process restart", func(lease *relayv1.RelayLease) { lease.RelayRunId = "replacement-run" }},
		{"lease replacement", func(lease *relayv1.RelayLease) { lease.RelayLeaseRevision++ }},
		{"draining", func(lease *relayv1.RelayLease) { lease.Draining = true }},
		{"expired", func(lease *relayv1.RelayLease) { lease.LeaseExpiresAt = time.Now().Add(-time.Second) }},
	} {
		for _, stage := range []string{"before claim", "during claim"} {
			t.Run(change.name+"/"+stage, func(t *testing.T) {
				f := newConnectorBindingFixture(t)
				lease := f.acceptor.CurrentLease()
				f.acceptor.CurrentLease = func() relayv1.RelayLease { return lease }
				prior, calls := f.acceptor.Claim, 0
				f.acceptor.Claim = connectorClaimFunc(func(ctx context.Context, current relayv1.RelayLease, source netip.Addr, proof tunnelv1.ConnectorPairLegProof, signature []byte) (relayv1.ConnectorPeerPairLegClaim, error) {
					calls++
					claim, err := prior.ClaimConnectorPeerPairLegFromAcceptedSocket(ctx, current, source, proof, signature)
					change.apply(&lease)
					return claim, err
				})
				wantCalls := 1
				if stage == "before claim" {
					change.apply(&lease)
					wantCalls = 0
				}
				accepted := &connectorSourcePeer{}
				accepted.move("192.0.2.1:12345")
				outer := &connectorObservedSession{forwardingTestSession: newForwardingTestSession(), connectorSourcePeer: accepted}
				t.Cleanup(func() { _ = outer.Close() })
				claim, err := f.acceptor.claim(t.Context(), outer, f.proof)
				var protocol *tunnel.ProtocolError
				if !errors.As(err, &protocol) || protocol.Code != tunnelv1.StaleConnectionAssignment {
					t.Fatal("stale relay became a terminal subject denial", err)
				}
				if calls != wantCalls || claim != (connectorClaim{}) || len(f.publisher.bridges) != 0 {
					t.Fatal("stale relay returned delivery authority or reached control before checking its lease")
				}
			})
		}
	}
}

func TestConnectorClaimDenialPrecedesConcurrentLeaseChange(t *testing.T) {
	f := newConnectorBindingFixture(t)
	lease := f.acceptor.CurrentLease()
	f.acceptor.CurrentLease = func() relayv1.RelayLease { return lease }
	denied := &tunnel.ProtocolError{Code: tunnelv1.Unauthenticated}
	f.acceptor.Claim = connectorClaimFunc(func(context.Context, relayv1.RelayLease, netip.Addr, tunnelv1.ConnectorPairLegProof, []byte) (relayv1.ConnectorPeerPairLegClaim, error) {
		lease.RelayRunId = "replacement-run"
		return relayv1.ConnectorPeerPairLegClaim{}, denied
	})
	accepted := &connectorSourcePeer{}
	accepted.move("192.0.2.1:12345")
	outer := &connectorObservedSession{forwardingTestSession: newForwardingTestSession(), connectorSourcePeer: accepted}
	t.Cleanup(func() { _ = outer.Close() })
	claim, err := f.acceptor.claim(t.Context(), outer, f.proof)
	var protocol *tunnel.ProtocolError
	if !errors.Is(err, denied) || !errors.As(err, &protocol) || protocol.Code != tunnelv1.Unauthenticated || claim != (connectorClaim{}) {
		t.Fatal("lease change hid the control authorization denial", err)
	}
	malformed := f.proof
	malformed.Signature = nil
	claim, err = f.acceptor.claim(t.Context(), outer, malformed)
	if !errors.As(err, &protocol) || protocol.Code != tunnelv1.Unauthenticated || claim != (connectorClaim{}) {
		t.Fatal("stale relay hid a malformed proof", err)
	}
}

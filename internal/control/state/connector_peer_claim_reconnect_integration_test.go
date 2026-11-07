package state

import (
	"errors"
	"net/netip"
	"testing"
	"time"
)

func TestIntegrationConnectorPeerClaimRecoversCommittedLostResponse(t *testing.T) {
	f := newConnectorPairFixture(t)
	pair := f.create(t)
	source := netip.MustParseAddr("192.0.2.1")
	firstAt := f.now.Add(time.Millisecond)
	first := testConnectorLegProof(t, pair, 0, firstAt, f.key)
	// discard the successful reply after commit, as when the outer hello is lost.
	if _, err := testClaimConnectorPeerPairLeg(t, f.d, f.visitor, pair.Relays[0].RelayLease, source, first, firstAt); err != nil {
		t.Fatal(err)
	}
	if _, err := testClaimConnectorPeerPairLeg(t, f.d, f.visitor, pair.Relays[0].RelayLease, source, first, firstAt); !errors.Is(err, ErrServiceAccess) {
		t.Fatal("replayed signed hello accepted", err)
	}
	nextAt := firstAt.Add(time.Millisecond)
	next := testConnectorLegProof(t, pair, 0, nextAt, f.key)
	recovered, err := testClaimConnectorPeerPairLeg(t, f.d, f.visitor, pair.Relays[0].RelayLease, source, next, nextAt)
	if err != nil {
		t.Fatal("fresh same-source claim could not recover", err)
	}
	if recovered.PairID != pair.ID || recovered.DeliveryID != pair.DeliveryID || recovered.DeliveryGeneration != pair.DeliveryGeneration || recovered.Key != pair.Key || recovered.ExpiresAt.After(pair.ExpiresAt) {
		t.Fatal("claim recovery changed pair or extended its authority")
	}
	changedAt := nextAt.Add(time.Millisecond)
	changed := testConnectorLegProof(t, pair, 0, changedAt, f.key)
	if _, err := testClaimConnectorPeerPairLeg(t, f.d, f.visitor, pair.Relays[0].RelayLease, netip.MustParseAddr("192.0.2.2"), changed, changedAt); !errors.Is(err, ErrConnectorPeerBindingStale) {
		t.Fatal("recovery changed observed source", err)
	}
	if err := f.d.RevokeVisitorDevice(f.visitor, f.request.Subject.IdentityID, f.request.Subject.DeviceID, changedAt); err != nil {
		t.Fatal(err)
	}
	if _, err := testClaimConnectorPeerPairLeg(t, f.d, f.visitor, pair.Relays[0].RelayLease, source, changed, changedAt); !errors.Is(err, ErrServiceAccess) {
		t.Fatal("revoked subject recovered a claim", err)
	}
}

package state

import (
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
)

func TestIntegrationNativePeerPairRenewalRebindsOnlyAuthorizedCarrier(t *testing.T) {
	f := newNativePairFixture(t)
	pair := f.create(t)
	for slot := range pair.Relays {
		f.claim(t, pair, slot, f.now)
	}
	binding, err := f.binding(t, pair, f.now)
	if err != nil {
		t.Fatal(err)
	}
	f.report(t, pair, binding.expiresAt, f.now)
	nextConnection, err := opaqueid.New(opaqueid.PublisherConnectionPrefix)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.d.pool.Exec(t.Context(), `UPDATE control.service_connection_slots SET publisher_connection_id=$1,connection_assignment_revision=connection_assignment_revision+1 WHERE publisher_connection_id=$2`, nextConnection, pair.Relays[0].PublisherConnectionID); err != nil {
		t.Fatal(err)
	}
	renew := f.request
	renew.Action, renew.PreviousPairID, renew.PreviousGeneration, renew.RequestedAt = "renew", pair.ID, pair.DeliveryGeneration, f.now.Add(time.Second)
	f.sign(t, &renew)
	if _, err := f.d.RenewNativePeerPair(f.visitor, renew, renew.RequestedAt); !errors.Is(err, ErrServiceAccess) {
		t.Fatal("stale carrier snapshot was renewed", err)
	}
	renew.ExpectedRelays[0].PublisherConnectionID = nextConnection
	renew.ExpectedRelays[0].AssignmentRevision++
	f.sign(t, &renew)
	next, err := f.d.RenewNativePeerPair(f.visitor, renew, renew.RequestedAt)
	if err != nil {
		t.Fatal("fresh exact owner renewal could not replace delivery", err)
	}
	if next.ID != pair.ID || next.Key != pair.Key || next.DeliveryID != pair.DeliveryID || next.DeliveryGeneration != pair.DeliveryGeneration || !next.PublisherPreparedUntil.IsZero() {
		t.Fatal("carrier renewal replaced the retained owner or borrowed installation readiness")
	}
	if next.Relays[0] != renew.ExpectedRelays[0] || next.Relays[1] != pair.Relays[1] {
		t.Fatal("carrier renewal changed the healthy sibling")
	}
	binding, err = f.binding(t, next, renew.RequestedAt)
	if err != nil || binding.claimsCurrent {
		t.Fatal("replacement borrowed the old carrier claim", err)
	}
	proofAt := f.now.Add(2 * time.Second)
	proof := testNativeLegProof(t, next, 0, proofAt, f.key)
	if _, err := testClaimNativePeerPairLeg(t, f.d, t.Context(), next.Relays[0].RelayLease, netip.MustParseAddr("192.0.2.11"), proof, proofAt); !errors.Is(err, ErrServiceAccess) {
		t.Fatal("carrier replacement changed the source history", err)
	}
	f.claim(t, next, 0, proofAt)
	binding, err = f.binding(t, next, proofAt)
	if err != nil || !binding.claimsCurrent || !binding.preparedUntil.IsZero() {
		t.Fatal("new carrier did not require fresh claim and publisher installation", err)
	}
	f.report(t, next, binding.expiresAt, proofAt)
	if _, err := f.d.RenewNativePeerPair(f.visitor, renew, proofAt); err != nil {
		t.Fatal("exact uncertain renewal retry lost its delivery", err)
	}
}

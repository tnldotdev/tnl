package state

import (
	"errors"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
)

func TestIntegrationNativePeerPairRenewalRejectsChangedCarrier(t *testing.T) {
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
	for _, current := range []bool{false, true} {
		if current {
			renew.ExpectedRelays[0].PublisherConnectionID = nextConnection
			renew.ExpectedRelays[0].AssignmentRevision++
		}
		f.sign(t, &renew)
		if _, err := f.d.RenewNativePeerPair(f.visitor, renew, renew.RequestedAt); !errors.Is(err, ErrServiceAccess) {
			t.Fatal("changed carrier renewed retained session", err)
		}
	}
	var stored string
	if err := f.d.pool.QueryRow(t.Context(), `SELECT slots->0->>'publisher_connection_id' FROM control.native_peer_pairs WHERE id=$1`, pair.ID).Scan(&stored); err != nil || stored != pair.Relays[0].PublisherConnectionID {
		t.Fatal("failed renewal changed pair", stored, err)
	}
}

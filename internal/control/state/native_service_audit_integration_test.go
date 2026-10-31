package state

import (
	"bytes"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/observability/serviceaudit"
)

func TestIntegrationNativeServiceAuditExactRunPairAndSource(t *testing.T) {
	f := newNativePairFixture(t)
	pair := f.create(t)
	ctx := t.Context()
	source := netip.MustParseAddr("192.0.2.10")
	for slot, relay := range pair.Relays {
		proof := testNativeLegProof(t, pair, slot, f.now, f.key)
		if _, err := testClaimNativePeerPairLeg(t, f.d, ctx, relay.RelayLease, source, proof, f.now); err != nil {
			t.Fatal(err)
		}
	}
	delivery, err := f.d.DeliverNativePeerPair(ctx, pair.ServiceID, f.run.RunID, pair.ID, pair.DeliveryGeneration, f.run.Token, f.now)
	if err != nil {
		t.Fatal(err)
	}
	o := serviceaudit.Observation{EventID: serviceaudit.NewID(), ServiceID: pair.ServiceID, ServiceKind: "service",
		RunID: f.run.RunID, RunNumber: f.run.RunNumber, PairID: pair.ID, VisitorConnectionID: "vc_0123456789ABCDEFGHIJKL",
		SourceIP: source.String(), EventType: "connection.open", OccurredAt: f.now, Outcome: "allowed"}
	report := func(token string, events ...serviceaudit.Observation) (ServiceObservationResult, error) {
		return f.d.IngestServiceRunObservations(ctx, pair.ServiceID, f.run.RunID, token, f.run.RunNumber, serviceaudit.Batch{Events: events}, f.now)
	}
	if _, err := report(f.run.Token, o); !errors.Is(err, ErrServiceAuditAccess) {
		t.Fatal("uninstalled pair reported an admitted visitor", err)
	}
	prepared := NativePeerPairPrepared{DeliveryID: delivery.DeliveryID, DeliveryGeneration: delivery.DeliveryGeneration, BindingExpiresAt: delivery.ExpiresAt}
	if err := f.d.ConfirmNativePeerPairPrepared(ctx, pair.ServiceID, f.run.RunID, pair.ID, f.run.Token, prepared, f.now); err != nil {
		t.Fatal(err)
	}
	before := nativePairSavedAuthority(t, f.d, pair.ID)
	for _, token := range []string{"", "person-token", pair.Key} {
		if _, err := report(token, o); !errors.Is(err, ErrServiceAccess) {
			t.Fatal("unrelated credential reported a native visitor", err)
		}
	}
	for _, change := range []func(*serviceaudit.Observation){
		func(o *serviceaudit.Observation) { o.SourceIP = "192.0.2.11" },
		func(o *serviceaudit.Observation) { o.PairID = "npp_0123456789ABCDEFGHIJKL" },
		func(o *serviceaudit.Observation) { o.RunID = "srun_0123456789ABCDEFGHIJKL" },
		func(o *serviceaudit.Observation) { o.RunNumber++ },
		func(o *serviceaudit.Observation) { o.ServiceID = "svc_0123456789ABCDEFGHIJKL" },
		func(o *serviceaudit.Observation) { o.OccurredAt = f.now.Add(-time.Minute) },
	} {
		bad := o
		change(&bad)
		if _, err := report(f.run.Token, bad); !errors.Is(err, ErrServiceAuditAccess) {
			t.Fatal("foreign native observation accepted", err)
		}
	}
	for i := range 2 {
		result, err := report(f.run.Token, o)
		if err != nil || result.Accepted != 1-i || result.Duplicates != i {
			t.Fatal("native audit was not retry-stable", result, err)
		}
	}
	if !bytes.Equal(before, nativePairSavedAuthority(t, f.d, pair.ID)) {
		t.Fatal("audit reporting changed traffic authority")
	}
	var actor, device, publisher, ip string
	if err := f.d.pool.QueryRow(ctx, `SELECT actor_identity_id,device_id,publisher_identity_id,host(source_ip) FROM control.service_audit_events WHERE id=$1`, o.EventID).
		Scan(&actor, &device, &publisher, &ip); err != nil || actor != pair.Subject.IdentityID || device != pair.Subject.DeviceID || publisher != pair.PublisherIdentityID || ip != source.String() {
		t.Fatal("audit identity or source was not derived from the installed pair", err)
	}
	// a rejected neighbor rolls the whole batch back, including an earlier valid
	// insert. a conflicting retry must not overwrite the first committed fact.
	valid, bad := o, o
	valid.EventID, bad.EventID = serviceaudit.NewID(), serviceaudit.NewID()
	bad.SourceIP = "192.0.2.12"
	if _, err := report(f.run.Token, valid, bad); !errors.Is(err, ErrServiceAuditAccess) {
		t.Fatal(err)
	}
	var count int
	if err := f.d.pool.QueryRow(ctx, `SELECT count(*) FROM control.service_audit_events WHERE id=$1`, valid.EventID).Scan(&count); err != nil || count != 0 {
		t.Fatal("rejected batch partially committed", count, err)
	}
	bad = o
	bad.Outcome = "denied"
	if _, err := report(f.run.Token, bad); !errors.Is(err, ErrServiceAuditAccess) {
		t.Fatal("retry rewrote a committed observation", err)
	}
	// replacing or cleaning delivery material must not discard the already
	// installed audit scope or retain a carrier secret just to flush a close.
	if _, err := f.d.pool.Exec(ctx, `DELETE FROM control.native_peer_pairs WHERE id=$1`, pair.ID); err != nil {
		t.Fatal(err)
	}
	closedAt := f.now.Add(time.Second)
	if err := f.d.CloseServiceRun(ctx, pair.ServiceID, f.run.RunID, f.run.Token, closedAt); err != nil {
		t.Fatal(err)
	}
	closed := o
	closed.EventID, closed.EventType, closed.Outcome, closed.Reason = serviceaudit.NewID(), "connection.close", "closed", "closed"
	closed.OccurredAt = closedAt.Add(time.Millisecond)
	batch := serviceaudit.Batch{Events: []serviceaudit.Observation{closed}}
	if result, err := f.d.IngestServiceRunObservations(ctx, pair.ServiceID, f.run.RunID, f.run.Token, f.run.RunNumber, batch, closed.OccurredAt); err != nil || result.Accepted != 1 {
		t.Fatal("joined close could not flush after run shutdown", result, err)
	}
	if _, err := f.d.IngestServiceRunObservations(ctx, pair.ServiceID, f.run.RunID, f.run.Token, f.run.RunNumber, batch, closedAt.Add(serviceObservationDeliveryGrace+time.Nanosecond)); !errors.Is(err, ErrServiceAccess) {
		t.Fatal("old run token escaped the delivery grace", err)
	}
}

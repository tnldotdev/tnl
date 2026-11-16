package state

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
)

func TestIntegrationServiceSlotsRestoredUniqueConnectionAndUnrelatedHTTPRuns(t *testing.T) {
	f := newServicePublicationFixture(t)
	prepareServingPublisher(t, f)
	sibling := f.sibling(t, "other-http", f.now)
	sibling.start(t, "other-http", f.now)
	prepareServingPublisher(t, sibling)
	d, ctx := f.database, t.Context()
	service, err := d.CreateServiceAt(ctx, f.service.TeamID, f.actor(t), "native", "native", ServicePlacement{}, f.now,
		ServiceMetadata{Protocol: "tcp"}, &ProjectServiceConfiguration{Protocol: "tcp", Target: "localhost:9000"})
	if err != nil {
		t.Fatal(err)
	}
	enrollment := publisherEnrollment(t, d, serviceTestAuthority{TeamID: service.TeamID, ActingIdentityID: f.actor(t)},
		PublisherScope{TeamID: service.TeamID, Kind: "service", ServiceID: service.ID}, f.now)
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	publisher, err := d.RedeemPublisherEnrollment(ctx, enrollment.Key, public, f.now)
	if err != nil {
		t.Fatal(err)
	}
	native := servicePublicationFixture{database: d, now: f.now, service: service, publisher: publisher, leases: f.leases}
	native.start(t, "native-run", f.now)
	prepareServingPublisher(t, native)
	assertAssignmentTotals(t, d.pool, 6)
	_, err = d.pool.Exec(ctx, `UPDATE control.service_connection_slots SET publisher_connection_id=$2
		WHERE service_run_id=$1 AND connection_slot=0`, native.run.RunID, f.run.Connections[0].PublisherConnectionID)
	var constraint *pgconn.PgError
	if !errors.As(err, &constraint) || constraint.Code != "23505" {
		t.Fatalf("connection identity reuse error=%v, want 23505", err)
	}
	if err := d.CloseServiceRun(ctx, native.service.ID, native.run.RunID, native.run.Token, f.now); err != nil {
		t.Fatal(err)
	}
	httpConnections := []string{f.run.Connections[0].PublisherConnectionID, f.run.Connections[1].PublisherConnectionID,
		sibling.run.Connections[0].PublisherConnectionID, sibling.run.Connections[1].PublisherConnectionID}
	var unrelatedReady, nativeOpen int
	if err := d.pool.QueryRow(ctx, `SELECT
		(SELECT count(*) FROM control.service_connection_slots WHERE publisher_connection_id=ANY($1::text[]) AND session_open AND state='ready'),
		(SELECT count(*) FROM control.service_connection_slots WHERE service_run_id=$2 AND session_open)`,
		httpConnections, native.run.RunID).Scan(&unrelatedReady, &nativeOpen); err != nil || unrelatedReady != 4 || nativeOpen != 0 {
		t.Fatalf("closed native/unrelated HTTP slots=%d/%d, want 0/4: %v", nativeOpen, unrelatedReady, err)
	}
	assertAssignmentTotals(t, d.pool, 4)
	for _, survivor := range []servicePublicationFixture{f, sibling} {
		state, err := d.HeartbeatServiceRun(ctx, survivor.service.ID, survivor.run.RunID, survivor.run.Token, f.now,
			ServiceRunHealth{Healthy: true, StreamCapacity: 64})
		if err != nil || state.State != "ready" {
			t.Fatal("native closure damaged an unrelated ready HTTP run", err)
		}
	}
}

func TestIntegrationServicePoolRestoredPublicSnapshotAndTerminalClosure(t *testing.T) {
	f := publicServingFixture(t, newServicePublicationFixture(t))
	d, ctx := f.database, t.Context()
	meta := f.service.ServiceMetadata
	meta.PublisherPool = true
	var err error
	f.service, err = d.ConfigureService(ctx, f.service.ID, f.actor(t), meta, nil, ServiceUpdateConditions{}, f.now)
	if err != nil {
		t.Fatal(err)
	}
	ingress := registerTestIngress(t, d, f.now)
	prepareServingPublisher(t, f)
	enrollment := publisherEnrollment(t, d, serviceTestAuthority{TeamID: f.service.TeamID, ActingIdentityID: f.actor(t)},
		PublisherScope{TeamID: f.service.TeamID, Kind: "service", ServiceID: f.service.ID}, f.now)
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	publisher, err := d.RedeemPublisherEnrollment(ctx, enrollment.Key, public, f.now)
	if err != nil {
		t.Fatal(err)
	}
	second := servicePublicationFixture{database: d, now: f.now, service: f.service, publisher: publisher, leases: f.leases}
	second.start(t, "second-publisher", f.now)
	prepareServingPublisher(t, second)
	checkSnapshot := func(want ...string) {
		t.Helper()
		snapshot, err := d.ReadIngressServices(ctx, ingress.IngressLeaseIdentity, f.now)
		if err != nil {
			t.Fatal(err)
		}
		got := map[string]bool{}
		for _, run := range snapshot.Runs {
			if run.ServiceID == f.service.ID {
				if run.RunID != f.run.RunID && run.RunID != second.run.RunID || len(run.Relays) != 2 {
					t.Fatal("pool snapshot changed an exact run or its two connected relays")
				}
				got[run.RunID] = true
			}
		}
		if len(got) != len(want) {
			t.Fatalf("pool snapshot runs=%v, want %v", got, want)
		}
		for _, id := range want {
			if !got[id] {
				t.Fatalf("pool snapshot omitted exact run %s", id)
			}
		}
	}
	checkSnapshot(f.run.RunID, second.run.RunID)
	if err := d.CloseServiceRun(ctx, f.service.ID, f.run.RunID, f.run.Token, f.now); err != nil {
		t.Fatal(err)
	}
	checkSnapshot(second.run.RunID)
	if err := d.RevokePublisherGrant(ctx, f.service.TeamID, second.publisher.ID, second.publisher.GrantID, f.actor(t), f.now); err != nil {
		t.Fatal(err)
	}
	checkSnapshot()
	var terminal bool
	if err := d.pool.QueryRow(ctx, `SELECT state='closed' AND closed_at IS NOT NULL AND NOT assignments_open
		FROM control.service_runs WHERE id=$1`, second.run.RunID).Scan(&terminal); err != nil || !terminal {
		t.Fatal("revoked pool publisher retained nonterminal run authority", err)
	}
}

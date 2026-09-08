package controlstate

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/controlstate/controlstatedb"
)

type retentionEvent struct {
	kind    IngressRoutingTableEventKind
	version int64
	age     time.Duration
	ttl     time.Duration
}

func seedRetentionEvents(t *testing.T, f routeSessionFixture, events []retentionEvent) []int64 {
	t.Helper()
	var revisions []int64
	for index, event := range events {
		projection := IngressRoutingTableProjection{RouteSessionID: f.setup.RouteSessionID, RouteID: f.setup.RouteID, RouteVersion: uint64(event.version), CanonicalHostname: f.request.CertificateIdentifiers[0], PolicyRevision: 1, RouteExpiresAt: f.now.Add(event.ttl)}
		payload, err := json.Marshal(projection)
		if err != nil {
			t.Fatal(err)
		}
		revision, err := controlstatedb.New(f.database.pool).InsertIngressRoutingTableEvent(t.Context(), controlstatedb.InsertIngressRoutingTableEventParams{
			EventKind: string(event.kind), RouteID: f.setup.RouteID, RouteVersion: event.version, CanonicalHostname: projection.CanonicalHostname,
			EntryRevision: int64(index + 1), Projection: payload, RouteExpiresAt: timestamptz(projection.RouteExpiresAt), CreatedAt: timestamptz(f.now.Add(-event.age)),
		})
		if err != nil {
			t.Fatal(err)
		}
		revisions = append(revisions, revision)
	}
	if _, err := f.database.pool.Exec(t.Context(), `UPDATE control.ingress_routing_table_clock SET current_revision = $1`, revisions[len(revisions)-1]); err != nil {
		t.Fatal(err)
	}
	return revisions
}

func TestIntegrationRoutingRetentionAnchorsAndBoundary(t *testing.T) {
	f := newRouteSessionFixture(t)
	old := time.Hour
	revisions := seedRetentionEvents(t, f, []retentionEvent{
		{IngressRouteUpsert, 1, old, time.Hour},
		{IngressChallengeUpsert, 1, old, time.Hour},
		{IngressRouteUpsert, 1, old, -time.Second},
		{IngressRouteTombstone, 2, old, -time.Second},
		{IngressChallengeTombstone, 2, old, -time.Second},
		{IngressRouteUpsert, 3, time.Minute, time.Hour},
		{IngressRouteUpsert, 3, old, time.Hour}, // Old timestamp after a recent revision.
		{IngressChallengeUpsert, 3, time.Minute, time.Hour},
	})
	ingress := registerTestIngress(t, f.database, f.now)
	before, err := f.database.ReadIngressRoutingTableSnapshot(t.Context(), ingress.IngressLeaseIdentity, f.now)
	if err != nil {
		t.Fatal(err)
	}
	floor, err := f.database.AdvanceIngressRoutingRetention(t.Context(), f.now.Add(-10*time.Minute))
	if err != nil || floor != uint64(revisions[5]-1) {
		t.Fatalf("floor=%d: %v", floor, err)
	}
	batch, err := f.database.PruneIngressRoutingHistory(t.Context(), 0)
	if err != nil || batch.Scanned != 5 || batch.Deleted != 3 || batch.More {
		t.Fatalf("batch=%+v: %v", batch, err)
	}
	after, err := f.database.ReadIngressRoutingTableSnapshot(t.Context(), ingress.IngressLeaseIdentity, f.now)
	if err != nil || !reflect.DeepEqual(before.Routes, after.Routes) || before.RoutingTableRevision != after.RoutingTableRevision {
		t.Fatalf("snapshot changed after pruning: %v", err)
	}
	for _, version := range []int64{1, 2, 3} {
		revision, err := controlstatedb.New(f.database.pool).LatestIngressRoutingEntryRevision(t.Context(), controlstatedb.LatestIngressRoutingEntryRevisionParams{RouteID: f.setup.RouteID, RouteVersion: version})
		want := map[int64]int64{1: 3, 2: 5, 3: 8}[version]
		if err != nil || revision != want {
			t.Fatalf("version %d latest=%d want=%d: %v", version, revision, want, err)
		}
	}
	for _, cursor := range []uint64{floor - 1, floor, floor + 1} {
		page, err := f.database.ReadIngressRoutingTableEvents(t.Context(), ingress.IngressLeaseIdentity, cursor, 100, f.now)
		if err != nil || page.ResnapshotRequired != (cursor < floor) {
			t.Fatalf("cursor=%d page=%+v: %v", cursor, page, err)
		}
		if cursor >= floor && len(page.Events) != int(uint64(revisions[7])-cursor) {
			t.Fatalf("incomplete retained suffix: %+v", page)
		}
	}
	// An older policy cutoff must not move the published floor backward.
	if again, err := f.database.AdvanceIngressRoutingRetention(t.Context(), f.now.Add(-2*time.Hour)); err != nil || again != floor {
		t.Fatalf("floor regressed: %d %v", again, err)
	}
}

func TestIntegrationRoutingRetentionReaderSnapshotsAndClock(t *testing.T) {
	f := newRouteSessionFixture(t)
	seedRetentionEvents(t, f, []retentionEvent{{IngressRouteUpsert, 1, time.Hour, time.Hour}, {IngressRouteTombstone, 1, time.Hour, 0}, {IngressChallengeUpsert, 1, time.Hour, -time.Second}})
	ctx := t.Context()
	reader, err := f.database.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		t.Fatal(err)
	}
	defer rollbackTestTransaction(t, reader)
	oldClock, err := controlstatedb.New(reader).ReadIngressRoutingTableClock(ctx)
	if err != nil {
		t.Fatal(err)
	}
	floor, err := f.database.AdvanceIngressRoutingRetention(ctx, f.now)
	if err != nil || floor != uint64(oldClock.CurrentRevision) {
		t.Fatalf("floor %d: %v", floor, err)
	}
	between, err := f.database.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		t.Fatal(err)
	}
	defer rollbackTestTransaction(t, between)
	newClock, err := controlstatedb.New(between).ReadIngressRoutingTableClock(ctx)
	if err != nil || newClock.RetainedAfterRevision != int64(floor) {
		t.Fatalf("floor not committed before delete: %v", err)
	}
	gate, err := f.database.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer rollbackTestTransaction(t, gate)
	if _, err := controlstatedb.New(gate).LockIngressRoutingTableClock(ctx); err != nil {
		t.Fatal(err)
	}
	callCtx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	batch, err := f.database.PruneIngressRoutingHistory(callCtx, 0)
	if err != nil || batch.Deleted != 1 {
		t.Fatalf("pruning waited for the publication clock: %+v %v", batch, err)
	}
	for _, tx := range []pgx.Tx{reader, between} {
		var count int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM control.ingress_routing_table_events`).Scan(&count); err != nil || count != 3 {
			t.Fatalf("reader lost repeatable history: %d %v", count, err)
		}
		entries, err := controlstatedb.New(tx).ListIngressRoutingTableSnapshot(ctx, controlstatedb.ListIngressRoutingTableSnapshotParams{Now: timestamptz(f.now), ThroughRevision: int64(floor)})
		if err != nil || len(entries) != 0 {
			t.Fatalf("tombstone/expiration resurrected an entry: %v", err)
		}
	}
	entries, err := controlstatedb.New(f.database.pool).ListIngressRoutingTableSnapshot(ctx, controlstatedb.ListIngressRoutingTableSnapshotParams{Now: timestamptz(f.now), ThroughRevision: int64(floor)})
	if err != nil || len(entries) != 0 {
		t.Fatalf("pruned snapshot resurrected an entry: %v", err)
	}
}

func TestIntegrationRoutingRetentionCancellationAndGuard(t *testing.T) {
	f := newRouteSessionFixture(t)
	revisions := seedRetentionEvents(t, f, []retentionEvent{{IngressRouteUpsert, 1, time.Hour, time.Hour}, {IngressRouteUpsert, 1, time.Hour, time.Hour}})
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	if _, err := f.database.AdvanceIngressRoutingRetention(ctx, f.now); err != nil {
		t.Fatal(err)
	}
	gate, err := f.database.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer rollbackTestTransaction(t, gate)
	if locked, err := controlstatedb.New(gate).TryLockIngressRoutingHistoryCleanup(ctx); err != nil || !locked {
		t.Fatal(err)
	}
	if batch, err := f.database.PruneIngressRoutingHistory(ctx, 0); err != nil || !batch.Busy || batch.Deleted != 0 {
		t.Fatalf("second cleanup did not skip: %+v %v", batch, err)
	}
	if err := gate.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	gate, err = f.database.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer rollbackTestTransaction(t, gate)
	if _, err := gate.Exec(ctx, `SELECT routing_table_revision FROM control.ingress_routing_table_events WHERE routing_table_revision = $1 FOR UPDATE`, revisions[0]); err != nil {
		t.Fatal(err)
	}
	operation, stop := context.WithCancel(ctx)
	workers := newIntegrationWorkers(t, stop)
	defer workers.stop()
	done := make(chan error, 1)
	workers.Go(func() { _, err := f.database.PruneIngressRoutingHistory(operation, 0); done <- err })
	waitForPostgresBlock(t, ctx, f.database, int32(gate.Conn().PgConn().PID()), done)
	stop()
	if err := awaitIntegrationResult(t, ctx, done); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancel=%v", err)
	}
	var count int
	if err := f.database.pool.QueryRow(ctx, `SELECT count(*) FROM control.ingress_routing_table_events`).Scan(&count); err != nil || count != 2 {
		t.Fatalf("canceled deletion persisted: %d %v", count, err)
	}
	if err := gate.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	if batch, err := f.database.PruneIngressRoutingHistory(ctx, 0); err != nil || batch.Deleted != 1 {
		t.Fatalf("retry: %+v %v", batch, err)
	}
}

func TestIntegrationRoutingRetentionBoundsScannedAnchors(t *testing.T) {
	f := newRouteSessionFixture(t)
	// Different route versions each need their own latest entry-revision anchor.
	if _, err := f.database.pool.Exec(t.Context(), `INSERT INTO control.ingress_routing_table_events
		(event_kind, route_id, route_version, canonical_hostname, entry_revision, projection, created_at)
		SELECT 'route_tombstone', $1, n, $2, 1, '{}'::bytea, $3 FROM generate_series(1, 2001) AS n`, f.setup.RouteID, f.request.CertificateIdentifiers[0], f.now.Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, err := f.database.pool.Exec(t.Context(), `UPDATE control.ingress_routing_table_clock SET current_revision = (SELECT max(routing_table_revision) FROM control.ingress_routing_table_events)`); err != nil {
		t.Fatal(err)
	}
	if _, err := f.database.AdvanceIngressRoutingRetention(t.Context(), f.now); err != nil {
		t.Fatal(err)
	}
	var cursor uint64
	for index, want := range []int64{1000, 1000, 1} {
		batch, err := f.database.PruneIngressRoutingHistory(t.Context(), cursor)
		if err != nil || batch.Scanned != want || batch.Deleted != 0 || batch.More != (index < 2) || batch.NextRevision <= cursor {
			t.Fatalf("batch=%+v: %v", batch, err)
		}
		cursor = batch.NextRevision
	}
}

func TestIntegrationRoutingRetentionRevisionGap(t *testing.T) {
	f := newRouteSessionFixture(t)
	seedRetentionEvents(t, f, []retentionEvent{{IngressRouteUpsert, 1, time.Hour, time.Hour}})
	tx, err := f.database.pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer rollbackTestTransaction(t, tx)
	if _, err := tx.Exec(t.Context(), `INSERT INTO control.ingress_routing_table_events (event_kind,route_id,route_version,canonical_hostname,entry_revision,projection,route_expires_at,created_at)
		SELECT event_kind,route_id,route_version,canonical_hostname,entry_revision+1,projection,route_expires_at,created_at FROM control.ingress_routing_table_events`); err != nil {
		t.Fatal(err)
	}
	if err := tx.Rollback(t.Context()); err != nil {
		t.Fatal(err)
	}
	recent := seedRetentionEvents(t, f, []retentionEvent{{IngressRouteUpsert, 2, time.Minute, time.Hour}})
	if recent[0] != 3 {
		t.Fatalf("missing rollback gap: %v", recent)
	}
	floor, err := f.database.AdvanceIngressRoutingRetention(t.Context(), f.now.Add(-10*time.Minute))
	if err != nil || floor != 2 {
		t.Fatalf("floor at gap=%d: %v", floor, err)
	}
	if _, err := f.database.PruneIngressRoutingHistory(t.Context(), 0); err != nil {
		t.Fatal(err)
	}
	ingress := registerTestIngress(t, f.database, f.now)
	page, err := f.database.ReadIngressRoutingTableEvents(t.Context(), ingress.IngressLeaseIdentity, floor, 10, f.now)
	if err != nil || page.ResnapshotRequired || len(page.Events) != 1 || page.NextRevision != 3 || page.More {
		t.Fatalf("gap boundary page=%+v: %v", page, err)
	}
}

func TestIntegrationRoutingRetentionContinuesPublishing(t *testing.T) {
	f := newRouteSessionFixture(t)
	database, now := f.database, f.now
	ingress := registerTestIngress(t, database, now)
	readyTestSession(t, f)
	for step := 1; step <= 2; step++ {
		if _, err := database.HeartbeatRouteSession(t.Context(), f.authentication(), now.Add(time.Duration(step)*time.Second), time.Minute, time.Minute); err != nil {
			t.Fatal(err)
		}
	}
	queries := controlstatedb.New(database.pool)
	key := controlstatedb.LatestIngressRoutingEntryRevisionParams{RouteID: f.setup.RouteID, RouteVersion: int64(f.setup.RouteVersion)}
	previous, err := queries.LatestIngressRoutingEntryRevision(t.Context(), key)
	if err != nil {
		t.Fatal(err)
	}
	// Age genuine projections without expiring the session or its connections.
	if _, err := database.pool.Exec(t.Context(), `UPDATE control.ingress_routing_table_events SET created_at = $1`, now.Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	floor, err := database.AdvanceIngressRoutingRetention(t.Context(), now.Add(-10*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if batch, err := database.PruneIngressRoutingHistory(t.Context(), 0); err != nil || batch.Deleted < 2 {
		t.Fatalf("prune genuine heartbeat history: %+v, %v", batch, err)
	}
	if _, err := database.HeartbeatRouteSession(t.Context(), f.authentication(), now.Add(3*time.Second), time.Minute, time.Minute); err != nil {
		t.Fatal(err)
	}
	if revision, err := queries.LatestIngressRoutingEntryRevision(t.Context(), key); err != nil || revision != previous+1 {
		t.Fatalf("post-pruning heartbeat entry revision = %d, want %d: %v", revision, previous+1, err)
	}
	if err := database.CloseRouteSession(t.Context(), f.setup.RouteSessionID, f.setup.RouteSessionToken, now.Add(4*time.Second)); err != nil {
		t.Fatal(err)
	}
	page, err := database.ReadIngressRoutingTableEvents(t.Context(), ingress.IngressLeaseIdentity, floor, 10, now.Add(4*time.Second))
	if err != nil || page.ResnapshotRequired || len(page.Events) != 2 || page.Events[1].Kind != IngressRouteTombstone {
		t.Fatalf("post-pruning publication suffix: %+v, %v", page, err)
	}
	if _, err := database.AdvanceIngressRoutingRetention(t.Context(), now.Add(5*time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := database.PruneIngressRoutingHistory(t.Context(), 0); err != nil {
		t.Fatal(err)
	}
	snapshot, err := database.ReadIngressRoutingTableSnapshot(t.Context(), ingress.IngressLeaseIdentity, now.Add(5*time.Second))
	if err != nil || len(snapshot.Routes) != 0 {
		t.Fatalf("closed route resurrected after pruning: %v", err)
	}
	f.now = now.Add(6 * time.Second)
	f.request.IdempotencyKey = "retention-republish"
	var issuanceID string
	var notAfter time.Time
	if err := database.pool.QueryRow(t.Context(), `SELECT id, not_after FROM control.acme_orders WHERE route_session_id = $1 AND state = 'installed'`, f.setup.RouteSessionID).Scan(&issuanceID, &notAfter); err != nil {
		t.Fatal(err)
	}
	if err := database.pool.QueryRow(t.Context(), `SELECT mutation_revision FROM control.routes WHERE id = $1`, f.request.RouteID).Scan(&f.request.ExpectedMutationRevision); err != nil {
		t.Fatal(err)
	}
	f.setup, err = database.CreateRouteSession(t.Context(), f.request, f.now, time.Minute, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.MarkRouteCertificateInstalled(t.Context(), f.authentication(), issuanceID, notAfter, f.now); err != nil {
		t.Fatal(err)
	}
	for slot := range f.setup.PublisherConnections {
		claimTestConnection(t, f, slot, f.now)
	}
	if _, err := database.MarkRouteSessionReady(t.Context(), f.authentication(), f.now); err != nil {
		t.Fatal(err)
	}
	snapshot, err = database.ReadIngressRoutingTableSnapshot(t.Context(), ingress.IngressLeaseIdentity, f.now)
	if err != nil || len(snapshot.Routes) != 1 || snapshot.Routes[0].RouteVersion != f.setup.RouteVersion || f.setup.RouteVersion <= uint64(key.RouteVersion) {
		t.Fatalf("republished hostname did not select the new route version: %v", err)
	}
	if revision, err := queries.LatestIngressRoutingEntryRevision(t.Context(), key); err != nil || revision != previous+2 {
		t.Fatalf("old version lost its tombstone anchor: revision %d, want %d: %v", revision, previous+2, err)
	}
}

package state

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
)

// routing history no longer serves authority. these selectors retain the
// underlying expiry, committed-read, cancellation, bounds, and replacement proofs
// against durable service-run tuples.
func TestIntegrationRoutingRetentionAnchorsAndBoundary(t *testing.T) {
	f := newServicePublicationFixture(t)
	ingress := registerTestIngress(t, f.database, f.now)
	old := ServiceRunReference{ServiceID: f.service.ID, RunID: f.run.RunID, RunNumber: f.run.RunNumber}
	if err := f.database.CloseServiceRun(t.Context(), f.service.ID, f.run.RunID, f.run.Token, f.now); err != nil {
		t.Fatal(err)
	}
	f.start(t, "next", f.now.Add(time.Second))
	current := ServiceRunReference{ServiceID: f.service.ID, RunID: f.run.RunID, RunNumber: f.run.RunNumber}
	boundary := f.now.Add(2 * time.Second)
	if _, err := f.database.pool.Exec(t.Context(), `UPDATE control.service_runs SET publisher_expires_at=$2 WHERE id=$1`, current.RunID, boundary); err != nil {
		t.Fatal(err)
	}
	refs := []ServiceRunReference{old, current}
	before, err := f.database.ClosedServiceRuns(t.Context(), ingress.IngressLeaseIdentity, refs, boundary)
	if err != nil || !reflect.DeepEqual(before, []ServiceRunReference{old}) {
		t.Fatal("expiration alone was mistaken for committed closure", before, err)
	}
	if count, err := f.database.ExpireServiceRuns(t.Context(), boundary); err != nil || count != 1 {
		t.Fatalf("expiry boundary closed %d runs, want one: %v", count, err)
	}
	after, err := f.database.ClosedServiceRuns(t.Context(), ingress.IngressLeaseIdentity, refs, boundary)
	if err != nil || len(after) != 2 {
		t.Fatal("cleanup lost a durable terminal tuple", after, err)
	}
	for _, ref := range after {
		if ref != old && ref != current {
			t.Fatal("cleanup invented another terminal tuple", ref)
		}
	}
	if count, err := f.database.ExpireServiceRuns(t.Context(), boundary.Add(time.Second)); err != nil || count != 0 {
		t.Fatalf("repeated cleanup settled a run twice: %d %v", count, err)
	}
}

func TestIntegrationRoutingRetentionReaderSnapshotsAndClock(t *testing.T) {
	f := newServicePublicationFixture(t)
	ingress := registerTestIngress(t, f.database, f.now)
	ctx := t.Context()
	reader, err := f.database.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Rollback(ctx)
	var open bool
	if err := reader.QueryRow(ctx, `SELECT closed_at IS NULL FROM control.service_runs WHERE id=$1`, f.run.RunID).Scan(&open); err != nil || !open {
		t.Fatal("reader did not capture the live run", err)
	}
	if err := f.database.CloseServiceRun(ctx, f.service.ID, f.run.RunID, f.run.Token, f.now); err != nil {
		t.Fatal(err)
	}
	if err := reader.QueryRow(ctx, `SELECT closed_at IS NULL FROM control.service_runs WHERE id=$1`, f.run.RunID).Scan(&open); err != nil || !open {
		t.Fatal("a committed close changed an existing reader snapshot", err)
	}
	ref := ServiceRunReference{ServiceID: f.service.ID, RunID: f.run.RunID, RunNumber: f.run.RunNumber}
	closed, err := f.database.ClosedServiceRuns(ctx, ingress.IngressLeaseIdentity, []ServiceRunReference{ref}, f.now)
	if err != nil || !reflect.DeepEqual(closed, []ServiceRunReference{ref}) {
		t.Fatal("a fresh reader missed committed terminal state", closed, err)
	}
}

func TestIntegrationRoutingRetentionCancellationAndGuard(t *testing.T) {
	f := newServicePublicationFixture(t)
	ingress := registerTestIngress(t, f.database, f.now)
	if err := f.database.CloseServiceRun(t.Context(), f.service.ID, f.run.RunID, f.run.Token, f.now); err != nil {
		t.Fatal(err)
	}
	ref := ServiceRunReference{ServiceID: f.service.ID, RunID: f.run.RunID, RunNumber: f.run.RunNumber}
	ctx, finish := context.WithTimeout(t.Context(), 5*time.Second)
	defer finish()
	gate, err := f.database.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer gate.Rollback(ctx)
	if _, err := gate.Exec(ctx, `SELECT ingress_id FROM control.ingress_leases WHERE ingress_id=$1 FOR UPDATE`, ingress.IngressID); err != nil {
		t.Fatal(err)
	}
	operation, cancel := context.WithCancel(ctx)
	workers := newIntegrationWorkers(t, cancel)
	defer workers.stop()
	done := make(chan error, 1)
	workers.Go(func() {
		_, err := f.database.ClosedServiceRuns(operation, ingress.IngressLeaseIdentity, []ServiceRunReference{ref}, f.now)
		done <- err
	})
	waitForPostgresBlock(t, ctx, f.database, int32(gate.Conn().PgConn().PID()), done)
	cancel()
	if err := awaitIntegrationResult(t, ctx, done); !errors.Is(err, context.Canceled) {
		t.Fatal("blocked terminal-state read ignored cancellation", err)
	}
	if err := gate.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	closed, err := f.database.ClosedServiceRuns(ctx, ingress.IngressLeaseIdentity, []ServiceRunReference{ref}, f.now)
	if err != nil || !reflect.DeepEqual(closed, []ServiceRunReference{ref}) {
		t.Fatal("canceled read damaged terminal state or retained its lock", closed, err)
	}
	stale := ingress.IngressLeaseIdentity
	stale.IngressLeaseRevision++
	if _, err := f.database.ClosedServiceRuns(ctx, stale, []ServiceRunReference{ref}, f.now); !errors.Is(err, ErrIngressLeaseStale) {
		t.Fatal("stale ingress received terminal-state authority", err)
	}
}

func TestIntegrationRoutingRetentionBoundsScannedAnchors(t *testing.T) {
	f := newServicePublicationFixture(t)
	ingress := registerTestIngress(t, f.database, f.now)
	if err := f.database.CloseServiceRun(t.Context(), f.service.ID, f.run.RunID, f.run.Token, f.now); err != nil {
		t.Fatal(err)
	}
	ref := ServiceRunReference{ServiceID: f.service.ID, RunID: f.run.RunID, RunNumber: f.run.RunNumber}
	refs := []ServiceRunReference{ref}
	for index := 1; index < 128; index++ {
		refs = append(refs, ServiceRunReference{ServiceID: f.service.ID,
			RunID: mustOpaqueID(t, opaqueid.ServiceRunPrefix), RunNumber: int64(index + 1)})
	}
	closed, err := f.database.ClosedServiceRuns(t.Context(), ingress.IngressLeaseIdentity, refs, f.now)
	if err != nil || !reflect.DeepEqual(closed, []ServiceRunReference{ref}) {
		t.Fatal("the maximum bounded request lost its terminal tuple", closed, err)
	}
	for _, invalid := range [][]ServiceRunReference{
		nil, {ref, ref}, append(refs, ServiceRunReference{ServiceID: f.service.ID,
			RunID: mustOpaqueID(t, opaqueid.ServiceRunPrefix), RunNumber: 129}),
		{{ServiceID: ref.ServiceID, RunID: ref.RunID, RunNumber: 0}},
	} {
		if _, err := f.database.ClosedServiceRuns(t.Context(), ingress.IngressLeaseIdentity, invalid, f.now); !errors.Is(err, ErrServiceAccess) {
			t.Fatal("unbounded, repeated, or invalid terminal-state request was accepted", err)
		}
	}
}

func TestIntegrationRoutingRetentionRevisionGap(t *testing.T) {
	f := newServicePublicationFixture(t)
	ingress := registerTestIngress(t, f.database, f.now)
	ref := ServiceRunReference{ServiceID: f.service.ID, RunID: f.run.RunID, RunNumber: f.run.RunNumber}
	tx, err := f.database.pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(t.Context())
	if _, err := tx.Exec(t.Context(), `UPDATE control.service_runs SET state='closed',closed_at=$2 WHERE id=$1`, ref.RunID, f.now); err != nil {
		t.Fatal(err)
	}
	closed, err := f.database.ClosedServiceRuns(t.Context(), ingress.IngressLeaseIdentity, []ServiceRunReference{ref}, f.now)
	if err != nil || len(closed) != 0 {
		t.Fatal("an uncommitted closure became terminal evidence", closed, err)
	}
	if err := tx.Rollback(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := f.database.CloseServiceRun(t.Context(), f.service.ID, f.run.RunID, f.run.Token, f.now); err != nil {
		t.Fatal(err)
	}
	wrong := ref
	wrong.RunNumber++
	missing := ref
	missing.RunID = mustOpaqueID(t, opaqueid.ServiceRunPrefix)
	closed, err = f.database.ClosedServiceRuns(t.Context(), ingress.IngressLeaseIdentity, []ServiceRunReference{ref, wrong, missing}, f.now)
	if err != nil || !reflect.DeepEqual(closed, []ServiceRunReference{ref}) {
		t.Fatal("terminal proof was inferred from a missing or mismatched tuple", closed, err)
	}
}

func TestIntegrationRoutingRetentionContinuesPublishing(t *testing.T) {
	f := newServicePublicationFixture(t)
	ingress := registerTestIngress(t, f.database, f.now)
	old := ServiceRunReference{ServiceID: f.service.ID, RunID: f.run.RunID, RunNumber: f.run.RunNumber}
	installPrivateTestCertificate(t, f.database, f.prepared, f.run, f.now)
	f.readyConnections(t, f.now)
	for step := range 3 {
		ready, err := f.database.HeartbeatServiceRun(t.Context(), f.service.ID, f.run.RunID, f.run.Token,
			f.now.Add(time.Duration(step)*time.Second), ServiceRunHealth{Healthy: true, StreamCapacity: 64})
		if err != nil || ready.State != "ready" || ready.RunID != old.RunID || ready.RunNumber != old.RunNumber ||
			step != 0 && !reflect.DeepEqual(ready.Connections, f.run.Connections) {
			t.Fatal("heartbeat changed the current run or its slots", ready, err)
		}
		f.run.Connections = ready.Connections
	}
	if err := f.database.CloseServiceRun(t.Context(), f.service.ID, f.run.RunID, f.run.Token, f.now.Add(3*time.Second)); err != nil {
		t.Fatal(err)
	}
	at := f.now.Add(4 * time.Second)
	f.start(t, "republished", at)
	installPrivateTestCertificate(t, f.database, f.prepared, f.run, at)
	f.readyConnections(t, at)
	if _, err := f.database.HeartbeatServiceRun(t.Context(), f.service.ID, f.run.RunID, f.run.Token, at, ServiceRunHealth{Healthy: true, StreamCapacity: 64}); err != nil {
		t.Fatal(err)
	}
	current := ServiceRunReference{ServiceID: f.service.ID, RunID: f.run.RunID, RunNumber: f.run.RunNumber}
	if current.RunID == old.RunID || current.RunNumber <= old.RunNumber {
		t.Fatal("republishing reused the terminal tuple")
	}
	closed, err := f.database.ClosedServiceRuns(t.Context(), ingress.IngressLeaseIdentity, []ServiceRunReference{old, current}, at)
	if err != nil || !reflect.DeepEqual(closed, []ServiceRunReference{old}) {
		t.Fatal("a new run erased old closure or inherited its terminal state", closed, err)
	}
	tx, err := f.database.pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(t.Context())
	id, number, _, err := selectRoutableServiceRun(t.Context(), tx, f.service.ID, f.prepared.Hostname, at)
	if err != nil || id != current.RunID || number != current.RunNumber {
		t.Fatal("republishing selected the old closed run", id, number, err)
	}
}

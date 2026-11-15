package state

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestIntegrationExpiredPublishRunReleasesPlacementForOtherPublicURL(t *testing.T) {
	f := newServicePublicationFixture(t)
	d, now := f.database, f.now
	other := f.sibling(t, "other", now)
	if _, err := d.pool.Exec(t.Context(), `UPDATE control.relay_leases SET connection_capacity=1`); err != nil {
		t.Fatal(err)
	}
	prepared, err := d.PrepareServiceRun(t.Context(), other.service.ID, other.publisher, "first", now,
		ServiceRunRequest{Metadata: other.service.ServiceMetadata})
	if err != nil {
		t.Fatal(err)
	}
	assertAssignmentTotals(t, d.pool, 2)
	if _, err := d.StartServiceRun(t.Context(), other.service.ID, prepared.RunID, prepared.RunNumber, other.publisher,
		now.Add(time.Second)); !errors.Is(err, ErrInsufficientRelayServices) {
		t.Fatal("live run did not retain its placement reservations", err)
	}
	// cleanup does not require another request for the departed publisher.
	later := f.run.ExpiresAt
	if count, err := d.ExpireServiceRuns(t.Context(), later); err != nil || count != 1 {
		t.Fatal("expired publisher did not release relay reservations", count, err)
	}
	if _, err := d.StartServiceRun(t.Context(), other.service.ID, prepared.RunID, prepared.RunNumber, other.publisher, later); err != nil {
		t.Fatal("expired publisher exhausted unrelated service placement", err)
	}
	assertAssignmentTotals(t, d.pool, 2)
	var closed bool
	if err := d.pool.QueryRow(t.Context(), `SELECT state='closed' AND closed_at>=publisher_expires_at AND NOT assignments_open
		FROM control.service_runs WHERE id=$1`, f.run.RunID).Scan(&closed); err != nil || !closed {
		t.Fatal("expired run retained publication authority", err)
	}
}

func TestIntegrationExpireSavedPublishRunsPublishesTombstones(t *testing.T) {
	f := publicServingFixture(t, newServicePublicationFixture(t))
	prepareServingPublisher(t, f)
	owner := registerServingIngress(t, f, "expiry", f.now)
	if _, err := admitServingVisitor(t, f, owner, f.now); err != nil {
		t.Fatal(err)
	}
	assertAssignmentTotals(t, f.database.pool, 2)
	at := f.run.ExpiresAt
	if count, err := f.database.ExpireServiceRuns(t.Context(), at); err != nil || count != 1 {
		t.Fatal("idle publisher cleanup failed", count, err)
	}
	assertAssignmentTotals(t, f.database.pool, 0)
	var closed bool
	if err := f.database.pool.QueryRow(t.Context(), `SELECT state='closed' AND closed_at>=publisher_expires_at
		AND (SELECT count(*)=2 FROM control.service_connection_slots WHERE service_run_id=$1 AND NOT session_open)
		FROM control.service_runs WHERE id=$1`, f.run.RunID).Scan(&closed); err != nil || !closed {
		t.Fatal("expiry retained run or connection authority", err)
	}
	if _, err := admitServingVisitor(t, f, owner, at); !errors.Is(err, ErrServiceAccess) {
		t.Fatal("expired run remained available to public admission", err)
	}
	if count, err := f.database.ExpireServiceRuns(t.Context(), at.Add(time.Second)); err != nil || count != 0 {
		t.Fatal("repeated cleanup changed already-closed state", count, err)
	}
}

func TestIntegrationExpireSavedPublishRunsSkipsLockedPublicURL(t *testing.T) {
	f := newServicePublicationFixture(t)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	gate, err := f.database.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer rollbackTestTransaction(t, gate)
	if _, err := gate.Exec(ctx, `SELECT id FROM control.services WHERE id=$1 FOR UPDATE`, f.service.ID); err != nil {
		t.Fatal(err)
	}
	workers := newIntegrationWorkers(t, cancel)
	defer workers.stop()
	done := make(chan error, 1)
	workers.Go(func() {
		count, err := f.database.ExpireServiceRuns(ctx, f.run.ExpiresAt)
		if err == nil && count != 1 {
			err = errors.New("unlocked expired service run was not closed")
		}
		done <- err
	})
	waitForPostgresBlock(t, ctx, f.database, int32(gate.Conn().PgConn().PID()), done)
	if err := gate.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err := awaitIntegrationResult(t, ctx, done); err != nil {
		t.Fatal(err)
	}
}

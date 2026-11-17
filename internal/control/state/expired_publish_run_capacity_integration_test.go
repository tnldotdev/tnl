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
	later := now.Add(45 * time.Second)
	setExpirationProgressServingDeadline(t, &f, later)
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
	if count, err := d.ExpireServiceRuns(t.Context(), later); err != nil || count != 1 {
		t.Fatal("expired publisher did not release relay reservations", count, err)
	}
	if _, err := d.StartServiceRun(t.Context(), other.service.ID, prepared.RunID, prepared.RunNumber, other.publisher, later); err != nil {
		t.Fatal("expired publisher exhausted unrelated service placement", err)
	}
	assertAssignmentTotals(t, d.pool, 2)
	var closed bool
	if err := d.pool.QueryRow(t.Context(), `SELECT state='closed' AND closed_at>=publisher_expires_at AND closed_at>=serving_until AND NOT assignments_open
		FROM control.service_runs WHERE id=$1`, f.run.RunID).Scan(&closed); err != nil || !closed {
		t.Fatal("expired run retained publication authority", err)
	}
}

func TestIntegrationExpireSavedPublishRunsPublishesTombstones(t *testing.T) {
	f := publicServingFixture(t, newServicePublicationFixture(t))
	prepareServingPublisher(t, f)
	at := f.now.Add(45 * time.Second)
	setExpirationProgressServingDeadline(t, &f, at)
	owner := registerServingIngress(t, f, "expiry", f.now)
	if _, err := readServingRun(t, f, owner, f.now); err != nil {
		t.Fatal(err)
	}
	assertAssignmentTotals(t, f.database.pool, 2)
	ref := ServiceRunReference{ServiceID: f.service.ID, RunID: f.run.RunID, RunNumber: f.run.RunNumber}
	if closed, err := f.database.ClosedServiceRuns(t.Context(), owner, []ServiceRunReference{ref}, at); err != nil || len(closed) != 0 {
		t.Fatal("serving expiry alone invented a committed tombstone", closed, err)
	}
	if count, err := f.database.ExpireServiceRuns(t.Context(), at); err != nil || count != 1 {
		t.Fatal("idle publisher cleanup failed", count, err)
	}
	assertAssignmentTotals(t, f.database.pool, 0)
	var closed bool
	if err := f.database.pool.QueryRow(t.Context(), `SELECT state='closed' AND closed_at>=publisher_expires_at AND closed_at>=serving_until
		AND (SELECT count(*)=2 FROM control.service_connection_slots WHERE service_run_id=$1 AND NOT session_open)
		FROM control.service_runs WHERE id=$1`, f.run.RunID).Scan(&closed); err != nil || !closed {
		t.Fatal("expiry retained run or connection authority", err)
	}
	if closed, err := f.database.ClosedServiceRuns(t.Context(), owner, []ServiceRunReference{ref}, at); err != nil || len(closed) != 1 || closed[0] != ref {
		t.Fatal("cleanup did not retain the exact committed tombstone", closed, err)
	}
	if _, err := readServingRun(t, f, owner, at); !errors.Is(err, ErrServiceAccess) {
		t.Fatal("expired run remained available to public admission", err)
	}
	if count, err := f.database.ExpireServiceRuns(t.Context(), at.Add(time.Second)); err != nil || count != 0 {
		t.Fatal("repeated cleanup changed already-closed state", count, err)
	}
}

func TestIntegrationExpireSavedPublishRunsSkipsLockedPublicURL(t *testing.T) {
	for _, boundary := range []string{"service", "run"} {
		t.Run(boundary, func(t *testing.T) {
			f := newServicePublicationFixture(t)
			at := f.now.Add(45 * time.Second)
			setExpirationProgressServingDeadline(t, &f, at)
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			gate, err := f.database.pool.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer rollbackTestTransaction(t, gate)
			if boundary == "service" {
				_, err = gate.Exec(ctx, `SELECT id FROM control.services WHERE id=$1 FOR UPDATE`, f.service.ID)
			} else {
				_, err = gate.Exec(ctx, `SELECT id FROM control.service_runs WHERE id=$1 FOR UPDATE`, f.run.RunID)
			}
			if err != nil {
				t.Fatal(err)
			}
			before := expirationProgressSnapshot(t, ctx, f.database, f.run.RunID)
			if count, err := f.database.ExpireServiceRuns(ctx, at); err != nil || count != 0 {
				t.Fatal("locked publication was not skipped within its original caller", count, err)
			}
			if after := expirationProgressSnapshot(t, ctx, f.database, f.run.RunID); after != before {
				t.Fatal("skipping changed the busy run, slots, audit or recovery episode")
			}
			assertAssignmentTotals(t, f.database.pool, 2)
			if err := gate.Commit(ctx); err != nil {
				t.Fatal(err)
			}
			if count, err := f.database.ExpireServiceRuns(ctx, at); err != nil || count != 1 {
				t.Fatal("unlocked expired service run was not closed within the same five-second caller", count, err)
			}
			assertExpirationProgressClosed(t, ctx, f.database, f.run.RunID)
			assertAssignmentTotals(t, f.database.pool, 0)
		})
	}
}

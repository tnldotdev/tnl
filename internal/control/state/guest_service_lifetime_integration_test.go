package state

import (
	"context"
	"crypto/ed25519"
	"errors"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
)

func TestIntegrationGuestAuthorityStartsAtReadinessAndSettlesIssuedIdleTail(t *testing.T) {
	f, _ := guestAuthorityFixture(t, false)
	before := f.stored(t)
	if before.UsedReadyNs != 0 || before.ActiveReadyAt.Valid || before.ReadyDeadline.Valid || before.ServingUntil.Valid {
		t.Fatalf("preparation charged ready time: %+v", before)
	}
	f.ready(t, f.now.Add(10*time.Second))
	ready := f.stored(t)
	if !ready.ReadyDeadline.Time.Equal(ready.ActiveReadyAt.Time.Add(GuestReadyAllowance)) || !ready.ServingUntil.Time.Equal(f.run.ServingUntil) {
		t.Fatalf("readiness bounds: %+v", ready)
	}
	if err := f.database.CloseServiceRun(f.ctx, f.service.ID, f.run.RunID, f.run.Token, f.now.Add(11*time.Second)); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		_ = f.database.CloseServiceRun(f.ctx, f.service.ID, f.run.RunID, f.run.Token, f.now.Add(12*time.Second))
	}
	after := f.stored(t)
	want := ready.ServingUntil.Time.Sub(ready.ActiveReadyAt.Time)
	if time.Duration(after.UsedReadyNs) != want || after.ActiveServiceRunID.Valid || !after.ServingUntil.Time.Equal(ready.ServingUntil.Time) {
		t.Fatalf("issued idle tail was not charged once: got %+v, want %s", after, want)
	}
}

func TestIntegrationGuestAuthorityCumulativeBudgetAndOfflineReplacement(t *testing.T) {
	f, guest := guestAuthorityFixture(t, true)
	first := f.stored(t)
	for elapsed := 30 * time.Second; elapsed <= 6*time.Minute+15*time.Second; elapsed += 15 * time.Second {
		if _, err := f.heartbeat(f.now.Add(elapsed)); err != nil {
			t.Fatal(err)
		}
	}
	issued := f.stored(t)
	if err := f.database.CloseServiceRun(f.ctx, f.service.ID, f.run.RunID, f.run.Token, f.now.Add(6*time.Minute+16*time.Second)); err != nil {
		t.Fatal(err)
	}
	settled := f.stored(t)
	spent := issued.ServingUntil.Time.Sub(first.ActiveReadyAt.Time)
	if time.Duration(settled.UsedReadyNs) != spent {
		t.Fatalf("first settlement = %d, want %s", settled.UsedReadyNs, spent)
	}
	overlapAt := issued.ServingUntil.Time.Add(-time.Second)
	if _, err := f.database.PrepareServiceRun(f.ctx, f.service.ID, f.publisher, "overlap", overlapAt, ServiceRunRequest{Metadata: f.service.ServiceMetadata}); err == nil {
		t.Fatal("replacement overlapped outstanding serving authority")
	}
	if err := f.database.DeleteGuestService(t.Context(), f.service.ID, guestCredentialForTest(guest), overlapAt); err != nil {
		t.Fatal(err)
	}
	request := f.allocation
	request.IdempotencyKey, request.Now = "next", overlapAt
	if _, err := f.database.AllocateGuestDemoService(t.Context(), request); !errors.Is(err, ErrServiceConflict) {
		t.Fatalf("another demo reused outstanding authority: %v", err)
	}
	request.Now = issued.ServingUntil.Time.Add(time.Second)
	var err error
	f.service, err = f.database.AllocateGuestDemoService(t.Context(), request)
	if err != nil {
		t.Fatal(err)
	}
	f.publisher, err = f.database.EnrollGuestPublisher(t.Context(), guestCredentialForTest(guest), f.service.ID, f.private.Public().(ed25519.PublicKey), request.Now)
	if err != nil {
		t.Fatal(err)
	}
	f.prepareAndStart(t, "restart", request.Now)
	f.ready(t, request.Now)
	restarted := f.stored(t)
	if restarted.UsedReadyNs != settled.UsedReadyNs || restarted.ReadyDeadline.Time.Sub(restarted.ActiveReadyAt.Time) != GuestReadyAllowance-spent {
		t.Fatalf("restart refilled or charged stopped time: %+v", restarted)
	}
	deadline := restarted.ReadyDeadline.Time
	for at := request.Now.Add(30 * time.Second); at.Before(deadline.Add(-time.Second)); at = at.Add(30 * time.Second) {
		if _, err := f.heartbeat(at); err != nil {
			t.Fatalf("heartbeat at %v before READY deadline %v: %v", at, deadline, err)
		}
		if got := f.stored(t).ReadyDeadline.Time; !got.Equal(deadline) {
			t.Fatalf("heartbeat slid READY deadline: %v != %v", got, deadline)
		}
	}
	if issued := f.stored(t); !issued.ServingUntil.Time.Equal(deadline) {
		t.Fatalf("last heartbeat did not issue the exact remaining authority: %+v", issued)
	}
	for range 2 {
		if _, err := f.database.ExpireServiceRuns(t.Context(), deadline.Add(time.Second)); err != nil {
			t.Fatal(err)
		}
	}
	final := f.stored(t)
	if final.UsedReadyNs != int64(GuestReadyAllowance) || final.EndReason.String != "ready_limit" || final.ActiveServiceRunID.Valid {
		t.Fatalf("final allowance was not settled once: %+v", final)
	}
}

func TestIntegrationGuestAuthorityPreparationRenewsWithoutStartingBudget(t *testing.T) {
	f, guest := guestAuthorityFixture(t, false)
	if _, err := f.database.pool.Exec(t.Context(), `UPDATE control.guest_trials SET used_ready_ns=$2 WHERE id=$1`, guest.ID, int64(GuestReadyAllowance-5*time.Second)); err != nil {
		t.Fatal(err)
	}
	for _, elapsed := range []time.Duration{time.Second, 4 * time.Second, 7 * time.Second} {
		at := f.now.Add(elapsed)
		started := time.Now()
		renewed, err := f.heartbeat(at)
		earliest := at.Add(5 * time.Second).Truncate(time.Microsecond)
		latest := at.Add(time.Since(started) + 5*time.Second + time.Microsecond)
		if err != nil || renewed.ExpiresAt.Before(earliest) || renewed.ExpiresAt.After(latest) {
			t.Fatalf("preparation observation bound = %v, %v", renewed.ExpiresAt, err)
		}
		var persisted time.Time
		if err := f.database.pool.QueryRow(t.Context(), `SELECT publisher_expires_at FROM control.service_runs WHERE id=$1`, f.run.RunID).Scan(&persisted); err != nil || !persisted.Equal(renewed.ExpiresAt) {
			t.Fatalf("preparation response differs from issued run authority: %v, %v, %v", renewed.ExpiresAt, persisted, err)
		}
		stored := f.stored(t)
		if stored.UsedReadyNs != int64(GuestReadyAllowance-5*time.Second) || stored.ReadyDeadline.Valid || stored.ServingUntil.Valid {
			t.Fatalf("preparation consumed ready authority: %+v", stored)
		}
	}
	f.ready(t, f.now.Add(9*time.Second))
	stored := f.stored(t)
	if stored.ReadyDeadline.Time.Sub(stored.ActiveReadyAt.Time) != 5*time.Second {
		t.Fatalf("readiness did not preserve the remaining five seconds: %+v", stored)
	}
}

func TestIntegrationGuestAuthorityLateCleanupAndConcurrentClose(t *testing.T) {
	for _, late := range []bool{false, true} {
		t.Run(map[bool]string{false: "concurrent-stop", true: "late-cleanup"}[late], func(t *testing.T) {
			f, _ := guestAuthorityFixture(t, true)
			if _, err := f.heartbeat(f.now.Add(10 * time.Second)); err != nil {
				t.Fatal(err)
			}
			before := f.stored(t)
			older, err := f.heartbeat(f.now.Add(5 * time.Second))
			if err != nil || !older.ServingUntil.Equal(before.ServingUntil.Time) {
				t.Fatalf("older heartbeat discarded issued authority: %v, %v", older.ServingUntil, err)
			}
			const callers = 8
			results := make(chan error, callers)
			var workers sync.WaitGroup
			for range callers {
				workers.Go(func() {
					if late {
						_, err := f.database.ExpireServiceRuns(t.Context(), f.now.Add(time.Hour))
						results <- err
					} else {
						err := f.database.CloseServiceRun(f.ctx, f.service.ID, f.run.RunID, f.run.Token, f.now.Add(11*time.Second))
						if errors.Is(err, ErrServiceAccess) {
							err = nil
						}
						results <- err
					}
				})
			}
			workers.Wait()
			for range callers {
				if err := <-results; err != nil {
					t.Fatal(err)
				}
			}
			after := f.stored(t)
			if time.Duration(after.UsedReadyNs) != before.ServingUntil.Time.Sub(before.ActiveReadyAt.Time) {
				t.Fatalf("concurrent settlement = %+v", after)
			}
		})
	}
}

func TestIntegrationGuestAuthoritySettlementRollsBackWithClosure(t *testing.T) {
	f, _ := guestAuthorityFixture(t, true)
	if _, err := f.database.pool.Exec(t.Context(), `CREATE FUNCTION control.reject_guest_close() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'guest closure fault' USING ERRCODE='23514'; END $$;
	CREATE TRIGGER reject_guest_close BEFORE UPDATE ON control.guest_trials FOR EACH ROW WHEN (OLD.active_service_run_id IS NOT NULL AND NEW.active_service_run_id IS NULL) EXECUTE FUNCTION control.reject_guest_close()`); err != nil {
		t.Fatal(err)
	}
	before := f.stored(t)
	if err := f.database.CloseServiceRun(f.ctx, f.service.ID, f.run.RunID, f.run.Token, f.now.Add(time.Second)); err == nil {
		t.Fatal("injected closure failure succeeded")
	}
	after := f.stored(t)
	if !reflect.DeepEqual(after, before) {
		t.Fatal("failed closure changed the stored guest record")
	}
	var open bool
	if err := f.database.pool.QueryRow(t.Context(), `SELECT closed_at IS NULL AND assignments_open FROM control.service_runs WHERE id=$1`, f.run.RunID).Scan(&open); err != nil || !open {
		t.Fatalf("failed settlement committed closure: %t, %v", open, err)
	}
	if _, err := f.database.pool.Exec(t.Context(), `DROP TRIGGER reject_guest_close ON control.guest_trials`); err != nil {
		t.Fatal(err)
	}
	if err := f.database.CloseServiceRun(f.ctx, f.service.ID, f.run.RunID, f.run.Token, f.now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if got := time.Duration(f.stored(t).UsedReadyNs); got != before.ServingUntil.Time.Sub(before.ActiveReadyAt.Time) {
		t.Fatalf("retry settlement = %s", got)
	}
}

func TestIntegrationGuestAuthorityCloseSerializesWithRenewal(t *testing.T) {
	f, _ := guestAuthorityFixture(t, true)
	before := f.stored(t)
	ctx, cancel := context.WithTimeout(f.ctx, 10*time.Second)
	defer cancel()
	gate, err := f.database.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer rollbackTestTransaction(t, gate)
	if _, err := controlstatedb.New(gate).LockGuestTrialByID(ctx, f.guest.ID); err != nil {
		t.Fatal(err)
	}
	workers := newIntegrationWorkers(t, cancel)
	defer workers.stop()
	renewed, closed := make(chan error, 1), make(chan error, 1)
	workers.Go(func() {
		_, err := f.database.HeartbeatServiceRun(ctx, f.service.ID, f.run.RunID, f.run.Token, f.now.Add(10*time.Second), ServiceRunHealth{Healthy: true, StreamCapacity: 32})
		renewed <- err
	})
	pid := waitForPostgresBlock(t, ctx, f.database, int32(gate.Conn().PgConn().PID()), renewed)
	workers.Go(func() {
		closed <- f.database.CloseServiceRun(ctx, f.service.ID, f.run.RunID, f.run.Token, f.now.Add(11*time.Second))
	})
	waitForPostgresBlock(t, ctx, f.database, pid, closed, int32(gate.Conn().PgConn().PID()))
	if err := gate.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err := awaitIntegrationResult(t, ctx, renewed); err != nil {
		t.Fatal(err)
	}
	if err := awaitIntegrationResult(t, ctx, closed); err != nil {
		t.Fatal(err)
	}
	after := f.stored(t)
	want := f.now.Add(10*time.Second + f.database.servingTolerance())
	if !after.ServingUntil.Time.Equal(want) || time.Duration(after.UsedReadyNs) != want.Sub(before.ActiveReadyAt.Time) {
		t.Fatalf("closure missed serialized renewal: %+v", after)
	}
}

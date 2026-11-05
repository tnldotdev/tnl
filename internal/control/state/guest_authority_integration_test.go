package state

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
)

func guestAuthorityFixture(t *testing.T, ready bool) (publishRunFixture, NewGuestTrial) {
	t.Helper()
	db, now, request, relays := newPublishRunPrerequisites(t)
	guest, err := NewGuestTrialCredential(netip.MustParseAddr("192.0.2.7"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.CreateGuestTrial(t.Context(), guest, "routes.example.test", now); err != nil {
		t.Fatal(err)
	}
	if _, err := db.pool.Exec(t.Context(), `INSERT INTO control.guest_public_urls VALUES ($1,$2,$3)`, request.PublicURLID, guest.ID, now); err != nil {
		t.Fatal(err)
	}
	setup, err := db.CreatePublishRun(t.Context(), request, now, 30*time.Second, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	f := publishRunFixture{db, now, request, setup, relays}
	if ready {
		readyTestSession(t, f)
	}
	return f, guest
}

func guestRestartRequest(t *testing.T, f publishRunFixture, key string) PublishRunRequest {
	t.Helper()
	request := f.request
	request.IdempotencyKey = key
	if err := f.database.pool.QueryRow(t.Context(), `SELECT mutation_revision FROM control.public_urls WHERE id=$1`, request.PublicURLID).Scan(&request.ExpectedMutationRevision); err != nil {
		t.Fatal(err)
	}
	return request
}

func TestIntegrationGuestAuthorityStartsAtReadinessAndSettlesIssuedIdleTail(t *testing.T) {
	f, guest := guestAuthorityFixture(t, false)
	prepareServingPublisher(t, f)
	servingPreparationPending(t, f, f.now)
	before, err := f.database.GuestTrialByAccessToken(t.Context(), guest.Token)
	if err != nil || before.UsedReady != 0 || !before.ReadyDeadline.IsZero() || !before.ServingUntil.IsZero() {
		t.Fatalf("preparation charged ready time: %+v, %v", before, err)
	}
	readyAt := f.now.Add(10 * time.Second)
	readyTestServingRun(t, f, readyAt)
	stored, err := f.database.GuestTrialByAccessToken(t.Context(), guest.Token)
	if err != nil || !stored.ReadyDeadline.Equal(readyAt.Add(20*time.Minute)) || !stored.ServingUntil.Equal(f.setup.ExpiresAt) {
		t.Fatalf("readiness bounds: %+v, %v", stored, err)
	}
	for range 2 {
		if err := f.database.ClosePublishRun(t.Context(), f.setup.PublishRunID, f.setup.PublishRunToken, readyAt.Add(time.Second)); err != nil {
			t.Fatal(err)
		}
	}
	stored, err = f.database.GuestTrialByAccessToken(t.Context(), guest.Token)
	if err != nil || stored.UsedReady != 20*time.Second || !stored.ServingUntil.Equal(f.setup.ExpiresAt) {
		t.Fatalf("idle stop did not charge the outstanding horizon exactly once: %+v, %v", stored, err)
	}
}

func TestIntegrationGuestAuthorityCumulativeBudgetAndOfflineReplacement(t *testing.T) {
	f, guest := guestAuthorityFixture(t, true)
	db, start := f.database, f.now
	firstUntil := start.Add(7 * time.Minute)
	if _, err := db.HeartbeatPublishRun(t.Context(), f.authentication(), start.Add(time.Second), 7*time.Minute-time.Second, time.Minute); err != nil {
		t.Fatal(err)
	}
	if err := db.ClosePublishRun(t.Context(), f.setup.PublishRunID, f.setup.PublishRunToken, start.Add(2*time.Minute)); err != nil {
		t.Fatal(err)
	}
	request := guestRestartRequest(t, f, "restart")
	if _, err := db.CreatePublishRun(t.Context(), request, firstUntil.Add(-time.Microsecond), time.Hour, time.Minute); !errors.Is(err, ErrPublishRunOpen) {
		t.Fatalf("replacement reused outstanding authority: %v", err)
	}
	if _, err := db.AllocateGuestDemoNumber(t.Context(), guest.ID, firstUntil.Add(-time.Microsecond)); !errors.Is(err, ErrPublishRunOpen) {
		t.Fatalf("another demo reused outstanding authority: %v", err)
	}
	restartAt := start.Add(10 * time.Minute)
	setup, err := db.CreatePublishRun(t.Context(), request, restartAt, time.Hour, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	next := publishRunFixture{db, restartAt, request, setup, f.leases}
	readyTestSession(t, next)
	want := restartAt.Add(13 * time.Minute)
	stored, err := db.GuestTrialByAccessToken(t.Context(), guest.Token)
	if err != nil || stored.UsedReady != 7*time.Minute || !stored.ReadyDeadline.Equal(want) || !stored.ServingUntil.Equal(want) {
		t.Fatalf("restart refilled the budget or charged stopped time: %+v, %v", stored, err)
	}
	for _, at := range []time.Time{restartAt.Add(time.Second), want.Add(-time.Second)} {
		renewed, err := db.HeartbeatPublishRun(t.Context(), next.authentication(), at, time.Hour, time.Minute)
		if err != nil || !renewed.ExpiresAt.Equal(want) {
			t.Fatalf("heartbeat changed the fixed ready deadline: %v, %v", renewed.ExpiresAt, err)
		}
	}
	if err := db.ClosePublishRun(t.Context(), f.setup.PublishRunID, f.setup.PublishRunToken, want.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, err := db.HeartbeatPublishRun(t.Context(), f.authentication(), restartAt, time.Hour, time.Minute); !errors.Is(err, ErrPublishRunStale) {
		t.Fatalf("old heartbeat revived authority: %v", err)
	}
	old, err := db.CreatePublishRun(t.Context(), f.request, restartAt, time.Hour, time.Minute)
	if err != nil || old.State != PublishRunClosed || old.ExpiresAt.After(restartAt) {
		t.Fatalf("idempotent old setup received new authority: %+v, %v", old, err)
	}
	for range 2 {
		if _, err := db.ExpireSavedPublishRuns(t.Context(), want.Add(time.Hour)); err != nil {
			t.Fatal(err)
		}
	}
	stored, err = db.GuestTrialByAccessToken(t.Context(), guest.Token)
	if err != nil || stored.UsedReady != 20*time.Minute || !stored.ServingUntil.Equal(want) {
		t.Fatalf("late cleanup overcharged the final horizon: %+v, %v", stored, err)
	}
	if _, err := db.CreatePublishRun(t.Context(), guestRestartRequest(t, next, "spent"), want.Add(time.Second), time.Hour, time.Minute); !errors.Is(err, ErrGuestTrialSpent) {
		t.Fatalf("spent budget created another run: %v", err)
	}
}

func TestIntegrationGuestAuthorityPreparationRenewsWithoutStartingBudget(t *testing.T) {
	f, guest := guestAuthorityFixture(t, false)
	if _, err := f.database.pool.Exec(t.Context(), `UPDATE control.guest_trials SET used_ready_ns=$2 WHERE id=$1`, guest.ID, int64(GuestReadyAllowance-5*time.Second)); err != nil {
		t.Fatal(err)
	}
	for _, elapsed := range []time.Duration{time.Second, 4 * time.Second, 7 * time.Second} {
		at := f.now.Add(elapsed)
		renewed, err := f.database.HeartbeatPublishRun(t.Context(), f.authentication(), at, time.Hour, time.Minute)
		if err != nil || !renewed.ExpiresAt.Equal(at.Add(5*time.Second)) {
			t.Fatalf("preparation observation bound = %v, %v", renewed.ExpiresAt, err)
		}
		stored, err := f.database.GuestTrialByAccessToken(t.Context(), guest.Token)
		if err != nil || stored.UsedReady != GuestReadyAllowance-5*time.Second || !stored.ReadyDeadline.IsZero() || !stored.ServingUntil.IsZero() {
			t.Fatalf("preparation consumed or reserved ready authority: %+v, %v", stored, err)
		}
	}
	f.now = f.now.Add(9 * time.Second)
	readyTestSession(t, f)
	renewed, err := f.database.HeartbeatPublishRun(t.Context(), f.authentication(), f.now.Add(time.Second), time.Hour, time.Minute)
	if err != nil || !renewed.ExpiresAt.Equal(f.now.Add(5*time.Second)) {
		t.Fatalf("readiness did not preserve the remaining five seconds: %v, %v", renewed.ExpiresAt, err)
	}
}

func TestIntegrationGuestAuthorityLateCleanupAndConcurrentClose(t *testing.T) {
	for _, late := range []bool{false, true} {
		t.Run(map[bool]string{false: "concurrent-stop", true: "late-cleanup"}[late], func(t *testing.T) {
			f, guest := guestAuthorityFixture(t, true)
			if _, err := f.database.HeartbeatPublishRun(t.Context(), f.authentication(), f.now.Add(10*time.Second), 30*time.Second, time.Minute); err != nil {
				t.Fatal(err)
			}
			// a delayed request with an older clock and shorter proposed lease
			// cannot shorten the issued horizon before settlement.
			older, err := f.database.HeartbeatPublishRun(t.Context(), f.authentication(), f.now.Add(5*time.Second), time.Second, time.Minute)
			if err != nil || !older.ExpiresAt.Equal(f.now.Add(40*time.Second)) {
				t.Fatalf("older heartbeat discarded issued authority: %v, %v", older.ExpiresAt, err)
			}
			const callers = 8
			results := make(chan error, callers)
			var workers sync.WaitGroup
			for range callers {
				workers.Go(func() {
					if late {
						_, err := f.database.ExpireSavedPublishRuns(t.Context(), f.now.Add(time.Hour))
						results <- err
					} else {
						results <- f.database.ClosePublishRun(t.Context(), f.setup.PublishRunID, f.setup.PublishRunToken, f.now.Add(11*time.Second))
					}
				})
			}
			workers.Wait()
			for range callers {
				if err := <-results; err != nil {
					t.Fatal(err)
				}
			}
			stored, err := f.database.GuestTrialByAccessToken(t.Context(), guest.Token)
			if err != nil || stored.UsedReady != 40*time.Second {
				t.Fatalf("settlement = %+v, %v", stored, err)
			}
		})
	}
}

func TestIntegrationGuestAuthoritySettlementRollsBackWithClosure(t *testing.T) {
	f, guest := guestAuthorityFixture(t, true)
	if _, err := f.database.pool.Exec(t.Context(), `CREATE FUNCTION control.reject_guest_close() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'guest closure fault' USING ERRCODE='23514'; END $$;
	CREATE TRIGGER reject_guest_close BEFORE UPDATE ON control.guest_trials FOR EACH ROW WHEN (OLD.active_publish_run_id IS NOT NULL AND NEW.active_publish_run_id IS NULL) EXECUTE FUNCTION control.reject_guest_close()`); err != nil {
		t.Fatal(err)
	}
	before, err := f.database.GuestTrialByAccessToken(t.Context(), guest.Token)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.database.ClosePublishRun(t.Context(), f.setup.PublishRunID, f.setup.PublishRunToken, f.now.Add(time.Second)); err == nil {
		t.Fatal("injected closure failure succeeded")
	}
	after, err := f.database.GuestTrialByAccessToken(t.Context(), guest.Token)
	if err != nil || after != before {
		t.Fatalf("failed closure settled budget: before=%+v after=%+v err=%v", before, after, err)
	}
	var open bool
	if err := f.database.pool.QueryRow(t.Context(), `SELECT closed_at IS NULL AND assignments_open FROM control.publish_runs WHERE id=$1`, f.setup.PublishRunID).Scan(&open); err != nil || !open {
		t.Fatalf("failed settlement committed run closure: %t, %v", open, err)
	}
	if _, err := f.database.pool.Exec(t.Context(), `DROP TRIGGER reject_guest_close ON control.guest_trials`); err != nil {
		t.Fatal(err)
	}
	if err := f.database.ClosePublishRun(t.Context(), f.setup.PublishRunID, f.setup.PublishRunToken, f.now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	after, err = f.database.GuestTrialByAccessToken(t.Context(), guest.Token)
	if err != nil || after.UsedReady != 30*time.Second {
		t.Fatalf("retry did not settle original horizon once: %+v, %v", after, err)
	}
}

func TestIntegrationGuestAuthorityCloseSerializesWithRenewal(t *testing.T) {
	f, guest := guestAuthorityFixture(t, true)
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	gate, err := f.database.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer rollbackTestTransaction(t, gate)
	if _, err := controlstatedb.New(gate).LockPublicURLForRun(ctx, f.setup.PublicURLID); err != nil {
		t.Fatal(err)
	}
	workers := newIntegrationWorkers(t, cancel)
	defer workers.stop()
	renewed, closed := make(chan error, 1), make(chan error, 1)
	workers.Go(func() {
		_, err := f.database.HeartbeatPublishRun(ctx, f.authentication(), f.now.Add(10*time.Second), 30*time.Second, time.Minute)
		renewed <- err
	})
	pid := waitForPostgresBlock(t, ctx, f.database, int32(gate.Conn().PgConn().PID()), renewed)
	workers.Go(func() {
		closed <- f.database.ClosePublishRun(ctx, f.setup.PublishRunID, f.setup.PublishRunToken, f.now.Add(11*time.Second))
	})
	waitForPostgresBlock(t, ctx, f.database, pid, closed)
	if err := gate.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err := awaitIntegrationResult(t, ctx, renewed); err != nil {
		t.Fatal(err)
	}
	if err := awaitIntegrationResult(t, ctx, closed); err != nil {
		t.Fatal(err)
	}
	stored, err := f.database.GuestTrialByAccessToken(t.Context(), guest.Token)
	if err != nil || stored.UsedReady != 40*time.Second {
		t.Fatalf("closure missed serialized renewal: %+v, %v", stored, err)
	}
}

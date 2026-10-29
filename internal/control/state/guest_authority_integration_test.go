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

func guestAuthorityFixture(t *testing.T) (publishRunFixture, NewGuestTrial) {
	t.Helper()
	database, now, request, leases := newPublishRunPrerequisites(t)
	guest, err := NewGuestTrialCredential(netip.MustParseAddr("192.0.2.7"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.CreateGuestTrial(t.Context(), guest, "routes.example.test", now); err != nil {
		t.Fatal(err)
	}
	if _, err := database.pool.Exec(t.Context(), `INSERT INTO control.guest_public_urls (public_url_id, guest_id, created_at) VALUES ($1,$2,$3)`, request.PublicURLID, guest.ID, now); err != nil {
		t.Fatal(err)
	}
	setup, err := database.CreatePublishRun(t.Context(), request, now, 30*time.Second, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	f := publishRunFixture{database, now, request, setup, leases}
	readyTestSession(t, f)
	return f, guest
}

func TestIntegrationGuestAuthorityBoundsLongPublisherLeaseToTwentyReadyMinutes(t *testing.T) {
	f, _ := guestAuthorityFixture(t)
	renewed, err := f.database.HeartbeatPublishRun(t.Context(), f.authentication(), f.now.Add(time.Second), time.Hour, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if want := f.now.Add(20 * time.Minute); !renewed.ExpiresAt.Equal(want) {
		t.Fatalf("guest publisher authority = %v, want fixed ready deadline %v", renewed.ExpiresAt, want)
	}
}

func TestIntegrationGuestAuthorityIdleStopChargesOutstandingTailOnce(t *testing.T) {
	f, guest := guestAuthorityFixture(t)
	if _, err := f.database.HeartbeatPublishRun(t.Context(), f.authentication(), f.now.Add(10*time.Second), 30*time.Second, time.Minute); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := f.database.ClosePublishRun(t.Context(), f.setup.PublishRunID, f.setup.PublishRunToken, f.now.Add(11*time.Second)); err != nil {
			t.Fatal(err)
		}
	}
	stored, err := f.database.GuestTrialByAccessToken(t.Context(), guest.Token)
	if err != nil {
		t.Fatal(err)
	}
	if stored.UsedReady != 40*time.Second {
		t.Fatalf("idle guest ready charge = %v, want issued offline horizon 40s exactly once", stored.UsedReady)
	}
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

func TestIntegrationGuestAuthorityFullCumulativeBudgetAcrossIdleAndRestart(t *testing.T) {
	f, guest := guestAuthorityFixture(t)
	db, start := f.database, f.now
	// no visitor or heartbeat activity is needed to spend already-issued time.
	firstUntil := start.Add(7 * time.Minute)
	if _, err := db.HeartbeatPublishRun(t.Context(), f.authentication(), start.Add(time.Second), 7*time.Minute-time.Second, time.Minute); err != nil {
		t.Fatal(err)
	}
	if err := db.ClosePublishRun(t.Context(), f.setup.PublishRunID, f.setup.PublishRunToken, start.Add(2*time.Minute)); err != nil {
		t.Fatal(err)
	}
	request := guestRestartRequest(t, f, "restart")
	if _, err := db.CreatePublishRun(t.Context(), request, firstUntil.Add(-time.Microsecond), time.Hour, time.Minute); !errors.Is(err, ErrPublishRunOpen) {
		t.Fatalf("replacement spent outstanding offline tail: %v", err)
	}
	// the independent idle gap is not ready authority and must not consume or
	// restore any of the thirteen minutes still available.
	restartAt := start.Add(10 * time.Minute)
	setup, err := db.CreatePublishRun(t.Context(), request, restartAt, time.Hour, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	next := publishRunFixture{database: db, now: restartAt, request: request, setup: setup, leases: f.leases}
	readyTestSession(t, next)
	want := restartAt.Add(13 * time.Minute)
	stored, err := db.GuestTrialByAccessToken(t.Context(), guest.Token)
	if err != nil || stored.UsedReady != 7*time.Minute || !stored.ReadyDeadline.Equal(want) || !stored.ServingUntil.Equal(want) {
		t.Fatalf("restart refilled or spent idle gap: %+v, %v", stored, err)
	}
	for _, at := range []time.Time{restartAt.Add(time.Second), want.Add(-time.Second)} {
		renewed, err := db.HeartbeatPublishRun(t.Context(), next.authentication(), at, time.Hour, time.Minute)
		if err != nil || !renewed.ExpiresAt.Equal(want) {
			t.Fatalf("remaining thirteen minutes unavailable or extended: %+v, %v", renewed, err)
		}
	}
	// a delayed old close and old heartbeat cannot settle the new interval or
	// revive the old owner, even with a later proposed publisher deadline.
	if err := db.ClosePublishRun(t.Context(), f.setup.PublishRunID, f.setup.PublishRunToken, want.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, err := db.HeartbeatPublishRun(t.Context(), f.authentication(), restartAt.Add(time.Second), time.Hour, time.Minute); !errors.Is(err, ErrPublishRunStale) {
		t.Fatalf("old owner revived: %v", err)
	}
	old, err := db.CreatePublishRun(t.Context(), f.request, restartAt, time.Hour, time.Minute)
	if err != nil || old.PublishRunID != f.setup.PublishRunID || old.State != PublishRunClosed || old.ExpiresAt.After(restartAt) {
		t.Fatalf("old response received new authority: %+v, %v", old, err)
	}
	stored, err = db.GuestTrialByAccessToken(t.Context(), guest.Token)
	if err != nil || stored.UsedReady != 7*time.Minute || !stored.ReadyDeadline.Equal(want) {
		t.Fatalf("old response changed current guest interval: %+v, %v", stored, err)
	}
	for range 2 {
		if _, err := db.ExpireSavedPublishRuns(t.Context(), want.Add(time.Hour)); err != nil {
			t.Fatal(err)
		}
	}
	stored, err = db.GuestTrialByAccessToken(t.Context(), guest.Token)
	if err != nil || stored.UsedReady != 20*time.Minute || !stored.ServingUntil.Equal(want) {
		t.Fatalf("full cumulative budget = %+v, %v", stored, err)
	}
	if _, err := db.CreatePublishRun(t.Context(), guestRestartRequest(t, next, "spent"), want.Add(time.Second), time.Hour, time.Minute); !errors.Is(err, ErrGuestTrialSpent) {
		t.Fatalf("twenty minutes allowed a new run: %v", err)
	}
}

func TestIntegrationGuestAuthorityConcurrentCloseSettlesOnce(t *testing.T) {
	f, guest := guestAuthorityFixture(t)
	if _, err := f.database.HeartbeatPublishRun(t.Context(), f.authentication(), f.now.Add(10*time.Second), 30*time.Second, time.Minute); err != nil {
		t.Fatal(err)
	}
	const callers = 12
	results := make(chan error, callers)
	var workers sync.WaitGroup
	for range callers {
		workers.Go(func() {
			results <- f.database.ClosePublishRun(t.Context(), f.setup.PublishRunID, f.setup.PublishRunToken, f.now.Add(11*time.Second))
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
		t.Fatalf("concurrent settlement = %+v, %v", stored, err)
	}
	// an exact retry is shared by all contenders, with one durable new owner.
	request := guestRestartRequest(t, f, "concurrent-replacement")
	setups := make(chan PublishRunSetup, callers)
	for range callers {
		workers.Go(func() {
			setup, err := f.database.CreatePublishRun(t.Context(), request, f.now.Add(40*time.Second), time.Minute, time.Minute)
			results <- err
			setups <- setup
		})
	}
	workers.Wait()
	var id string
	for range callers {
		if err := <-results; err != nil {
			t.Fatal(err)
		}
		setup := <-setups
		if id != "" && setup.PublishRunID != id {
			t.Fatal("exact retries created different owners")
		}
		id = setup.PublishRunID
	}
	var active int
	if err := f.database.pool.QueryRow(t.Context(), `SELECT count(*) FROM control.publish_runs WHERE public_url_id=$1 AND closed_at IS NULL`, request.PublicURLID).Scan(&active); err != nil || active != 1 {
		t.Fatalf("active replacement count = %d, %v", active, err)
	}
}

func TestIntegrationGuestAuthoritySettlementRollsBackWithClosure(t *testing.T) {
	f, guest := guestAuthorityFixture(t)
	if _, err := f.database.pool.Exec(t.Context(), `CREATE FUNCTION control.reject_guest_close() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'guest closure fault' USING ERRCODE='23514'; END $$;
	CREATE TRIGGER reject_guest_close BEFORE UPDATE ON control.guest_trials FOR EACH ROW WHEN (OLD.active_publish_run_id IS NOT NULL AND NEW.active_publish_run_id IS NULL) EXECUTE FUNCTION control.reject_guest_close()`); err != nil {
		t.Fatal(err)
	}
	before, err := f.database.GuestTrialByAccessToken(t.Context(), guest.Token)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.database.ClosePublishRun(t.Context(), f.setup.PublishRunID, f.setup.PublishRunToken, f.now.Add(time.Second)); err == nil {
		t.Fatal("injected settlement failure succeeded")
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
	f, guest := guestAuthorityFixture(t)
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

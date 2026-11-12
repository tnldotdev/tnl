package state

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/security/credentials"
)

type browserRefreshWorkerKey struct{}
type browserRefreshQueryKey struct{}

type browserRefreshTracer struct {
	pgx.QueryTracer
	conflicts chan int
}

func (tracer *browserRefreshTracer) TraceQueryStart(ctx context.Context, conn *pgx.Conn, data pgx.TraceQueryStartData) context.Context {
	ctx = tracer.QueryTracer.TraceQueryStart(ctx, conn, data)
	return context.WithValue(ctx, browserRefreshQueryKey{}, strings.HasPrefix(data.SQL, "-- name: LockServiceHTTPBrowserSession"))
}

func (tracer *browserRefreshTracer) TraceQueryEnd(ctx context.Context, conn *pgx.Conn, data pgx.TraceQueryEndData) {
	tracer.QueryTracer.TraceQueryEnd(ctx, conn, data)
	worker, observed := ctx.Value(browserRefreshWorkerKey{}).(int)
	locking, _ := ctx.Value(browserRefreshQueryKey{}).(bool)
	var failure *pgconn.PgError
	if observed && locking && errors.As(data.Err, &failure) && failure != nil && failure.Code == "55P03" {
		select {
		case tracer.conflicts <- worker:
		case <-ctx.Done():
		}
	}
}

type serviceBrowserRefreshFixture struct {
	d                                                  *Database
	now                                                time.Time
	tracer                                             *browserRefreshTracer
	service, peerService, cookie, peerCookie, identity string
	session                                            ControlSession
	deadline                                           time.Time
}

func newServiceBrowserRefreshFixture(t *testing.T) serviceBrowserRefreshFixture {
	t.Helper()
	d, _, now := newControlStateIntegrationDatabaseWithURL(t, "service_browser_refresh")
	configuration := d.pool.Config()
	tracer := &browserRefreshTracer{QueryTracer: configuration.ConnConfig.Tracer.(pgx.QueryTracer), conflicts: make(chan int, 512)}
	configuration.ConnConfig.Tracer = tracer
	configuration.MaxConns, configuration.MinConns = 2, 0
	pool, err := pgxpool.NewWithConfig(t.Context(), configuration)
	if err != nil {
		t.Fatal(err)
	}
	d.pool.Close()
	d.pool = pool
	r := retainedEnvironmentProject(t, d, now)
	environment, _ := retainedServiceEnvironment(t, d, r, "browser", map[string]EnvironmentServicePublication{"api": {Protocol: "http", Target: "api.internal:3000"}, "peer": {Protocol: "http", Target: "peer.internal:3000"}})
	f := serviceBrowserRefreshFixture{d: d, now: now.Add(2 * time.Second), tracer: tracer, deadline: now.Add(time.Hour), identity: r.ActorID}
	// refresh owns a browser row and its real control session, not a serving
	// topology. seed captured run labels here; the retained admission suite owns
	// proving those labels against a live publisher run.
	for _, service := range environment.Services {
		session := browserTestControlSession(t, d, r.ActorID, now)
		handoff, _, err := randomBrowserSecret()
		if err != nil {
			t.Fatal(err)
		}
		digest, err := browserDigest(handoff)
		if err != nil {
			t.Fatal(err)
		}
		sealed, err := d.storageKey.Seal(browserContext(digest), []byte(session.RefreshToken))
		if err != nil {
			t.Fatal(err)
		}
		run := mustOpaqueID(t, opaqueid.ServiceRunPrefix)
		q := controlstatedb.New(d.pool)
		err = q.InsertServiceHTTPBrowserSession(t.Context(), controlstatedb.InsertServiceHTTPBrowserSessionParams{HandoffDigest: digest, ServiceID: service.ServiceID, RunIds: []string{run}, ControlSessionID: session.SessionID, ReturnPath: "/", HandoffExpiresAt: timestamptz(now.Add(time.Minute)), ExpiresAt: timestamptz(f.deadline), RefreshCiphertext: sealed, StorageKeyID: d.storageKey.CurrentID()})
		if err != nil {
			t.Fatal(err)
		}
		cookie, _, err := randomBrowserSecret()
		if err != nil {
			t.Fatal(err)
		}
		cookieDigest, err := browserDigest(cookie)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = q.RedeemServiceHTTPBrowserSession(t.Context(), controlstatedb.RedeemServiceHTTPBrowserSessionParams{HandoffDigest: digest, CookieDigest: cookieDigest, ServiceID: service.ServiceID, ServiceRunID: run, Now: timestamptz(now)}); err != nil {
			t.Fatal(err)
		}
		if service.Service == "api" {
			f.service, f.cookie, f.session = service.ServiceID, cookie, session
			if _, err := d.pool.Exec(t.Context(), `UPDATE control.control_sessions SET access_expires_at=$2 WHERE id=$1`, session.SessionID, f.now.Add(-time.Second)); err != nil {
				t.Fatal(err)
			}
		} else {
			f.peerService, f.peerCookie = service.ServiceID, cookie
		}
	}
	return f
}

func (f serviceBrowserRefreshFixture) facts(t *testing.T, service string, ciphertext bool) []byte {
	t.Helper()
	var result []byte
	err := f.d.pool.QueryRow(t.Context(), `SELECT (to_jsonb(browser) - CASE WHEN $2 THEN ARRAY[]::text[] ELSE ARRAY['refresh_ciphertext','storage_key_id'] END)::text FROM control.service_http_browser_sessions browser WHERE service_id=$1`, service, ciphertext).Scan(&result)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func (f serviceBrowserRefreshFixture) rotate(ctx context.Context, token string) (BrowserTokenRotation, error) {
	rotated, err := f.d.RefreshControlSession(ctx, credentials.RefreshToken(token), time.Hour, time.Now())
	if err != nil {
		return BrowserTokenRotation{}, err
	}
	return BrowserTokenRotation{IdentityID: rotated.Identity.Identity.ID, AccessToken: rotated.AccessToken.String(), RefreshToken: rotated.RefreshToken.String(), AccessExpiresAt: rotated.AccessExpiresAt}, nil
}

func TestIntegrationServiceBrowserRefreshContention(t *testing.T) {
	f := newServiceBrowserRefreshFixture(t)
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	workers := newIntegrationWorkers(t, cancel)
	defer workers.stop()
	before, peerBefore := f.facts(t, f.service, false), f.facts(t, f.peerService, true)
	entered, release := make(chan struct{}), make(chan struct{})
	var rotations atomic.Int32
	refresh := func(ctx context.Context, token string) (BrowserTokenRotation, error) {
		if rotations.Add(1) == 1 {
			close(entered)
		}
		select {
		case <-release:
		case <-ctx.Done():
			return BrowserTokenRotation{}, context.Cause(ctx)
		}
		return f.rotate(ctx, token)
	}
	type outcome struct {
		session BrowserAccessSession
		err     error
	}
	done := make(chan outcome, 8)
	workers.Go(func() {
		s, err := f.d.RefreshServiceBrowserSession(ctx, f.service, f.cookie, f.now, refresh)
		done <- outcome{s, err}
	})
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	for worker := range 7 {
		workers.Go(func() {
			workerCtx := context.WithValue(ctx, browserRefreshWorkerKey{}, worker)
			s, err := f.d.RefreshServiceBrowserSession(workerCtx, f.service, f.cookie, f.now, refresh)
			done <- outcome{s, err}
		})
	}
	counts := make([]int, 7)
	for remaining := 7; remaining > 0; {
		select {
		case worker := <-f.tracer.conflicts:
			counts[worker]++
			if counts[worker] == 8 {
				remaining--
			}
		case <-ctx.Done():
			t.Fatal("contenders did not reach eight real NOWAIT conflicts", ctx.Err())
		}
	}
	peer, err := f.d.RefreshServiceBrowserSession(ctx, f.peerService, f.peerCookie, f.now, func(context.Context, string) (BrowserTokenRotation, error) {
		t.Error("fresh peer requested rotation")
		return BrowserTokenRotation{}, ErrPreviewAccess
	})
	if err != nil || peer.IdentityID != f.identity || !peer.ExpiresAt.Equal(f.deadline) {
		t.Fatal("independent peer was blocked or changed", err)
	}
	close(release)
	for range 8 {
		result := awaitIntegrationResult(t, ctx, done)
		if result.err != nil || result.session.IdentityID != f.identity || !result.session.AccessExpiresAt.After(f.now) || !result.session.ExpiresAt.Equal(f.deadline) {
			t.Fatalf("contending refresh failed or widened identity/lifetime: %v", result.err)
		}
	}
	workers.Wait()
	if rotations.Load() != 1 {
		t.Fatal("concurrent requests rotated more than once", rotations.Load())
	}
	if !bytes.Equal(before, f.facts(t, f.service, false)) || !bytes.Equal(peerBefore, f.facts(t, f.peerService, true)) {
		t.Fatal("refresh changed saved browser/run binding or independent peer")
	}
	var handoff, sealed []byte
	var key string
	if err := f.d.pool.QueryRow(ctx, `SELECT handoff_digest,refresh_ciphertext,storage_key_id FROM control.service_http_browser_sessions WHERE service_id=$1`, f.service).Scan(&handoff, &sealed, &key); err != nil {
		t.Fatal(err)
	}
	plain, _, err := f.d.storageKey.Open(key, browserContext(handoff), sealed)
	if err != nil || string(plain) == f.session.RefreshToken.String() || bytes.Contains(sealed, plain) {
		t.Fatal("rotated refresh was not saved encrypted", err)
	}
	if _, err := f.d.pool.Exec(ctx, `UPDATE control.control_sessions SET access_expires_at=$2 WHERE id=$1`, f.session.SessionID, f.now.Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	next, err := f.d.RefreshServiceBrowserSession(ctx, f.service, f.cookie, f.now, func(ctx context.Context, token string) (BrowserTokenRotation, error) {
		rotations.Add(1)
		return f.rotate(ctx, token)
	})
	if err != nil || rotations.Load() != 2 || !next.ExpiresAt.Equal(f.deadline) {
		t.Fatal("encrypted rotated credential did not refresh within original lifetime", err)
	}
}

func TestIntegrationServiceBrowserRefreshWaitCancellation(t *testing.T) {
	for _, mode := range []string{"cancel", "deadline"} {
		t.Run(mode, func(t *testing.T) {
			f := newServiceBrowserRefreshFixture(t)
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			workers := newIntegrationWorkers(t, cancel)
			defer workers.stop()
			entered, release := make(chan struct{}), make(chan struct{})
			var calls atomic.Int32
			winner := make(chan error, 1)
			workers.Go(func() {
				_, err := f.d.RefreshServiceBrowserSession(ctx, f.service, f.cookie, f.now, func(ctx context.Context, token string) (BrowserTokenRotation, error) {
					calls.Add(1)
					close(entered)
					select {
					case <-release:
					case <-ctx.Done():
						return BrowserTokenRotation{}, context.Cause(ctx)
					}
					return f.rotate(ctx, token)
				})
				winner <- err
			})
			select {
			case <-entered:
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
			waitCtx, stop := context.WithCancelCause(ctx)
			defer stop(nil)
			cause := errors.New("cancel this browser request")
			var expected error = cause
			if mode == "deadline" {
				var deadlineCancel context.CancelFunc
				waitCtx, deadlineCancel = context.WithTimeout(waitCtx, time.Second)
				defer deadlineCancel()
				expected = context.DeadlineExceeded
			}
			waiter := make(chan error, 1)
			workers.Go(func() {
				_, err := f.d.RefreshServiceBrowserSession(context.WithValue(waitCtx, browserRefreshWorkerKey{}, 0), f.service, f.cookie, f.now, func(context.Context, string) (BrowserTokenRotation, error) {
					calls.Add(1)
					return BrowserTokenRotation{}, errors.New("waiting request invoked authority")
				})
				waiter <- err
			})
			select {
			case <-f.tracer.conflicts:
			case <-ctx.Done():
				t.Fatal("waiting request did not reach NOWAIT", ctx.Err())
			}
			if mode == "cancel" {
				stop(cause)
			}
			if err := awaitIntegrationResult(t, ctx, waiter); !errors.Is(err, expected) {
				t.Fatal("contention ignored cancellation/deadline", err)
			}
			// canceled queries can retire their connection asynchronously. acquire
			// the other slot while the winner still owns its transaction, rather
			// than treating an instantaneous pool-stat snapshot as completed cleanup.
			available, err := f.d.pool.Acquire(ctx)
			if err != nil {
				t.Fatal("canceled contender retained the other pool slot", err)
			}
			available.Release()
			if calls.Load() != 1 || f.d.pool.Stat().AcquiredConns() != 1 {
				t.Fatal("waiting request called authority or retained a pool connection", calls.Load(), f.d.pool.Stat().AcquiredConns())
			}
			close(release)
			if err := awaitIntegrationResult(t, ctx, winner); err != nil {
				t.Fatal("canceled contender prevented winner rotation", err)
			}
			workers.Wait()
			if f.d.pool.Stat().AcquiredConns() != 0 {
				t.Fatal("refresh leaked a pool connection")
			}
			if err := f.d.pool.Ping(ctx); err != nil {
				t.Fatal("refresh left the small pool unusable", err)
			}
		})
	}
}

func TestIntegrationServiceBrowserRefreshCurrentAuthority(t *testing.T) {
	t.Run("parent revoked while waiting", func(t *testing.T) {
		f := newServiceBrowserRefreshFixture(t)
		ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
		defer cancel()
		workers := newIntegrationWorkers(t, cancel)
		gate, err := f.d.pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer rollbackTestTransaction(t, gate)
		defer workers.stop()
		digest, err := browserDigest(f.cookie)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = controlstatedb.New(gate).LockServiceHTTPBrowserSession(ctx, controlstatedb.LockServiceHTTPBrowserSessionParams{ServiceID: f.service, CookieDigest: digest, ExpiresAt: timestamptz(f.now)}); err != nil {
			t.Fatal(err)
		}
		var calls atomic.Int32
		done := make(chan error, 1)
		workers.Go(func() {
			_, err := f.d.RefreshServiceBrowserSession(context.WithValue(ctx, browserRefreshWorkerKey{}, 0), f.service, f.cookie, f.now, func(ctx context.Context, token string) (BrowserTokenRotation, error) {
				calls.Add(1)
				return f.rotate(ctx, token)
			})
			done <- err
		})
		select {
		case <-f.tracer.conflicts:
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
		if err := f.d.RevokeControlSession(ctx, ControlPrincipal{SessionID: f.session.SessionID, IdentityID: f.identity}, time.Now()); err != nil {
			t.Fatal(err)
		}
		if err := gate.Commit(ctx); err != nil {
			t.Fatal(err)
		}
		if err := awaitIntegrationResult(t, ctx, done); !errors.Is(err, ErrPreviewAccess) || calls.Load() != 0 {
			t.Fatal("wait reused revoked parent or invoked authority", calls.Load(), err)
		}
	})
	for _, change := range []string{"parent revoked after callback", "identity disabled after callback", "browser expired during callback"} {
		t.Run(change, func(t *testing.T) {
			f := newServiceBrowserRefreshFixture(t)
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			entry := f.now
			if change == "browser expired during callback" {
				entry = f.deadline.Add(-25 * time.Millisecond)
			}
			calls := 0
			_, err := f.d.RefreshServiceBrowserSession(ctx, f.service, f.cookie, entry, func(ctx context.Context, token string) (BrowserTokenRotation, error) {
				calls++
				rotated, err := f.rotate(ctx, token)
				if err != nil {
					return rotated, err
				}
				switch change {
				case "parent revoked after callback":
					err = f.d.RevokeControlSession(ctx, ControlPrincipal{SessionID: f.session.SessionID, IdentityID: f.identity}, time.Now())
				case "identity disabled after callback":
					_, err = f.d.pool.Exec(ctx, `UPDATE control.identities SET disabled_at=$2 WHERE id=$1`, f.identity, time.Now())
				case "browser expired during callback":
					// this is the real remaining browser lifetime, not a scheduling
					// delay used to assume that another worker reached a lock.
					timer := time.NewTimer(f.deadline.Sub(entry) + time.Millisecond)
					defer timer.Stop()
					select {
					case <-timer.C:
					case <-ctx.Done():
						return rotated, context.Cause(ctx)
					}
				}
				return rotated, err
			})
			if !errors.Is(err, ErrPreviewAccess) || calls != 1 {
				t.Fatal("refresh returned stale authority or repeated rotation", calls, err)
			}
		})
	}
}

func TestIntegrationServiceBrowserRefreshDoesNotReplayRotation(t *testing.T) {
	for _, stage := range []string{"callback failure", "rotation write failure"} {
		t.Run(stage, func(t *testing.T) {
			f := newServiceBrowserRefreshFixture(t)
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			before := f.facts(t, f.service, true)
			if stage == "rotation write failure" {
				// the authority callback commits in its own transaction before this
				// storage failure. retrying the outer operation would hide that error.
				_, err := f.d.pool.Exec(ctx, `CREATE FUNCTION control.test_browser_rotation_failure() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION USING ERRCODE='55P03',MESSAGE='fixture browser rotation write failure'; END $$;
                    CREATE TRIGGER test_browser_rotation_failure BEFORE UPDATE OF refresh_ciphertext ON control.service_http_browser_sessions FOR EACH ROW EXECUTE FUNCTION control.test_browser_rotation_failure()`)
				if err != nil {
					t.Fatal(err)
				}
			}
			failure := &pgconn.PgError{Code: "55P03", Message: "fixture callback failure"}
			calls := 0
			_, err := f.d.RefreshServiceBrowserSession(ctx, f.service, f.cookie, f.now, func(ctx context.Context, token string) (BrowserTokenRotation, error) {
				calls++
				rotated, err := f.rotate(ctx, token)
				if err != nil {
					return rotated, err
				}
				if stage == "callback failure" {
					return rotated, failure
				}
				return rotated, nil
			})
			var postgres *pgconn.PgError
			if calls != 1 || !errors.As(err, &postgres) || postgres == nil || postgres.Code != "55P03" || stage == "callback failure" && !errors.Is(err, failure) {
				t.Fatal("callback/write failure was retried or lost", calls, err)
			}
			if !bytes.Equal(before, f.facts(t, f.service, true)) {
				t.Fatal("failed refresh partially updated its browser receipt")
			}
		})
	}
}

package controlstate

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/controlstate/controlstatedb"
)

func TestIntegrationSessionStartsOnDifferentRoutesShareTeamGuard(t *testing.T) {
	f := newTransactionAuthorityFixture(t)
	registerCertificatePlanRelays(t, f.database, f.now)
	sibling := siblingSessionRequest(t, f)
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	gate, err := f.database.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer rollbackTestTransaction(t, gate)
	if _, err := controlstatedb.New(gate).LockRouteForSession(ctx, f.route.ID); err != nil {
		t.Fatal(err)
	}
	workers := newIntegrationWorkers(t, cancel)
	defer workers.stop()
	first := make(chan error, 1)
	workers.Go(func() {
		_, err := f.database.CreateRouteSession(ctx, f.sessionRequest, f.now, time.Hour, time.Hour)
		first <- err
	})
	// The first start holds its team guard while blocked on its own route.
	waitForPostgresBlock(t, ctx, f.database, int32(gate.Conn().PgConn().PID()), first)
	independent, stop := context.WithTimeout(ctx, 2*time.Second)
	defer stop()
	if _, err := f.database.CreateRouteSession(independent, sibling, f.now, time.Hour, time.Hour); err != nil {
		t.Fatalf("independent route could not start while the first route was blocked: %v", err)
	}
	if err := gate.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err := awaitIntegrationResult(t, ctx, first); err != nil {
		t.Fatal(err)
	}
}

func TestIntegrationAuthorityMutationIncludesConcurrentSessionStarts(t *testing.T) {
	for _, mutation := range []string{"role", "remove", "release"} {
		t.Run(mutation, func(t *testing.T) {
			f := newTransactionAuthorityFixture(t)
			registerCertificatePlanRelays(t, f.database, f.now)
			requests := []RouteSessionRequest{f.sessionRequest, siblingSessionRequest(t, f)}
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			// Hold both route rows so both starts can acquire their team guards.
			firstGate, err := f.database.pool.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer rollbackTestTransaction(t, firstGate)
			secondGate, err := f.database.pool.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer rollbackTestTransaction(t, secondGate)
			if _, err := controlstatedb.New(firstGate).LockRouteForSession(ctx, requests[0].RouteID); err != nil {
				t.Fatal(err)
			}
			if _, err := controlstatedb.New(secondGate).LockRouteForSession(ctx, requests[1].RouteID); err != nil {
				t.Fatal(err)
			}
			workers := newIntegrationWorkers(t, cancel)
			defer workers.stop()
			started := []chan error{make(chan error, 1), make(chan error, 1)}
			for index, request := range requests {
				workers.Go(func() {
					_, err := f.database.CreateRouteSession(ctx, request, f.now, time.Hour, time.Hour)
					started[index] <- err
				})
			}
			firstPID := waitForPostgresBlock(t, ctx, f.database, int32(firstGate.Conn().PgConn().PID()), started[0])
			secondPID := waitForPostgresBlock(t, ctx, f.database, int32(secondGate.Conn().PgConn().PID()), started[1])
			mutated := make(chan error, 1)
			workers.Go(func() {
				var err error
				switch mutation {
				case "role":
					_, err = f.database.SetMembershipRole(ctx, f.owner, f.member.TeamID, f.member.ID, "member", f.now)
				case "remove":
					err = f.database.RemoveMembership(ctx, f.owner, f.member.TeamID, f.member.ID, f.now)
				case "release":
					err = f.database.ReleaseTeamDomain(ctx, f.owner, f.member.TeamID, f.domain.ID, f.now)
				}
				mutated <- err
			})
			// PostgreSQL can wait on either member of the shared row lock first.
			waitForPostgresBlock(t, ctx, f.database, firstPID, mutated, secondPID)
			if err := firstGate.Commit(ctx); err != nil {
				t.Fatal(err)
			}
			if err := awaitIntegrationResult(t, ctx, started[0]); err != nil {
				t.Fatal(err)
			}
			// Releasing one reader must not let the mutation miss the other start.
			waitForPostgresBlock(t, ctx, f.database, secondPID, mutated)
			if err := secondGate.Commit(ctx); err != nil {
				t.Fatal(err)
			}
			if err := awaitIntegrationResult(t, ctx, started[1]); err != nil {
				t.Fatal(err)
			}
			if err := awaitIntegrationResult(t, ctx, mutated); err != nil {
				t.Fatal(err)
			}
			var closed int
			if err := f.database.pool.QueryRow(ctx, `SELECT count(*) FROM control.route_sessions WHERE team_id = $1 AND state = 'closed' AND closed_at IS NOT NULL`, f.member.TeamID).Scan(&closed); err != nil || closed != 2 {
				t.Fatalf("mutation closed %d sessions, want both concurrent starts: %v", closed, err)
			}
			for _, request := range requests {
				if _, err := f.database.CreateRouteSession(ctx, request, f.now, time.Hour, time.Hour); !errors.Is(err, ErrRouteAuthority) {
					t.Fatalf("stale session replay after %s: %v", mutation, err)
				}
			}
		})
	}
}

func TestIntegrationAuthorityMutationProgressesDuringSessionRetries(t *testing.T) {
	for _, operation := range []string{"role", "delete"} {
		t.Run(operation, func(t *testing.T) {
			f := newTransactionAuthorityFixture(t)
			registerCertificatePlanRelays(t, f.database, f.now)
			var deletion RouteSessionRequest
			if operation == "delete" {
				deletion = siblingSessionRequest(t, f)
			}
			if _, err := f.database.CreateRouteSession(t.Context(), f.sessionRequest, f.now, time.Hour, time.Hour); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			gate, err := f.database.pool.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer rollbackTestTransaction(t, gate)
			if _, err := controlstatedb.New(gate).LockRouteForSession(ctx, f.route.ID); err != nil {
				t.Fatal(err)
			}
			workers := newIntegrationWorkers(t, cancel)
			defer workers.stop()
			failed := make(chan error, 4)
			var retries atomic.Int64
			for range 4 {
				workers.Go(func() {
					for ctx.Err() == nil {
						_, err := f.database.CreateRouteSession(ctx, f.sessionRequest, f.now, time.Hour, time.Hour)
						if errors.Is(err, ErrRouteAuthority) || ctx.Err() != nil {
							return
						}
						if err != nil {
							failed <- err
							return
						}
						retries.Add(1)
					}
				})
			}
			waitForPostgresBlock(t, ctx, f.database, int32(gate.Conn().PgConn().PID()), failed)
			mutationCtx, stop := context.WithTimeout(ctx, 2*time.Second)
			defer stop()
			mutated := make(chan error, 1)
			workers.Go(func() {
				var err error
				if operation == "delete" {
					err = f.database.DeleteRoute(mutationCtx, f.member.IdentityID, deletion.RouteID, f.now)
				} else {
					_, err = f.database.SetMembershipRole(mutationCtx, f.owner, f.member.TeamID, f.member.ID, "member", f.now)
				}
				mutated <- err
			})
			if err := gate.Commit(ctx); err != nil {
				t.Fatal(err)
			}
			if err := awaitIntegrationResult(t, ctx, mutated); err != nil {
				t.Fatalf("%s failed after %d retries: %v", operation, retries.Load(), err)
			}
			workers.stop()
			if operation == "delete" {
				if _, err := f.database.GetRoute(t.Context(), f.member.IdentityID, deletion.RouteID); !errors.Is(err, ErrRouteNotFound) {
					t.Fatalf("deleted route is still visible: %v", err)
				}
				if setup, err := f.database.CreateRouteSession(t.Context(), f.sessionRequest, f.now, time.Hour, time.Hour); err != nil || setup.ClosedAt != nil {
					t.Fatalf("deletion changed the sibling's live session: %v", err)
				}
			}
			select {
			case err := <-failed:
				t.Fatal(err)
			default:
			}
		})
	}
}

func TestIntegrationConcurrentStartsOnOneRoute(t *testing.T) {
	for _, sameRequest := range []bool{true, false} {
		t.Run(fmt.Sprintf("same_request_%t", sameRequest), func(t *testing.T) {
			database, now, request, _ := newRouteSessionPrerequisites(t)
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			workers := newIntegrationWorkers(t, cancel)
			defer workers.stop()
			const callers = 8
			type result struct {
				setup RouteSessionSetup
				err   error
			}
			results := make(chan result, callers)
			start := make(chan struct{})
			for index := range callers {
				workers.Go(func() {
					candidate := request
					if !sameRequest {
						candidate.IdempotencyKey = fmt.Sprintf("start-%d", index)
						candidate.RequestDigest = sha256.Sum256([]byte(candidate.IdempotencyKey))
					}
					<-start
					setup, err := database.CreateRouteSession(ctx, candidate, now, time.Hour, time.Hour)
					results <- result{setup, err}
				})
			}
			close(start)
			var first RouteSessionSetup
			succeeded := 0
			for range callers {
				result := awaitIntegrationResult(t, ctx, results)
				if result.err != nil {
					if sameRequest || !errors.Is(result.err, ErrRouteMutationStale) {
						t.Fatal(result.err)
					}
					continue
				}
				if succeeded > 0 && (result.setup.RouteSessionID != first.RouteSessionID || result.setup.RouteSessionToken != first.RouteSessionToken || result.setup.PublisherConnections != first.PublisherConnections) {
					t.Fatal("concurrent retries returned different session credentials or assignments")
				}
				first = result.setup
				succeeded++
			}
			want := 1
			if sameRequest {
				want = callers
			}
			if succeeded != want || first.RouteVersion != 1 {
				t.Fatalf("successful starts=%d route version=%d; want %d/1", succeeded, first.RouteVersion, want)
			}
			var sessions, connections int
			if err := database.pool.QueryRow(ctx, `SELECT (SELECT count(*) FROM control.route_sessions), (SELECT count(*) FROM control.route_session_connections)`).Scan(&sessions, &connections); err != nil || sessions != 1 || connections != 2 {
				t.Fatalf("stored sessions/connections=%d/%d; want 1/2: %v", sessions, connections, err)
			}
		})
	}
}

func siblingSessionRequest(t *testing.T, f transactionAuthorityFixture) RouteSessionRequest {
	t.Helper()
	request := f.createRequest
	request.IdempotencyKey = "sibling"
	request.RequestDigest = sha256.Sum256([]byte("sibling"))
	request.CanonicalHostname = "sibling.member." + f.domain.CanonicalDomain
	route, err := f.database.CreateRoute(t.Context(), request, f.now)
	if err != nil {
		t.Fatal(err)
	}
	session := f.sessionRequest
	session.RouteID, session.ExpectedMutationRevision = route.ID, route.MutationRevision
	session.CertificateCacheKey, session.CertificateScope = route.CanonicalHostname, route.CanonicalHostname
	session.CertificateIdentifiers = []string{route.CanonicalHostname}
	return session
}

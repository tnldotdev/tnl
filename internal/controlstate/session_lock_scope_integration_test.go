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
	if _, err := controlstatedb.New(gate).LockPublicURLForRun(ctx, f.route.ID); err != nil {
		t.Fatal(err)
	}
	workers := newIntegrationWorkers(t, cancel)
	defer workers.stop()
	first := make(chan error, 1)
	workers.Go(func() {
		_, err := f.database.CreatePublishRun(ctx, f.sessionRequest, f.now, time.Hour, time.Hour)
		first <- err
	})
	// The first start holds its team guard while blocked on its own route.
	waitForPostgresBlock(t, ctx, f.database, int32(gate.Conn().PgConn().PID()), first)
	independent, stop := context.WithTimeout(ctx, 2*time.Second)
	defer stop()
	if _, err := f.database.CreatePublishRun(independent, sibling, f.now, time.Hour, time.Hour); err != nil {
		t.Fatalf("independent route could not start while the first route was blocked: %v", err)
	}
	if err := gate.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err := awaitIntegrationResult(t, ctx, first); err != nil {
		t.Fatal(err)
	}
}

func TestIntegrationHeartbeatProgressesWithUsageRouteReference(t *testing.T) {
	f := newPublishRunFixture(t)
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	usage, err := f.database.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer rollbackTestTransaction(t, usage)
	if _, err := controlstatedb.New(usage).LockPublicURLForUsage(ctx, f.setup.PublicURLID); err != nil {
		t.Fatal(err)
	}
	// Usage retains this reference until its page commits. A heartbeat may
	// serialize on the session, but must not wait for a route identity reference.
	if _, err := f.database.HeartbeatPublishRun(ctx, f.authentication(), f.now.Add(time.Second), time.Hour, time.Hour); err != nil {
		t.Fatalf("heartbeat blocked behind usage's route reference: %v", err)
	}
}

func TestIntegrationAuthorityMutationIncludesConcurrentSessionStarts(t *testing.T) {
	for _, mutation := range []string{"role", "remove", "release"} {
		t.Run(mutation, func(t *testing.T) {
			f := newTransactionAuthorityFixture(t)
			registerCertificatePlanRelays(t, f.database, f.now)
			requests := []PublishRunRequest{f.sessionRequest, siblingSessionRequest(t, f)}
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
			if _, err := controlstatedb.New(firstGate).LockPublicURLForRun(ctx, requests[0].PublicURLID); err != nil {
				t.Fatal(err)
			}
			if _, err := controlstatedb.New(secondGate).LockPublicURLForRun(ctx, requests[1].PublicURLID); err != nil {
				t.Fatal(err)
			}
			workers := newIntegrationWorkers(t, cancel)
			defer workers.stop()
			started := []chan error{make(chan error, 1), make(chan error, 1)}
			for index, request := range requests {
				workers.Go(func() {
					_, err := f.database.CreatePublishRun(ctx, request, f.now, time.Hour, time.Hour)
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
			if err := f.database.pool.QueryRow(ctx, `SELECT count(*) FROM control.publish_runs WHERE team_id = $1 AND state = 'closed' AND closed_at IS NOT NULL`, f.member.TeamID).Scan(&closed); err != nil || closed != 2 {
				t.Fatalf("mutation closed %d sessions, want both concurrent starts: %v", closed, err)
			}
			for _, request := range requests {
				if _, err := f.database.CreatePublishRun(ctx, request, f.now, time.Hour, time.Hour); !errors.Is(err, ErrPublicURLAuthority) {
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
			var deletion PublishRunRequest
			if operation == "delete" {
				deletion = siblingSessionRequest(t, f)
			}
			if _, err := f.database.CreatePublishRun(t.Context(), f.sessionRequest, f.now, time.Hour, time.Hour); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			gate, err := f.database.pool.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer rollbackTestTransaction(t, gate)
			if _, err := controlstatedb.New(gate).LockPublicURLForRun(ctx, f.route.ID); err != nil {
				t.Fatal(err)
			}
			workers := newIntegrationWorkers(t, cancel)
			defer workers.stop()
			failed := make(chan error, 4)
			var retries atomic.Int64
			for range 4 {
				workers.Go(func() {
					for ctx.Err() == nil {
						_, err := f.database.CreatePublishRun(ctx, f.sessionRequest, f.now, time.Hour, time.Hour)
						if errors.Is(err, ErrPublicURLAuthority) || ctx.Err() != nil {
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
					err = f.database.DeletePublicURL(mutationCtx, f.member.IdentityID, deletion.PublicURLID, f.now)
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
				if _, err := f.database.GetPublicURL(t.Context(), f.member.IdentityID, deletion.PublicURLID); !errors.Is(err, ErrPublicURLNotFound) {
					t.Fatalf("deleted route is still visible: %v", err)
				}
				if setup, err := f.database.CreatePublishRun(t.Context(), f.sessionRequest, f.now, time.Hour, time.Hour); err != nil || setup.ClosedAt != nil {
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

func TestIntegrationConcurrentStartsOnOnePublicURL(t *testing.T) {
	for _, sameRequest := range []bool{true, false} {
		t.Run(fmt.Sprintf("same_request_%t", sameRequest), func(t *testing.T) {
			database, now, request, _ := newPublishRunPrerequisites(t)
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			workers := newIntegrationWorkers(t, cancel)
			defer workers.stop()
			const callers = 8
			type result struct {
				setup PublishRunSetup
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
					setup, err := database.CreatePublishRun(ctx, candidate, now, time.Hour, time.Hour)
					results <- result{setup, err}
				})
			}
			close(start)
			var first PublishRunSetup
			succeeded := 0
			for range callers {
				result := awaitIntegrationResult(t, ctx, results)
				if result.err != nil {
					if sameRequest || !errors.Is(result.err, ErrPublicURLMutationStale) {
						t.Fatal(result.err)
					}
					continue
				}
				if succeeded > 0 && (result.setup.PublishRunID != first.PublishRunID || result.setup.PublishRunToken != first.PublishRunToken || result.setup.PublisherConnections != first.PublisherConnections) {
					t.Fatal("concurrent retries returned different session credentials or assignments")
				}
				first = result.setup
				succeeded++
			}
			want := 1
			if sameRequest {
				want = callers
			}
			if succeeded != want || first.PublishRunNumber != 1 {
				t.Fatalf("successful starts=%d publish run number=%d; want %d/1", succeeded, first.PublishRunNumber, want)
			}
			var sessions, connections int
			if err := database.pool.QueryRow(ctx, `SELECT (SELECT count(*) FROM control.publish_runs), (SELECT count(*) FROM control.publish_run_connections)`).Scan(&sessions, &connections); err != nil || sessions != 1 || connections != 2 {
				t.Fatalf("stored sessions/connections=%d/%d; want 1/2: %v", sessions, connections, err)
			}
		})
	}
}

func siblingSessionRequest(t *testing.T, f transactionAuthorityFixture) PublishRunRequest {
	t.Helper()
	request := f.createRequest
	request.IdempotencyKey = "sibling"
	request.RequestDigest = sha256.Sum256([]byte("sibling"))
	request.CanonicalHostname = "sibling.member." + f.domain.CanonicalDomain
	route, err := f.database.CreatePublicURL(t.Context(), request, f.now)
	if err != nil {
		t.Fatal(err)
	}
	session := f.sessionRequest
	session.PublicURLID, session.ExpectedMutationRevision = route.ID, route.MutationRevision
	session.CertificateCacheKey, session.CertificateScope = route.CanonicalHostname, route.CanonicalHostname
	session.CertificateIdentifiers = []string{route.CanonicalHostname}
	return session
}

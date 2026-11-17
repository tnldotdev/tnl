package state

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/failure"
)

func TestIntegrationServiceRunStartsOnDifferentServicesSharePlacement(t *testing.T) {
	f := newServicePublicationFixture(t)
	// close fixture's open run so this test controls starts.
	if err := f.database.CloseServiceRun(t.Context(), f.service.ID, f.run.RunID, f.run.Token, f.now); err != nil {
		t.Fatal(err)
	}
	sibling := f.sibling(t, "sibling", f.now)
	var err error
	f.prepared, err = f.database.PrepareServiceRun(t.Context(), f.service.ID, f.publisher, "blocked", f.now, ServiceRunRequest{Metadata: f.service.ServiceMetadata})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	gate, err := f.database.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer rollbackTestTransaction(t, gate)
	if _, err := controlstatedb.New(gate).LockService(ctx, f.service.ID); err != nil {
		t.Fatal(err)
	}
	workers := newIntegrationWorkers(t, cancel)
	defer workers.stop()
	first := make(chan error, 1)
	workers.Go(func() {
		_, err := f.database.StartServiceRun(ctx, f.service.ID, f.prepared.RunID, f.prepared.RunNumber, f.publisher, f.now)
		first <- err
	})
	// the first start holds team/service admission while blocked on its own service.
	waitForPostgresBlock(t, ctx, f.database, int32(gate.Conn().PgConn().PID()), first)
	independent, stop := context.WithTimeout(ctx, 2*time.Second)
	defer stop()
	prepared, err := sibling.database.PrepareServiceRun(independent, sibling.service.ID, sibling.publisher, "independent", f.now, ServiceRunRequest{Metadata: sibling.service.ServiceMetadata})
	if err != nil {
		t.Fatalf("independent service could not start while the first service was blocked: %v", err)
	}
	if _, err := sibling.database.StartServiceRun(independent, sibling.service.ID, prepared.RunID, prepared.RunNumber, sibling.publisher, f.now); err != nil {
		t.Fatalf("independent service run did not start: %v", err)
	}
	if err := gate.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err := awaitIntegrationResult(t, ctx, first); err != nil {
		t.Fatal(err)
	}
}

func TestIntegrationHeartbeatProgressesWithServiceReference(t *testing.T) {
	f := newServicePublicationFixture(t)
	installPrivateTestCertificate(t, f.database, f.prepared, f.run, f.now)
	f.readyConnections(t, f.now)
	ready, err := f.database.HeartbeatServiceRun(t.Context(), f.service.ID, f.run.RunID, f.run.Token, f.now, ServiceRunHealth{Healthy: true, StreamCapacity: 64})
	if err != nil || ready.State != "ready" {
		t.Fatal(ready, err)
	}
	ready.Token = f.run.Token
	f.run = ready
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	reference, err := f.database.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer rollbackTestTransaction(t, reference)
	if _, err := reference.Exec(ctx, `SELECT id FROM control.services WHERE id=$1 FOR KEY SHARE`, f.service.ID); err != nil {
		t.Fatal(err)
	}
	// a heartbeat may serialize on the service run, but must not wait for a
	// transaction retaining a service identity reference.
	if _, err := f.database.HeartbeatServiceRun(ctx, f.service.ID, f.run.RunID, f.run.Token, f.run.ExpiresAt.Add(-time.Second), ServiceRunHealth{Healthy: true, StreamCapacity: 64}); err != nil {
		t.Fatalf("heartbeat blocked behind a service reference: %v", err)
	}
}

func TestIntegrationAuthorityMutationIncludesConcurrentServiceStarts(t *testing.T) {
	for _, mutation := range []string{"role", "remove", "release"} {
		t.Run(mutation, func(t *testing.T) {
			owner, member, domain, fixtures := sessionLockAuthorityFixtures(t)
			f, sibling := fixtures[0], fixtures[1]
			ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
			defer cancel()
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
			if _, err := controlstatedb.New(firstGate).LockService(ctx, f.service.ID); err != nil {
				t.Fatal(err)
			}
			if _, err := controlstatedb.New(secondGate).LockService(ctx, sibling.service.ID); err != nil {
				t.Fatal(err)
			}
			workers := newIntegrationWorkers(t, cancel)
			defer workers.stop()
			started := []chan error{make(chan error, 1), make(chan error, 1)}
			for index := range fixtures {
				workers.Go(func() {
					fixture := &fixtures[index]
					run, err := fixture.database.StartServiceRun(ctx, fixture.service.ID, fixture.prepared.RunID, fixture.prepared.RunNumber, fixture.publisher, fixture.now)
					fixture.run = run
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
					_, err = f.database.SetMembershipRole(ctx, owner, f.service.TeamID, member.ID, TeamRoleMember, f.now)
				case "remove":
					err = f.database.RemoveMembership(ctx, owner, f.service.TeamID, member.ID, f.now)
				case "release":
					err = f.database.ReleaseTeamDomain(ctx, owner, f.service.TeamID, domain.ID, f.now)
				}
				mutated <- err
			})
			// postgres may wait on either shared team-row holder first.
			waitForPostgresBlock(t, ctx, f.database, firstPID, mutated, secondPID)
			if err := firstGate.Commit(ctx); err != nil {
				t.Fatal(err)
			}
			if err := awaitIntegrationResult(t, ctx, started[0]); err != nil {
				t.Fatal(err)
			}
			// releasing one waiter must not let the mutation miss the other start.
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
			var closed, slots int
			if err := f.database.pool.QueryRow(ctx, `SELECT
				(SELECT count(*) FROM control.service_runs WHERE team_id=$1 AND state='closed' AND closed_at IS NOT NULL AND NOT assignments_open),
				(SELECT count(*) FROM control.service_connection_slots slot JOIN control.service_runs run ON run.id=slot.service_run_id
				 WHERE run.team_id=$1 AND NOT slot.session_open)`, member.TeamID).Scan(&closed, &slots); err != nil || closed != 2 || slots != 4 {
				t.Fatalf("mutation closed runs/slots=%d/%d, want 2/4: %v", closed, slots, err)
			}
			for _, fixture := range fixtures {
				if fixture.run.Token == "" || len(fixture.run.Connections) != 2 {
					t.Fatal("concurrent start omitted run credentials or assignments")
				}
				if _, err := fixture.database.StartServiceRun(ctx, fixture.service.ID, fixture.run.RunID, fixture.run.RunNumber, fixture.publisher, f.now); !errors.Is(err, ErrServiceAccess) {
					t.Fatalf("stale service run replay after %s: %v", mutation, err)
				}
				if _, err := fixture.database.HeartbeatServiceRun(ctx, fixture.service.ID, fixture.run.RunID, fixture.run.Token, f.now, ServiceRunHealth{StreamCapacity: 64}); !errors.Is(err, ErrServiceAccess) {
					t.Fatalf("closed service run heartbeat after %s: %v", mutation, err)
				}
				// demotion closes the captured run, but a member-owned publisher
				// retains its explicit grant. the original key must not revive it.
				want := ErrServiceAccess
				if mutation == "role" {
					want = ErrServiceConflict
				}
				if _, err := fixture.database.PrepareServiceRun(ctx, fixture.service.ID, fixture.publisher, fixture.prepared.IdempotencyKey, f.now, ServiceRunRequest{Metadata: fixture.service.ServiceMetadata}); !errors.Is(err, want) {
					t.Fatalf("stale preparation replay after %s: %v, want %v", mutation, err, want)
				}
			}
		})
	}
}

func TestIntegrationAuthorityMutationProgressesDuringRunRetries(t *testing.T) {
	for _, operation := range []string{"role", "delete"} {
		t.Run(operation, func(t *testing.T) {
			owner, member, _, fixtures := sessionLockAuthorityFixtures(t)
			f, deletion := fixtures[0], fixtures[1]
			var err error
			f.run, err = f.database.StartServiceRun(t.Context(), f.service.ID, f.prepared.RunID, f.prepared.RunNumber, f.publisher, f.now)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			gate, err := f.database.pool.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer rollbackTestTransaction(t, gate)
			if _, err := controlstatedb.New(gate).LockService(ctx, f.service.ID); err != nil {
				t.Fatal(err)
			}
			workers := newIntegrationWorkers(t, cancel)
			defer workers.stop()
			failed := make(chan error, 4)
			var retries atomic.Int64
			var stopRetries atomic.Bool
			for range 4 {
				workers.Go(func() {
					for !stopRetries.Load() && ctx.Err() == nil {
						run, err := f.database.StartServiceRun(ctx, f.service.ID, f.run.RunID, f.run.RunNumber, f.publisher, f.now)
						if err != nil {
							if operation == "role" && errors.Is(err, ErrServiceAccess) || ctx.Err() != nil && failure.Only(err, ctx.Err()) {
								return
							}
							failed <- err
							return
						}
						if run.Token != f.run.Token || !slices.Equal(run.Connections, f.run.Connections) {
							failed <- errors.New("start retry changed the live run credential or assignments")
							return
						}
						retries.Add(1)
					}
				})
			}
			retryPID := waitForPostgresBlock(t, ctx, f.database, int32(gate.Conn().PgConn().PID()), failed)
			mutationCtx, stop := context.WithTimeout(ctx, 2*time.Second)
			defer stop()
			mutated := make(chan error, 1)
			workers.Go(func() {
				var err error
				if operation == "delete" {
					err = f.database.DeleteService(mutationCtx, deletion.service.ID, member.IdentityID, observedServiceDeletion(t, f.database, deletion.service.ID), f.now)
				} else {
					_, err = f.database.SetMembershipRole(mutationCtx, owner, f.service.TeamID, member.ID, TeamRoleMember, f.now)
				}
				mutated <- err
			})
			// observe the writer queued behind a real retry before allowing any
			// reader to commit and race for the next shared admission.
			waitForPostgresBlock(t, ctx, f.database, retryPID, mutated)
			if err := gate.Commit(ctx); err != nil {
				t.Fatal(err)
			}
			if err := awaitIntegrationResult(t, ctx, mutated); err != nil {
				t.Fatalf("%s failed after %d retries: %v", operation, retries.Load(), err)
			}
			// finish in-flight operations under their original context before
			// cancellation can turn successful cleanup into a rollback failure.
			stopRetries.Store(true)
			workers.Wait()
			workers.stop()
			if operation == "delete" {
				if _, err := f.database.GetService(t.Context(), deletion.service.ID, member.IdentityID); !errors.Is(err, ErrServiceAccess) {
					t.Fatalf("deleted service is still visible: %v", err)
				}
				run, err := f.database.StartServiceRun(t.Context(), f.service.ID, f.run.RunID, f.run.RunNumber, f.publisher, f.now)
				if err != nil || run.RunID != f.run.RunID || run.Token != f.run.Token || !slices.Equal(run.Connections, f.run.Connections) {
					t.Fatalf("deletion changed the sibling's live run: %v", err)
				}
			} else {
				var role string
				if err := f.database.pool.QueryRow(t.Context(), `SELECT role FROM control.team_memberships WHERE id=$1`, member.ID).Scan(&role); err != nil || role != string(TeamRoleMember) {
					t.Fatalf("role mutation did not commit: role=%s err=%v", role, err)
				}
				if _, err := f.database.StartServiceRun(t.Context(), f.service.ID, f.run.RunID, f.run.RunNumber, f.publisher, f.now); !errors.Is(err, ErrServiceAccess) {
					t.Fatalf("role mutation left the captured run live: %v", err)
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

func TestIntegrationConcurrentStartsOnOneService(t *testing.T) {
	for _, sameRequest := range []bool{true, false} {
		t.Run(fmt.Sprintf("same_request_%t", sameRequest), func(t *testing.T) {
			base := newServicePublicationFixture(t)
			f := base.sibling(t, "concurrent", base.now)
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			workers := newIntegrationWorkers(t, cancel)
			defer workers.stop()
			const callers = 8
			type result struct {
				prep ServiceRunPreparation
				err  error
			}
			results := make(chan result, callers)
			start := make(chan struct{})
			for index := range callers {
				workers.Go(func() {
					key := "same"
					if !sameRequest {
						key = fmt.Sprintf("start-%d", index)
					}
					<-start
					prep, err := f.database.PrepareServiceRun(ctx, f.service.ID, f.publisher, key, f.now, ServiceRunRequest{Metadata: f.service.ServiceMetadata})
					results <- result{prep, err}
				})
			}
			close(start)
			var first ServiceRunPreparation
			succeeded := 0
			for range callers {
				r := awaitIntegrationResult(t, ctx, results)
				if r.err != nil {
					if sameRequest || !errors.Is(r.err, ErrServiceConflict) {
						t.Fatal(r.err)
					}
					continue
				}
				if succeeded > 0 && (r.prep.RunID != first.RunID || r.prep.RunNumber != first.RunNumber) {
					t.Fatal("concurrent preparation retries returned different runs")
				}
				first = r.prep
				succeeded++
			}
			want := 1
			if sameRequest {
				want = callers
			}
			if succeeded != want || first.RunNumber != 1 {
				t.Fatalf("successful preparations=%d run number=%d; want %d/1", succeeded, first.RunNumber, want)
			}
			type startResult struct {
				run ServiceRunState
				err error
			}
			starts := make(chan startResult, succeeded)
			commit := make(chan struct{})
			for range succeeded {
				workers.Go(func() {
					<-commit
					run, err := f.database.StartServiceRun(ctx, f.service.ID, first.RunID, first.RunNumber, f.publisher, f.now)
					starts <- startResult{run, err}
				})
			}
			close(commit)
			var run ServiceRunState
			for index := range succeeded {
				result := awaitIntegrationResult(t, ctx, starts)
				if result.err != nil {
					t.Fatal(result.err)
				}
				if result.run.Token == "" || len(result.run.Connections) != 2 {
					t.Fatal("start omitted its run credential or assignments")
				}
				if result.run.Connections[0].ConnectionSlot != 0 || result.run.Connections[1].ConnectionSlot != 1 ||
					result.run.Connections[0].PublisherConnectionID == result.run.Connections[1].PublisherConnectionID ||
					result.run.Connections[0].RelayServiceID == result.run.Connections[1].RelayServiceID {
					t.Fatal("start did not assign two distinct connection slots and relay services")
				}
				if index > 0 && (result.run.RunID != run.RunID || result.run.RunNumber != run.RunNumber || result.run.Token != run.Token || !slices.Equal(result.run.Connections, run.Connections)) {
					t.Fatal("concurrent retries returned different run credentials or assignments")
				}
				run = result.run
			}
			var runs, slots int
			if err := f.database.pool.QueryRow(ctx, `SELECT (SELECT count(*) FROM control.service_runs WHERE service_id=$1), (SELECT count(*) FROM control.service_connection_slots WHERE service_id=$1)`, f.service.ID).Scan(&runs, &slots); err != nil || runs != 1 || slots != 2 {
				t.Fatalf("stored runs/slots=%d/%d; want 1/2: %v", runs, slots, err)
			}
		})
	}
}

func sessionLockAuthorityFixtures(t *testing.T) (string, Membership, Domain, []servicePublicationFixture) {
	t.Helper()
	database, now, owner, team := newAuthorityTeam(t)
	_, member := allocationVisitorMember(t, database, team.ID, owner, "run-admin", TeamRoleAdmin, now)
	domain, err := database.ClaimTeamDomain(t.Context(), ClaimDomainRequest{
		IdentityID: owner, TeamID: team.ID, Domain: "session-lock.example.test",
		IdempotencyKey: "session-domain", RequestDigest: sha256.Sum256([]byte("session-domain")),
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	work, found, err := database.ClaimDNSAuthorityWork(t.Context(), "session-lock", now, time.Minute)
	if err != nil || !found || work.Reference != domain.DNSAuthorityReference {
		t.Fatal("custom domain authority was not queued", found, err)
	}
	work.State, work.ProviderZoneID, work.Nameservers = "ready", "ZSESSION", []string{"ns-1.example.test"}
	if _, err := database.SaveDNSAuthorityWork(t.Context(), work, now); err != nil {
		t.Fatal(err)
	}
	registerCertificatePlanRelays(t, database, now)
	fixtures := make([]servicePublicationFixture, 2)
	for index := range fixtures {
		name := fmt.Sprintf("service-%d", index)
		service, err := database.CreateServiceAt(t.Context(), team.ID, member.IdentityID, name, name,
			ServicePlacement{DomainID: domain.ID}, now, ServiceMetadata{}, &ProjectServiceConfiguration{Target: "localhost:3000"})
		if err != nil {
			t.Fatal(err)
		}
		if service.DomainID != domain.ID {
			t.Fatal("fixture did not select the releasable custom domain")
		}
		actor, err := controlstatedb.New(database.pool).GetTeamActorContext(t.Context(), controlstatedb.GetTeamActorContextParams{TeamID: team.ID, IdentityID: member.IdentityID})
		if err != nil {
			t.Fatal(err)
		}
		enrollment, err := database.IssuePublisherEnrollment(t.Context(), CreatePublisherEnrollmentRequest{
			Scope: PublisherScope{TeamID: team.ID, Kind: "service", ServiceID: service.ID}, Ownership: "member",
			Name: name, Kind: "installed", EditorID: member.IdentityID, EditorMembershipID: member.ID,
			PolicyRevision: uint64(actor.PolicyRevision), Now: now,
		})
		if err != nil {
			t.Fatal(err)
		}
		public, _, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		publisher, err := database.RedeemPublisherEnrollment(t.Context(), enrollment.Key, public, now)
		if err != nil {
			t.Fatal(err)
		}
		prepared, err := database.PrepareServiceRun(t.Context(), service.ID, publisher, "concurrent", now, ServiceRunRequest{Metadata: service.ServiceMetadata})
		if err != nil {
			t.Fatal(err)
		}
		fixtures[index] = servicePublicationFixture{database: database, now: now, service: service, publisher: publisher, prepared: prepared}
	}
	return owner, member, domain, fixtures
}

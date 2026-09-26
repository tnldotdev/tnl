package controlstate

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/controlstate/controlstatedb"
)

func TestIntegrationACMEChallengeIgnoresUnrelatedHeartbeats(t *testing.T) {
	f := newPublishRunFixture(t)
	database, now := f.database, f.now
	ingress := registerTestIngress(t, database, now)
	// A second, fully ready route publishes genuine heartbeat projections.
	seedControlPublicURL(t, database, now, "unrelated")
	healthy := f
	healthy.request.PublicURLID, healthy.request.TeamID = "public_url_unrelated", "team_unrelated"
	healthy.request.ActingIdentityID, healthy.request.MembershipID = "identity_unrelated", "membership_unrelated"
	healthy.request.CertificateCacheKey = "certificate_unrelated"
	healthy.request.CertificateIdentifiers = []string{"route-unrelated.example.test"}
	var err error
	healthy.setup, err = database.CreatePublishRun(t.Context(), healthy.request, now, time.Minute, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	readyTestSession(t, healthy)
	claimTestConnection(t, f, 0, now)
	prepared := createPlanIssuanceWork(t, database, now, f.authentication(), f.certificatePlan(), false, func(work *ACMEOrderWork) {
		work.Authorizations[0].AuthorizationURL = "https://acme.example.test/authz/pending"
		work.Authorizations[0].ChallengeURL = "https://acme.example.test/challenge/pending"
	})
	if _, err := database.MarkCertificateChallengeReady(t.Context(), prepared.ID, f.setup.PublishRunToken, now); err != nil {
		t.Fatal(err)
	}
	page, err := database.ReadIngressRoutingTableEvents(t.Context(), ingress.IngressLeaseIdentity, 0, 100, now)
	if err != nil || len(page.Events) == 0 || page.Events[len(page.Events)-1].Kind != IngressChallengeUpsert {
		t.Fatalf("challenge publication: %v", err)
	}
	renewACMEBarrierIngress(t, database, ingress, page.ThroughRevision, now, time.Hour)
	for step := 1; step <= 3; step++ {
		at := now.Add(time.Duration(step) * time.Second)
		if _, err := database.HeartbeatPublishRun(t.Context(), healthy.authentication(), at, time.Minute, time.Minute); err != nil {
			t.Fatal(err)
		}
		work, found, err := database.ClaimACMEOrderWork(t.Context(), "challenge-worker", at, time.Minute)
		if err != nil || !found || work.ID != prepared.ID {
			t.Fatalf("unrelated heartbeat %d blocked an acknowledged challenge: found=%t error=%v", step, found, err)
		}
		// Keep the authorization presented to exercise the next publication too.
		if _, err := database.SaveACMEOrderWork(t.Context(), work, at); err != nil {
			t.Fatal(err)
		}
	}
	// Changes to the challenge's own forwarding projection still need acknowledgement.
	at := now.Add(4 * time.Second)
	if _, err := database.HeartbeatPublishRun(t.Context(), f.authentication(), at, time.Minute, time.Minute); err != nil {
		t.Fatal(err)
	}
	if _, found, err := database.ClaimACMEOrderWork(t.Context(), "before-new-projection", at, time.Minute); err != nil || found {
		t.Fatalf("claimed before updated challenge was applied: found=%t error=%v", found, err)
	}
	page, err = database.ReadIngressRoutingTableEvents(t.Context(), ingress.IngressLeaseIdentity, page.ThroughRevision, 100, at)
	if err != nil || len(page.Events) != 4 || page.Events[3].Kind != IngressChallengeUpsert {
		t.Fatalf("heartbeat publications: events=%d error=%v", len(page.Events), err)
	}
	renewACMEBarrierIngress(t, database, ingress, page.ThroughRevision, at, time.Hour)
	work, found, err := database.ClaimACMEOrderWork(t.Context(), "after-new-projection", at, time.Minute)
	if err != nil || !found || work.ID != prepared.ID {
		t.Fatalf("updated challenge was not claimable: found=%t error=%v", found, err)
	}
}

func TestIntegrationACMEChallengeReadyRequeuesClaimedWork(t *testing.T) {
	for _, nextWorker := range []string{"original", "replacement"} {
		t.Run(nextWorker, func(t *testing.T) {
			f := newPublishRunFixture(t)
			database, now := f.database, f.now
			firstIngress := registerTestIngress(t, database, now)
			secondIngress, err := database.RegisterIngress(t.Context(), IngressRegistration{
				IngressID: "second", IngressRunID: "second-run", ProtocolVersion: 1, ConnectionCapacity: 100,
			}, now, time.Hour)
			if err != nil {
				t.Fatal(err)
			}
			claimTestConnection(t, f, 0, now)
			prepared := createPlanIssuanceWork(t, database, now, f.authentication(), f.certificatePlan(), false, func(work *ACMEOrderWork) {
				work.OrderURL = "https://acme.example.test/order/1"
				work.FinalizeURL = "https://acme.example.test/finalize/1"
			})
			original, found, err := database.ClaimACMEOrderWork(t.Context(), "original", now, 2*time.Minute)
			if err != nil || !found || original.ID != prepared.ID || original.Authorizations[0].State != "presenting" {
				t.Fatalf("claim presenting work: found %t, error %v", found, err)
			}

			// The worker has a snapshot, then the publisher acknowledges the challenge
			// while the worker is outside PostgreSQL talking to the CA.
			at := now.Add(time.Second)
			if _, err := database.MarkCertificateChallengeReady(t.Context(), original.ID, f.setup.PublishRunToken, at); err != nil {
				t.Fatal(err)
			}
			original.AvailableAt = now.Add(time.Hour)
			if _, err := database.SaveACMEOrderWork(t.Context(), original, at); !errors.Is(err, ErrACMEWorkStale) {
				t.Fatalf("save pre-acknowledgement snapshot: %v", err)
			}
			page, err := database.ReadIngressRoutingTableEvents(t.Context(), firstIngress.IngressLeaseIdentity, 0, 10, at)
			if err != nil || len(page.Events) != 1 || page.Events[0].Kind != IngressChallengeUpsert {
				t.Fatalf("challenge publication: %d events, error %v", len(page.Events), err)
			}
			for _, ingress := range []IngressLease{firstIngress, secondIngress} {
				if _, found, err := database.ClaimACMEOrderWork(t.Context(), nextWorker, at, 2*time.Minute); err != nil || found {
					t.Fatalf("claim before every ingress applied the challenge: found %t, error %v", found, err)
				}
				if _, err := database.RenewIngress(t.Context(), IngressRenewal{
					IngressLeaseIdentity: ingress.IngressLeaseIdentity, RoutingTableRevision: page.ThroughRevision,
				}, at, time.Hour); err != nil {
					t.Fatal(err)
				}
			}
			current, found, err := database.ClaimACMEOrderWork(t.Context(), nextWorker, at, 2*time.Minute)
			if err != nil || !found {
				t.Fatalf("order was not reclaimable one second into its two-minute lease: found %t, error %v", found, err)
			}
			if current.ID != original.ID || current.OrderURL != original.OrderURL || current.FinalizeURL != original.FinalizeURL ||
				current.WorkEpoch != original.WorkEpoch+1 || current.WorkerID != nextWorker ||
				current.Authorizations[0].State != "presented" || current.Authorizations[0].Revision != original.Authorizations[0].Revision+1 {
				t.Fatal("reclaim did not preserve the order and load the acknowledged authorization with a new work epoch")
			}

			// A late save must also reject an old epoch when the same worker reclaims.
			if _, err := database.SaveACMEOrderWork(t.Context(), original, at); !errors.Is(err, ErrACMEWorkStale) {
				t.Fatalf("old worker overwrote the replacement claim: %v", err)
			}
			queries := controlstatedb.New(database.pool)
			beforeReplay, err := queries.GetACMEOrder(t.Context(), original.ID)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := database.MarkCertificateChallengeReady(t.Context(), original.ID, f.setup.PublishRunToken, at.Add(time.Second)); err != nil {
				t.Fatal(err)
			}
			afterReplay, err := queries.GetACMEOrder(t.Context(), original.ID)
			if err != nil || !reflect.DeepEqual(afterReplay, beforeReplay) {
				t.Fatalf("acknowledgement replay changed an active work claim: %v", err)
			}
			if _, found, err := database.ClaimACMEOrderWork(t.Context(), "competitor", at.Add(time.Second), time.Minute); err != nil || found {
				t.Fatalf("competing claim after acknowledgement replay: found %t, error %v", found, err)
			}
			current.Authorizations[0].State = "validating"
			current.Authorizations[0].Attempts++
			current.AvailableAt = now.Add(time.Minute)
			saved, err := database.SaveACMEOrderWork(t.Context(), current, at.Add(time.Second))
			if err != nil || saved.Authorizations[0].State != "validating" || saved.Authorizations[0].PresentedAt == nil {
				t.Fatalf("reclaimed work did not advance validation: %v", err)
			}
			if _, err := database.MarkCertificateChallengeReady(t.Context(), original.ID, f.setup.PublishRunToken, at.Add(2*time.Second)); err != nil {
				t.Fatal(err)
			}
			if _, found, err := database.ClaimACMEOrderWork(t.Context(), "competitor", at.Add(2*time.Second), time.Minute); err != nil || found {
				t.Fatalf("acknowledgement replay bypassed the next poll time: found %t, error %v", found, err)
			}
			page, err = database.ReadIngressRoutingTableEvents(t.Context(), firstIngress.IngressLeaseIdentity, page.ThroughRevision, 10, at.Add(2*time.Second))
			if err != nil || len(page.Events) != 0 {
				t.Fatalf("acknowledgement replay published extra routing events: %d events, error %v", len(page.Events), err)
			}
		})
	}
}

func TestIntegrationACMEChallengeReadyRollbackPreservesClaim(t *testing.T) {
	f := newPublishRunFixture(t)
	database, now := f.database, f.now
	ingress := registerTestIngress(t, database, now)
	claimTestConnection(t, f, 0, now)
	prepared := createPlanIssuanceWork(t, database, now, f.authentication(), f.certificatePlan(), false, nil)
	work, found, err := database.ClaimACMEOrderWork(t.Context(), "original", now, 2*time.Minute)
	if err != nil || !found || work.ID != prepared.ID {
		t.Fatalf("claim prerequisite: found %t, error %v", found, err)
	}
	queries := controlstatedb.New(database.pool)
	before, err := queries.GetACMEOrder(t.Context(), work.ID)
	if err != nil {
		t.Fatal(err)
	}
	beforeAuthorizations, err := queries.ListACMEOrderAuthorizations(t.Context(), work.ID)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	clock, err := database.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer rollbackTestTransaction(t, clock)
	if _, err := controlstatedb.New(clock).LockIngressRoutingTableClock(ctx); err != nil {
		t.Fatal(err)
	}
	operationCtx, stopOperation := context.WithCancel(ctx)
	workers := newIntegrationWorkers(t, stopOperation)
	defer workers.stop()
	done := make(chan error, 1)
	workers.Go(func() {
		_, err := database.MarkCertificateChallengeReady(operationCtx, work.ID, f.setup.PublishRunToken, now.Add(time.Second))
		done <- err
	})
	// Publication is the final command, after both the authorization transition
	// and work invalidation. Cancel there to exercise rollback of all three.
	waitForPostgresBlock(t, ctx, database, int32(clock.Conn().PgConn().PID()), done)
	stopOperation()
	if err := awaitIntegrationResult(t, ctx, done); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancel blocked acknowledgement: %v", err)
	}
	if err := clock.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	after, err := queries.GetACMEOrder(ctx, work.ID)
	if err != nil || !reflect.DeepEqual(after, before) {
		t.Fatalf("rolled-back acknowledgement changed the work claim: %v", err)
	}
	afterAuthorizations, err := queries.ListACMEOrderAuthorizations(ctx, work.ID)
	if err != nil || !reflect.DeepEqual(afterAuthorizations, beforeAuthorizations) {
		t.Fatalf("rolled-back acknowledgement changed authorizations: %v", err)
	}
	page, err := database.ReadIngressRoutingTableEvents(ctx, ingress.IngressLeaseIdentity, 0, 10, now.Add(time.Second))
	if err != nil || len(page.Events) != 0 || page.ThroughRevision != 0 {
		t.Fatalf("rolled-back acknowledgement published a challenge: %d events, revision %d, error %v", len(page.Events), page.ThroughRevision, err)
	}
	if _, found, err := database.ClaimACMEOrderWork(ctx, "competitor", now.Add(time.Second), time.Minute); err != nil || found {
		t.Fatalf("claim after acknowledgement rollback: found %t, error %v", found, err)
	}
	if _, err := database.SaveACMEOrderWork(ctx, work, now.Add(time.Second)); err != nil {
		t.Fatalf("original work could not save after acknowledgement rollback: %v", err)
	}
}

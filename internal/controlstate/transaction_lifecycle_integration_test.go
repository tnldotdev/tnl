package controlstate

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/controlstate/controlstatedb"
	"github.com/tnldotdev/tnl/internal/credentials"
)

func TestIntegrationTransactionRoutingClockSerializesAllocation(t *testing.T) {
	database, now := newCertificatePlanDatabase(t)
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	lease, err := database.RegisterIngress(ctx, IngressRegistration{
		IngressID: "transaction-ingress", IngressRunID: "run", ProtocolVersion: 1, ConnectionCapacity: 10,
	}, now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	routes := make([]PublicURL, 2)
	sessions := make([]PublishRunAuthentication, 2)
	for index := range routes {
		hostname := fmt.Sprintf("route-%d.example.test", index)
		plan := CertificatePlan{CacheKey: hostname, Scope: hostname, Identifiers: []string{hostname}, ChallengeMethod: "tls-alpn-01"}
		routes[index], sessions[index] = newExternalPlanSession(t, database, now, "team_external", hostname, "managed:example.test", plan)
	}
	first, err := database.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer rollbackTestTransaction(t, first)
	second, err := database.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer rollbackTestTransaction(t, second)
	emit := func(tx pgx.Tx, index int) (int64, error) {
		queries := controlstatedb.New(tx)
		route, err := queries.LockPublicURLForRun(ctx, routes[index].ID)
		if err != nil {
			return 0, err
		}
		session, err := queries.GetPublishRun(ctx, sessions[index].PublishRunID)
		if err != nil {
			return 0, err
		}
		pending := pendingIngressRoutingTableEvents{}
		published, err := pending.addRouteEvent(ctx, queries, route, session, nil, IngressPublicURLTombstone, now)
		if err != nil {
			return 0, err
		}
		if err := pending.publish(ctx, queries); err != nil {
			return 0, err
		}
		return published.routingTableRevision, nil
	}
	firstRevision, err := emit(first, 0)
	if err != nil {
		t.Fatal(err)
	}
	workers := newIntegrationWorkers(t, cancel)
	defer workers.stop()
	secondDone := make(chan error, 1)
	var secondRevision int64
	workers.Go(func() {
		var err error
		secondRevision, err = emit(second, 1)
		secondDone <- err
	})
	waitForPostgresBlock(t, ctx, database, int32(first.Conn().PgConn().PID()), secondDone)
	var allocated int64
	if err := database.pool.QueryRow(ctx, `
		SELECT pg_sequence_last_value(pg_get_serial_sequence(
			'control.ingress_routing_table_events', 'id')::regclass)
	`).Scan(&allocated); err != nil {
		t.Fatal(err)
	}
	if allocated != firstRevision {
		t.Fatalf("blocked emitter allocated revision %d before taking the clock; want %d", allocated, firstRevision)
	}
	page, err := database.ReadIngressRoutingTableEvents(ctx, lease.IngressLeaseIdentity, 0, 10, now)
	if err != nil || page.ThroughRevision != 0 || len(page.Events) != 0 {
		t.Fatalf("uncommitted clock leaked: %#v, %v", page, err)
	}
	if err := first.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err := awaitIntegrationResult(t, ctx, secondDone); err != nil {
		t.Fatal(err)
	}
	page, err = database.ReadIngressRoutingTableEvents(ctx, lease.IngressLeaseIdentity, 0, 10, now)
	if err != nil || len(page.Events) != 1 || page.Events[0].PublicURLID != routes[0].ID || page.NextRevision != uint64(firstRevision) {
		t.Fatalf("first committed page = %#v, %v", page, err)
	}
	if err := second.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	page, err = database.ReadIngressRoutingTableEvents(ctx, lease.IngressLeaseIdentity, page.NextRevision, 10, now)
	if err != nil || len(page.Events) != 1 || page.Events[0].PublicURLID != routes[1].ID ||
		page.NextRevision != uint64(secondRevision) || secondRevision <= firstRevision || page.More {
		t.Fatalf("next committed page skipped an event: %#v, %v", page, err)
	}
}

func TestIntegrationTransactionRoutingEntryRevisionFollowsRouteLock(t *testing.T) {
	database, now := newCertificatePlanDatabase(t)
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	plan := CertificatePlan{CacheKey: "entry.example.test", Scope: "entry.example.test", Identifiers: []string{"entry.example.test"}, ChallengeMethod: "tls-alpn-01"}
	route, authentication := newExternalPlanSession(t, database, now, "team_entry", "entry.example.test", "managed:example.test", plan)
	first, err := database.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer rollbackTestTransaction(t, first)
	second, err := database.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer rollbackTestTransaction(t, second)
	firstQueries := controlstatedb.New(first)
	storedPublicURL, err := firstQueries.LockPublicURLForRun(ctx, route.ID)
	if err != nil {
		t.Fatal(err)
	}
	storedSession, err := firstQueries.GetPublishRun(ctx, authentication.PublishRunID)
	if err != nil {
		t.Fatal(err)
	}
	firstPending := pendingIngressRoutingTableEvents{}
	firstPublished, err := firstPending.addRouteEvent(ctx, firstQueries, storedPublicURL, storedSession, nil, IngressPublicURLTombstone, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := firstPending.publish(ctx, firstQueries); err != nil {
		t.Fatal(err)
	}
	workers := newIntegrationWorkers(t, cancel)
	defer workers.stop()
	secondDone := make(chan error, 1)
	var secondPublished *publishedIngressRoutingTableEvent
	workers.Go(func() {
		secondQueries := controlstatedb.New(second)
		storedPublicURL, err := secondQueries.LockPublicURLForRun(ctx, route.ID)
		if err == nil {
			storedSession, sessionErr := secondQueries.GetPublishRun(ctx, authentication.PublishRunID)
			err = sessionErr
			if err == nil {
				secondPending := pendingIngressRoutingTableEvents{}
				secondPublished, err = secondPending.addRouteEvent(ctx, secondQueries, storedPublicURL, storedSession, nil, IngressPublicURLTombstone, now.Add(time.Second))
				if err == nil {
					err = secondPending.publish(ctx, secondQueries)
				}
			}
		}
		if err == nil {
			err = second.Commit(ctx)
		}
		secondDone <- err
	})
	waitForPostgresBlock(t, ctx, database, int32(first.Conn().PgConn().PID()), secondDone)
	if err := first.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err := awaitIntegrationResult(t, ctx, secondDone); err != nil {
		t.Fatal(err)
	}
	if firstPublished.entryRevision != 1 || secondPublished == nil || secondPublished.entryRevision != 2 {
		t.Fatalf("entry revisions = %+v, %+v; want 1, 2", firstPublished, secondPublished)
	}
}

func TestIntegrationTransactionRoutingPublicationRollbackAndPendingEvents(t *testing.T) {
	database, now := newCertificatePlanDatabase(t)
	plan := func(hostname string) CertificatePlan {
		return CertificatePlan{CacheKey: hostname, Scope: hostname, Identifiers: []string{hostname}, ChallengeMethod: "tls-alpn-01"}
	}
	routeA, authenticationA := newExternalPlanSession(t, database, now, "team_pending_a", "pending-a.example.test", "managed:example.test", plan("pending-a.example.test"))
	routeB, authenticationB := newExternalPlanSession(t, database, now, "team_pending_b", "pending-b.example.test", "managed:example.test", plan("pending-b.example.test"))
	var baselineEvents, baselineClock int64
	if err := database.pool.QueryRow(t.Context(), `SELECT count(*) FROM control.ingress_routing_table_events`).Scan(&baselineEvents); err != nil {
		t.Fatal(err)
	}
	if err := database.pool.QueryRow(t.Context(), `SELECT current_revision FROM control.ingress_routing_table_clock WHERE id = 1`).Scan(&baselineClock); err != nil {
		t.Fatal(err)
	}
	tx, err := database.pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	queries := controlstatedb.New(tx)
	storedA, err := queries.LockPublicURLForRun(t.Context(), routeA.ID)
	if err != nil {
		t.Fatal(err)
	}
	sessionA, err := queries.GetPublishRun(t.Context(), authenticationA.PublishRunID)
	if err != nil {
		t.Fatal(err)
	}
	storedB, err := queries.LockPublicURLForRun(t.Context(), routeB.ID)
	if err != nil {
		t.Fatal(err)
	}
	sessionB, err := queries.GetPublishRun(t.Context(), authenticationB.PublishRunID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(t.Context(), `UPDATE control.public_urls SET target = 'http://127.0.0.1:4999' WHERE id = $1`, routeA.ID); err != nil {
		t.Fatal(err)
	}
	pending := pendingIngressRoutingTableEvents{}
	first, err := pending.addRouteEvent(t.Context(), queries, storedA, sessionA, nil, IngressPublicURLTombstone, now)
	if err != nil {
		t.Fatal(err)
	}
	second, err := pending.addChallengeEvent(t.Context(), queries, storedA, sessionA, nil, IngressChallengeTombstone, now.Add(time.Minute), now)
	if err != nil {
		t.Fatal(err)
	}
	third, err := pending.addRouteEvent(t.Context(), queries, storedB, sessionB, nil, IngressPublicURLTombstone, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := pending.publish(t.Context(), queries); err != nil {
		t.Fatal(err)
	}
	if first.entryRevision != 1 || second.entryRevision != 2 || third.entryRevision != 1 ||
		first.routingTableRevision >= second.routingTableRevision || second.routingTableRevision >= third.routingTableRevision {
		t.Fatalf("published revisions = %+v, %+v, %+v", first, second, third)
	}
	if err := tx.Rollback(t.Context()); err != nil {
		t.Fatal(err)
	}
	var events, clock int64
	var target string
	if err := database.pool.QueryRow(t.Context(), `SELECT count(*) FROM control.ingress_routing_table_events`).Scan(&events); err != nil {
		t.Fatal(err)
	}
	if err := database.pool.QueryRow(t.Context(), `SELECT current_revision FROM control.ingress_routing_table_clock WHERE id = 1`).Scan(&clock); err != nil {
		t.Fatal(err)
	}
	if err := database.pool.QueryRow(t.Context(), `SELECT target FROM control.public_urls WHERE id = $1`, routeA.ID).Scan(&target); err != nil {
		t.Fatal(err)
	}
	if events != baselineEvents || clock != baselineClock || target != routeA.Target {
		t.Fatalf("rollback left events/clock/target = %d/%d/%q; want %d/%d/%q", events, clock, target, baselineEvents, baselineClock, routeA.Target)
	}

	tx, err = database.pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer rollbackTestTransaction(t, tx)
	queries = controlstatedb.New(tx)
	storedA, err = queries.LockPublicURLForRun(t.Context(), routeA.ID)
	if err != nil {
		t.Fatal(err)
	}
	storedB, err = queries.LockPublicURLForRun(t.Context(), routeB.ID)
	if err != nil {
		t.Fatal(err)
	}
	pending = pendingIngressRoutingTableEvents{}
	first, err = pending.addRouteEvent(t.Context(), queries, storedA, sessionA, nil, IngressPublicURLTombstone, now)
	if err != nil {
		t.Fatal(err)
	}
	second, err = pending.addChallengeEvent(t.Context(), queries, storedA, sessionA, nil, IngressChallengeTombstone, now.Add(time.Minute), now)
	if err != nil {
		t.Fatal(err)
	}
	third, err = pending.addRouteEvent(t.Context(), queries, storedB, sessionB, nil, IngressPublicURLTombstone, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := pending.publish(t.Context(), queries); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}
	if first.entryRevision != 1 || second.entryRevision != 2 || third.entryRevision != 1 ||
		first.routingTableRevision >= second.routingTableRevision || second.routingTableRevision >= third.routingTableRevision {
		t.Fatalf("committed pending revisions = %+v, %+v, %+v", first, second, third)
	}
}

func TestIntegrationTransactionExpiredReplacementFollowsHeartbeatPlacementLocks(t *testing.T) {
	database, now := newCertificatePlanDatabase(t)
	plan := func(hostname string) CertificatePlan {
		return CertificatePlan{CacheKey: hostname, Scope: hostname, Identifiers: []string{hostname}, ChallengeMethod: "tls-alpn-01"}
	}
	_, heartbeatAuthentication := newExternalPlanSession(t, database, now, "team_cycle_heartbeat", "heartbeat-cycle.example.test", "managed:example.test", plan("heartbeat-cycle.example.test"))
	replacementPublicURL, replacementAuthentication := newExternalPlanSession(t, database, now, "team_cycle_replacement", "replacement-cycle.example.test", "managed:example.test", plan("replacement-cycle.example.test"))
	for _, authentication := range []PublishRunAuthentication{heartbeatAuthentication, replacementAuthentication} {
		if _, err := database.pool.Exec(t.Context(), `UPDATE control.publish_runs SET state = 'ready', ready_at = $2 WHERE id = $1`, authentication.PublishRunID, now); err != nil {
			t.Fatal(err)
		}
		if _, err := database.pool.Exec(t.Context(), `UPDATE control.publish_run_connection_slots AS connections
			SET state = 'ready', connected_relay_id = leases.relay_id,
			    connected_relay_run_id = leases.relay_run_id,
			    connected_relay_lease_revision = leases.relay_lease_revision,
			    claim_id = 'transaction-cycle', connected_at = $2, ready_at = $2
			FROM control.relay_leases AS leases
			WHERE connections.publish_run_id = $1
			  AND leases.relay_service_id = connections.relay_service_id`, authentication.PublishRunID, now); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := database.pool.Exec(t.Context(), `UPDATE control.publish_run_connection_slots
		SET state = 'closed', disconnected_at = $2, closed_at = $2
		WHERE publish_run_id = $1 AND connection_slot = 0`, heartbeatAuthentication.PublishRunID, now); err != nil {
		t.Fatal(err)
	}
	if _, err := database.pool.Exec(t.Context(), `UPDATE control.publish_runs SET publisher_expires_at = $1 WHERE id = $2`, now.Add(time.Second), replacementAuthentication.PublishRunID); err != nil {
		t.Fatal(err)
	}
	secret := sha256.Sum256([]byte("plan-retry"))
	replacementRequest := PublishRunRequest{
		PublicURLID: replacementPublicURL.ID, TeamID: replacementPublicURL.TeamID, MembershipID: replacementPublicURL.MembershipID,
		ActingIdentityID: "identity_" + strings.TrimPrefix(replacementPublicURL.TeamID, "team_"), RetrySecret: secret[:], IdempotencyKey: "replacement",
		RequestDigest: sha256.Sum256([]byte("replacement")), PolicyRevision: 1,
		CertificateCacheKey: replacementPublicURL.CanonicalHostname, CertificateScope: replacementPublicURL.CanonicalHostname,
		CertificateIdentifiers: []string{replacementPublicURL.CanonicalHostname}, CertificateChallenge: "tls-alpn-01",
		ExpectedMutationRevision: replacementPublicURL.MutationRevision + 1,
	}
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	gate, err := database.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer rollbackTestTransaction(t, gate)
	if _, err := controlstatedb.New(gate).LockIngressRoutingTableClock(ctx); err != nil {
		t.Fatal(err)
	}
	workers := newIntegrationWorkers(t, cancel)
	heartbeatDone := make(chan error, 1)
	var heartbeatSetup PublishRunSetup
	workers.Go(func() {
		var err error
		heartbeatSetup, err = database.HeartbeatPublishRun(ctx, heartbeatAuthentication, now.Add(2*time.Second), 48*time.Hour, time.Hour)
		heartbeatDone <- err
	})
	heartbeatPID := waitForPostgresBlock(t, ctx, database, int32(gate.Conn().PgConn().PID()), heartbeatDone)
	replacementDone := make(chan error, 1)
	workers.Go(func() {
		_, err := database.CreatePublishRun(ctx, replacementRequest, now.Add(2*time.Second), time.Hour, time.Hour)
		replacementDone <- err
	})
	// the closed slot needs a new reservation (a failed ready slot may reuse its
	// reservation without placement). replacement must queue behind that allocation.
	// extending the fixture's 48-hour lease also requires routing publication.
	// if closure acquired the routing clock immediately, it would wait on the gate instead.
	waitForPostgresBlock(t, ctx, database, heartbeatPID, replacementDone)
	if err := gate.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err := awaitIntegrationResult(t, ctx, heartbeatDone); err != nil {
		t.Fatal(err)
	}
	if heartbeatSetup.PublisherConnections[0].State != PublisherConnectionAssigned ||
		heartbeatSetup.PublisherConnections[0].ConnectionAssignmentRevision != 2 ||
		heartbeatSetup.PublisherConnections[1].State != PublisherConnectionReady {
		t.Fatalf("closed connection replacement = %#v", heartbeatSetup.PublisherConnections)
	}
	if err := awaitIntegrationResult(t, ctx, replacementDone); err != nil {
		t.Fatal(err)
	}
}

func TestIntegrationTransactionLocalAuthorityLockOrder(t *testing.T) {
	for _, mutation := range []string{"role", "remove", "release"} {
		for _, operation := range []string{"create", "session", "update", "delete"} {
			t.Run(mutation+"/"+operation, func(t *testing.T) {
				fixture := newTransactionAuthorityFixture(t)
				database, now := fixture.database, fixture.now
				if operation == "session" {
					registerCertificatePlanRelays(t, database, now)
				}
				ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
				defer cancel()
				gate, err := database.pool.Begin(ctx)
				if err != nil {
					t.Fatal(err)
				}
				defer rollbackTestTransaction(t, gate)
				if _, err := controlstatedb.New(gate).LockPublicURLForRun(ctx, fixture.route.ID); err != nil {
					t.Fatal(err)
				}
				workers := newIntegrationWorkers(t, cancel)
				defer workers.stop()
				mutationDone := make(chan error, 1)
				workers.Go(func() {
					var err error
					switch mutation {
					case "role":
						_, err = database.SetMembershipRole(ctx, fixture.owner, fixture.member.TeamID, fixture.member.ID, "member", now)
					case "remove":
						err = database.RemoveMembership(ctx, fixture.owner, fixture.member.TeamID, fixture.member.ID, now)
					case "release":
						err = database.ReleaseTeamDomain(ctx, fixture.owner, fixture.member.TeamID, fixture.domain.ID, now)
					}
					mutationDone <- err
				})
				// the authority mutation owns the team and waits at the public URL lock.
				mutationPID := waitForPostgresBlock(t, ctx, database, int32(gate.Conn().PgConn().PID()), mutationDone)
				operationDone := make(chan error, 1)
				workers.Go(func() {
					var err error
					switch operation {
					case "create":
						request := fixture.createRequest
						request.IdempotencyKey, request.CanonicalHostname = "sibling", "sibling.member."+fixture.domain.CanonicalDomain
						_, err = database.CreatePublicURL(ctx, request, now)
					case "session":
						_, err = database.CreatePublishRun(ctx, fixture.sessionRequest, now, time.Hour, time.Hour)
					case "update":
						_, err = database.UpdateAuthorizedPublicURL(ctx, AuthorizedPublicURLUpdateRequest{
							PublicURLID: fixture.route.ID, TeamID: fixture.route.TeamID, ActingIdentityID: fixture.member.IdentityID,
							Target: "http://127.0.0.1:3001", AllowedIPPrefixes: []string{},
							PolicyRevision: uint64(fixture.route.PolicyRevision), ExpectedMutationRevision: fixture.route.MutationRevision,
						}, now)
					case "delete":
						err = database.DeletePublicURL(ctx, fixture.member.IdentityID, fixture.route.ID, now)
					}
					operationDone <- err
				})
				// public URL operations must wait on the team before locking a public URL.
				waitForPostgresBlock(t, ctx, database, mutationPID, operationDone)
				if err := gate.Commit(ctx); err != nil {
					t.Fatal(err)
				}
				if err := awaitIntegrationResult(t, ctx, mutationDone); err != nil {
					t.Fatal(err)
				}
				err = awaitIntegrationResult(t, ctx, operationDone)
				var want error
				switch operation {
				case "create":
					if mutation != "role" {
						want = ErrPublicURLAccess
					}
				case "session":
					want = ErrPublicURLAuthority
				case "update":
					want = ErrPublicURLNotEnabled
					if mutation == "role" {
						want = ErrPublicURLAccess
					}
				case "delete":
					if mutation == "remove" {
						want = ErrPublicURLNotFound
					}
				}
				if !errors.Is(err, want) {
					t.Fatalf("%s after %s = %v; want %v", operation, mutation, err, want)
				}
			})
		}
	}
}

func TestIntegrationTransactionDomainReleaseCertificateExpiry(t *testing.T) {
	for _, certificateState := range []string{"waiting_for_install", "installed", "canceled"} {
		t.Run(certificateState, func(t *testing.T) {
			fixture := newTransactionAuthorityFixture(t)
			database, now := fixture.database, fixture.now
			registerCertificatePlanRelays(t, database, now)
			setup, err := database.CreatePublishRun(t.Context(), fixture.sessionRequest, now, time.Hour, time.Hour)
			if err != nil {
				t.Fatal(err)
			}
			authentication := PublishRunAuthentication{
				PublishRunID: setup.PublishRunID, PublicURLID: setup.PublicURLID, PublishRunNumber: setup.PublishRunNumber, PublishRunToken: setup.PublishRunToken,
			}
			plan := CertificatePlan{CacheKey: fixture.route.CanonicalHostname, Scope: fixture.route.CanonicalHostname,
				Identifiers: []string{fixture.route.CanonicalHostname}, ChallengeMethod: "dns-01"}
			work := createPlanIssuanceWork(t, database, now, authentication, plan, true, nil)
			if certificateState == "installed" {
				if _, err := database.MarkPublicURLCertificateInstalled(t.Context(), authentication, work.ID, *work.NotAfter, now); err != nil {
					t.Fatal(err)
				}
			}
			if err := database.ReleaseTeamDomain(t.Context(), fixture.owner, fixture.member.TeamID, fixture.domain.ID, now); err != nil {
				t.Fatal(err)
			}
			if err := database.DeletePublicURL(t.Context(), fixture.owner, fixture.route.ID, now); err != nil {
				t.Fatalf("delete suspended public_url: %v", err)
			}
			var state string
			var notAfter time.Time
			var certificate []byte
			if err := database.pool.QueryRow(t.Context(), `SELECT state, not_after, certificate_pem FROM control.acme_orders WHERE id = $1`, work.ID).
				Scan(&state, &notAfter, &certificate); err != nil {
				t.Fatal(err)
			}
			wantState := "waiting_for_install"
			if certificateState == "installed" {
				wantState = "installed"
			}
			if state != wantState || !notAfter.Equal(*work.NotAfter) || len(certificate) == 0 {
				t.Fatalf("session closure lost issued certificate history: state %s, expiry %v, bytes %d", state, notAfter, len(certificate))
			}
			if certificateState == "canceled" {
				// persisted canceled, unacknowledged orders still own an issued certificate.
				if _, err := database.pool.Exec(t.Context(), `UPDATE control.acme_orders SET state = 'canceled' WHERE id = $1`, work.ID); err != nil {
					t.Fatal(err)
				}
			}
			ready, err := database.DNSAuthorityReleaseReady(t.Context(), fixture.domain.ID, notAfter)
			if err != nil || ready {
				t.Fatalf("pending public URL DNS must block release even after certificate expiry: %t, %v", ready, err)
			}
			dnsWork, found, err := database.ClaimDNSPublicURLWork(t.Context(), "cleanup", now, time.Minute)
			if err != nil || !found || dnsWork.PublicURLID != fixture.route.ID || dnsWork.State != PublicURLDNSRemoving {
				t.Fatalf("claim route cleanup: %#v, %t, %v", dnsWork, found, err)
			}
			dnsWork.State, dnsWork.AvailableAt = PublicURLDNSRemoved, time.Time{}
			if _, err := database.SaveDNSPublicURLWork(t.Context(), dnsWork, now); err != nil {
				t.Fatal(err)
			}
			for _, observed := range []time.Time{now, notAfter.Add(-time.Microsecond), notAfter, notAfter.Add(time.Second)} {
				ready, err := database.DNSAuthorityReleaseReady(t.Context(), fixture.domain.ID, observed)
				if err != nil || ready != !observed.Before(notAfter) {
					t.Fatalf("release readiness at %s = %t, %v; expiry %s", observed, ready, err, notAfter)
				}
			}
			if certificateState == "canceled" {
				for _, statement := range []string{
					`UPDATE control.acme_orders SET state = 'finalizing' WHERE id = $1`,
					`UPDATE control.acme_authorizations SET state = 'canceled', cleanup_completed_at = NULL WHERE order_id = $1`,
				} {
					if _, err := database.pool.Exec(t.Context(), statement, work.ID); err != nil {
						t.Fatal(err)
					}
					ready, err := database.DNSAuthorityReleaseReady(t.Context(), fixture.domain.ID, notAfter)
					if err != nil || ready {
						t.Fatalf("unfinished issuance/cleanup did not block release: %t, %v", ready, err)
					}
					if _, err := database.pool.Exec(t.Context(), `UPDATE control.acme_orders SET state = 'canceled' WHERE id = $1`, work.ID); err != nil {
						t.Fatal(err)
					}
				}
				if _, err := database.pool.Exec(t.Context(), `UPDATE control.acme_authorizations SET state = 'complete', cleanup_completed_at = $2 WHERE order_id = $1`, work.ID, notAfter); err != nil {
					t.Fatal(err)
				}
			}
			// complete the real domain release only after all blockers have expired.
			authorityWork, found, err := database.ClaimDNSAuthorityWork(t.Context(), "release", notAfter, time.Minute)
			if err != nil || !found || authorityWork.Reference != fixture.domain.DNSAuthorityReference {
				t.Fatalf("claim domain release: %t, %v", found, err)
			}
			authorityWork.State, authorityWork.AvailableAt = "released", notAfter
			if _, err := database.SaveDNSAuthorityWork(t.Context(), authorityWork, notAfter); err != nil {
				t.Fatal(err)
			}
			var released bool
			if err := database.pool.QueryRow(t.Context(), `SELECT state = 'released' AND released_at IS NOT NULL FROM control.domains WHERE id = $1`, fixture.domain.ID).
				Scan(&released); err != nil || !released {
				t.Fatalf("domain was not released: %t, %v", released, err)
			}
		})
	}
}

func TestIntegrationTransactionDNSAuthorityLockOrder(t *testing.T) {
	for _, saveFirst := range []bool{false, true} {
		t.Run(fmt.Sprintf("save_first_%t", saveFirst), func(t *testing.T) {
			fixture := newTransactionAuthorityFixture(t)
			database, now := fixture.database, fixture.now
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			domain, err := database.ClaimTeamDomain(ctx, ClaimDomainRequest{
				IdentityID: fixture.owner, TeamID: fixture.member.TeamID, IdempotencyKey: "default-domain",
				RequestDigest: sha256.Sum256([]byte("default-domain")), Domain: "default.example.test", MakeDefault: true,
			}, now)
			if err != nil {
				t.Fatal(err)
			}
			work, found, err := database.ClaimDNSAuthorityWork(ctx, "ready-default", now, time.Minute)
			if err != nil || !found || work.Reference != domain.DNSAuthorityReference {
				t.Fatalf("claim default domain work: %t, %v", found, err)
			}
			work.State, work.ProviderZoneID, work.Nameservers = "ready", "ZDEFAULT", []string{"ns-1.example.test"}
			gate, err := database.pool.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer rollbackTestTransaction(t, gate)
			if saveFirst {
				_, err = controlstatedb.New(gate).LockDNSAuthority(ctx, work.Reference)
			} else {
				_, err = controlstatedb.New(gate).LockTeamDomain(ctx, controlstatedb.LockTeamDomainParams{
					DomainID: domain.ID, TeamID: text(fixture.member.TeamID),
				})
			}
			if err != nil {
				t.Fatal(err)
			}
			workers := newIntegrationWorkers(t, cancel)
			defer workers.stop()
			saveDone, releaseDone := make(chan error, 1), make(chan error, 1)
			save := func() {
				_, err := database.SaveDNSAuthorityWork(ctx, work, now)
				saveDone <- err
			}
			release := func() {
				releaseDone <- database.ReleaseTeamDomain(ctx, fixture.owner, fixture.member.TeamID, domain.ID, now)
			}
			first, second := release, save
			firstDone, secondDone := releaseDone, saveDone
			if saveFirst {
				first, second, firstDone, secondDone = save, release, saveDone, releaseDone
			}
			workers.Go(first)
			firstPID := waitForPostgresBlock(t, ctx, database, int32(gate.Conn().PgConn().PID()), firstDone)
			workers.Go(second)
			waitForPostgresBlock(t, ctx, database, firstPID, secondDone)
			if err := gate.Commit(ctx); err != nil {
				t.Fatal(err)
			}
			if err := awaitIntegrationResult(t, ctx, firstDone); err != nil {
				t.Fatal(err)
			}
			wantErr, wantState := ErrDNSAuthorityWorkStale, "releasing"
			if saveFirst {
				wantErr, wantState = ErrAuthorityConflict, "ready"
			}
			if err := awaitIntegrationResult(t, ctx, secondDone); !errors.Is(err, wantErr) {
				t.Fatalf("second authority operation = %v; want %v", err, wantErr)
			}
			var domainState, authorityState string
			var isDefault bool
			if err := database.pool.QueryRow(ctx, `
				SELECT domains.state, authorities.state, teams.default_domain_id = domains.id
				FROM control.domains AS domains
				JOIN control.dns_authorities AS authorities ON authorities.authority_reference = domains.dns_authority_reference
				JOIN control.teams AS teams ON teams.id = domains.team_id
				WHERE domains.id = $1
			`, domain.ID).Scan(&domainState, &authorityState, &isDefault); err != nil ||
				domainState != wantState || authorityState != wantState || isDefault != saveFirst {
				t.Fatalf("domain/authority/default = %s/%s/%t, %v", domainState, authorityState, isDefault, err)
			}
		})
	}
}

func TestIntegrationTransactionMixedEphemeralDeletion(t *testing.T) {
	fixture := newTransactionAuthorityFixture(t)
	database, now := fixture.database, fixture.now
	for _, suspended := range []bool{false, true} {
		request := fixture.createRequest
		request.IdempotencyKey = fmt.Sprintf("ephemeral-%t", suspended)
		request.CanonicalHostname = request.IdempotencyKey + ".member." + fixture.domain.CanonicalDomain
		request.Ephemeral = true
		route, err := database.CreatePublicURL(t.Context(), request, now)
		if err != nil {
			t.Fatal(err)
		}
		if suspended {
			if _, err := controlstatedb.New(database.pool).SuspendAuthorityPublicURL(t.Context(), controlstatedb.SuspendAuthorityPublicURLParams{
				PublicURLID: route.ID, SuspensionReason: text("test"), SuspendedAt: timestamptz(now),
			}); err != nil {
				t.Fatal(err)
			}
		}
	}
	count, err := database.DeleteExpiredEphemeralPublicURLs(t.Context(), now.Add(ephemeralPublicURLGracePeriod))
	if err != nil || count != 2 {
		t.Fatalf("mixed enabled/suspended expiry batch = %d, %v; want 2", count, err)
	}
	var deleted, audited int
	if err := database.pool.QueryRow(t.Context(), `
		SELECT count(*) FILTER (WHERE lifecycle_state = 'deleted' AND suspended_at IS NULL AND dns_state = 'removing'),
		       (SELECT count(*) FROM control.admin_audit_events WHERE request_id LIKE 'ephemeral_expiry/%')
		FROM control.public_urls WHERE ephemeral
	`).Scan(&deleted, &audited); err != nil || deleted != 2 || audited != 2 {
		t.Fatalf("deleted/audited batch = %d/%d, %v; want 2/2", deleted, audited, err)
	}
	if count, err := database.DeleteExpiredEphemeralPublicURLs(t.Context(), now.Add(ephemeralPublicURLGracePeriod)); err != nil || count != 0 {
		t.Fatalf("repeated expiry batch = %d, %v", count, err)
	}
}

type transactionAuthorityFixture struct {
	database       *Database
	now            time.Time
	owner          string
	member         Membership
	domain         Domain
	route          PublicURL
	createRequest  CreatePublicURLRequest
	sessionRequest PublishRunRequest
}

func newTransactionAuthorityFixture(t *testing.T) transactionAuthorityFixture {
	t.Helper()
	database, now := newControlStateIntegrationDatabase(t, "transaction_authority")
	local, err := database.CreateBuiltinControlSession(t.Context(), "managed.example.test", 1, time.Hour, 24*time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	owner := local.Identity.Identity.ID
	team, err := database.CreateTeam(t.Context(), CreateTeamRequest{
		IdentityID: owner, IdempotencyKey: "team", RequestDigest: sha256.Sum256([]byte("team")), DisplayName: "transaction-tests", MemberSlug: "owner",
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	const memberIdentity = "identity_transaction_member"
	insertAuthorityIdentity(t, database, memberIdentity, "", false, now)
	secret := sha256.Sum256([]byte("transaction retry secret"))
	invitation, err := database.CreateTeamInvitation(t.Context(), CreateInvitationRequest{
		IdentityID: owner, TeamID: team.ID, IdempotencyKey: "invite", RequestDigest: sha256.Sum256([]byte("invite")),
		MemberSlug: "member", InitialRole: "admin", ExpiresAt: now.Add(time.Hour), RetrySecret: secret[:],
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	member, err := database.AcceptInvitation(t.Context(), memberIdentity, credentials.InvitationToken(invitation.Secret), now)
	if err != nil {
		t.Fatal(err)
	}
	domain, err := database.ClaimTeamDomain(t.Context(), ClaimDomainRequest{
		IdentityID: owner, TeamID: team.ID, IdempotencyKey: "domain", RequestDigest: sha256.Sum256([]byte("domain")), Domain: "claimed.example.test",
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	work, found, err := database.ClaimDNSAuthorityWork(t.Context(), "ready", now, time.Minute)
	if err != nil || !found || work.Reference != domain.DNSAuthorityReference {
		t.Fatalf("claim local authority: %t, %v", found, err)
	}
	work.State, work.ProviderZoneID, work.Nameservers = "ready", "ZTRANSACTION", []string{"ns-1.example.test"}
	if _, err := database.SaveDNSAuthorityWork(t.Context(), work, now); err != nil {
		t.Fatal(err)
	}
	request := CreatePublicURLRequest{
		TeamID: team.ID, DomainID: domain.ID, MembershipID: member.ID, ActingIdentityID: memberIdentity,
		IdempotencyKey: "route", RequestDigest: sha256.Sum256([]byte("route")), CanonicalHostname: "api.member." + domain.CanonicalDomain,
		Target: "http://127.0.0.1:3000", PublicURLScope: PublicURLScopeMember, Purpose: PublicURLPurposeApp, DNSState: PublicURLDNSPending, DNSAuthorityReference: domain.DNSAuthorityReference,
	}
	route, err := database.CreatePublicURL(t.Context(), request, now)
	if err != nil {
		t.Fatal(err)
	}
	return transactionAuthorityFixture{
		database: database, now: now, owner: owner, member: member, domain: domain, route: route, createRequest: request,
		sessionRequest: PublishRunRequest{
			PublicURLID: route.ID, TeamID: team.ID, MembershipID: member.ID, ActingIdentityID: memberIdentity,
			RetrySecret: secret[:], IdempotencyKey: "session", RequestDigest: sha256.Sum256([]byte("session")),
			PolicyRevision: uint64(route.PolicyRevision), ExpectedMutationRevision: route.MutationRevision,
			CertificateCacheKey: route.CanonicalHostname, CertificateScope: route.CanonicalHostname,
			CertificateIdentifiers: []string{route.CanonicalHostname}, CertificateChallenge: "dns-01",
		},
	}
}

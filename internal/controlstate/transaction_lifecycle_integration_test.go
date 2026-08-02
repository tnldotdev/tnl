package controlstate

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
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
	routes := make([]Route, 2)
	sessions := make([]RouteSessionAuthentication, 2)
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
		route, err := queries.LockRouteForSession(ctx, routes[index].ID)
		if err != nil {
			return 0, err
		}
		session, err := queries.GetRouteSession(ctx, sessions[index].RouteSessionID)
		if err != nil {
			return 0, err
		}
		revision, _, err := emitRouteRoutingTableEvent(ctx, queries, route, session, nil, IngressRouteTombstone, now)
		return revision, err
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
			'control.ingress_routing_table_events', 'routing_table_revision')::regclass)
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
	if err != nil || len(page.Events) != 1 || page.Events[0].RouteID != routes[0].ID || page.NextRevision != uint64(firstRevision) {
		t.Fatalf("first committed page = %#v, %v", page, err)
	}
	if err := second.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	page, err = database.ReadIngressRoutingTableEvents(ctx, lease.IngressLeaseIdentity, page.NextRevision, 10, now)
	if err != nil || len(page.Events) != 1 || page.Events[0].RouteID != routes[1].ID ||
		page.NextRevision != uint64(secondRevision) || secondRevision <= firstRevision || page.More {
		t.Fatalf("next committed page skipped an event: %#v, %v", page, err)
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
				if _, err := controlstatedb.New(gate).LockRouteForSession(ctx, fixture.route.ID); err != nil {
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
				// The authority mutation owns the team and is stopped at its route lock.
				mutationPID := waitForPostgresBlock(t, ctx, database, int32(gate.Conn().PgConn().PID()), mutationDone)
				operationDone := make(chan error, 1)
				workers.Go(func() {
					var err error
					switch operation {
					case "create":
						request := fixture.createRequest
						request.IdempotencyKey, request.CanonicalHostname = "sibling", "sibling.member."+fixture.domain.CanonicalDomain
						_, err = database.CreateRoute(ctx, request, now)
					case "session":
						_, err = database.CreateRouteSession(ctx, fixture.sessionRequest, now, time.Hour, time.Hour)
					case "update":
						_, err = database.UpdateAuthorizedRoute(ctx, AuthorizedRouteUpdateRequest{
							RouteID: fixture.route.ID, TeamID: fixture.route.TeamID, ActingIdentityID: fixture.member.IdentityID,
							Target: "http://127.0.0.1:3001", AllowedIPPrefixes: []string{},
							PolicyRevision: uint64(fixture.route.PolicyRevision), ExpectedMutationRevision: fixture.route.MutationRevision,
						}, now)
					case "delete":
						err = database.DeleteRoute(ctx, fixture.member.IdentityID, fixture.route.ID, now)
					}
					operationDone <- err
				})
				// Route operations must wait on the team, not acquire the route first.
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
						want = ErrRouteAccess
					}
				case "session":
					want = ErrRouteAuthority
				case "update":
					want = ErrRouteNotEnabled
					if mutation == "role" {
						want = ErrRouteAccess
					}
				case "delete":
					if mutation == "remove" {
						want = ErrRouteNotFound
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
			setup, err := database.CreateRouteSession(t.Context(), fixture.sessionRequest, now, time.Hour, time.Hour)
			if err != nil {
				t.Fatal(err)
			}
			authentication := RouteSessionAuthentication{
				RouteSessionID: setup.RouteSessionID, RouteID: setup.RouteID, RouteVersion: setup.RouteVersion, RouteSessionToken: setup.RouteSessionToken,
			}
			plan := CertificatePlan{CacheKey: fixture.route.CanonicalHostname, Scope: fixture.route.CanonicalHostname,
				Identifiers: []string{fixture.route.CanonicalHostname}, ChallengeMethod: "dns-01"}
			work := createPlanIssuanceWork(t, database, now, authentication, plan, true, nil)
			if certificateState == "installed" {
				if _, err := database.MarkRouteCertificateInstalled(t.Context(), authentication, work.ID, *work.NotAfter, now); err != nil {
					t.Fatal(err)
				}
			}
			if err := database.ReleaseTeamDomain(t.Context(), fixture.owner, fixture.member.TeamID, fixture.domain.ID, now); err != nil {
				t.Fatal(err)
			}
			if err := database.DeleteRoute(t.Context(), fixture.owner, fixture.route.ID, now); err != nil {
				t.Fatalf("delete suspended route: %v", err)
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
				// Persisted canceled, unacknowledged orders still own an issued certificate.
				if _, err := database.pool.Exec(t.Context(), `UPDATE control.acme_orders SET state = 'canceled' WHERE id = $1`, work.ID); err != nil {
					t.Fatal(err)
				}
			}
			ready, err := database.DNSAuthorityReleaseReady(t.Context(), fixture.domain.ID, notAfter)
			if err != nil || ready {
				t.Fatalf("pending public route DNS must block release even after certificate expiry: %t, %v", ready, err)
			}
			dnsWork, found, err := database.ClaimDNSRouteWork(t.Context(), "cleanup", now, time.Minute)
			if err != nil || !found || dnsWork.RouteID != fixture.route.ID || dnsWork.State != RouteDNSRemoving {
				t.Fatalf("claim route cleanup: %#v, %t, %v", dnsWork, found, err)
			}
			dnsWork.State, dnsWork.AvailableAt = RouteDNSRemoved, time.Time{}
			if _, err := database.SaveDNSRouteWork(t.Context(), dnsWork, now); err != nil {
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
			// Complete the real domain release only after all blockers have expired.
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

func TestIntegrationTransactionHostedRevocationIncludesConcurrentCreation(t *testing.T) {
	database, now := newControlStateIntegrationDatabase(t, "revocation_creation")
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	const identity = "identity_transaction_hosted"
	if _, err := database.EnsureExternalAuthorityPrincipal(ctx, identity, now); err != nil {
		t.Fatal(err)
	}
	request := CreateRouteRequest{
		TeamID: "team_external", DomainID: "domain_external", ActingIdentityID: identity,
		IdempotencyKey: "route", RequestDigest: sha256.Sum256([]byte("route")), CanonicalHostname: "api.example.test",
		Target: "http://127.0.0.1:3000", RouteScope: RouteScopeShared, DNSState: RouteDNSUnmanaged,
		AuthorityIssuer: "https://authority.example.test", PolicyRevision: 1,
	}
	gate, err := database.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer rollbackTestTransaction(t, gate)
	if _, err := controlstatedb.New(gate).LockRouteCreationControl(ctx); err != nil {
		t.Fatal(err)
	}
	workers := newIntegrationWorkers(t, cancel)
	defer workers.stop()
	created := make(chan error, 1)
	var route Route
	workers.Go(func() {
		var err error
		route, err = database.CreateRoute(ctx, request, now)
		created <- err
	})
	creatorPID := waitForPostgresBlock(t, ctx, database, int32(gate.Conn().PgConn().PID()), created)
	revoked := make(chan error, 1)
	workers.Go(func() {
		applied, _, err := database.ApplyHostedPolicyRevocation(ctx, request.AuthorityIssuer, request.TeamID, 2, false, nil, []string{request.DomainID}, now)
		if err == nil && !applied {
			err = errors.New("revocation was not applied")
		}
		revoked <- err
	})
	waitForPostgresBlock(t, ctx, database, creatorPID, revoked)
	if err := gate.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	for _, done := range []<-chan error{created, revoked} {
		if err := awaitIntegrationResult(t, ctx, done); err != nil {
			t.Fatal(err)
		}
	}
	current, err := database.GetRouteForAuthorization(ctx, route.ID)
	if err != nil || current.LifecycleState != RouteLifecycleSuspended {
		t.Fatalf("revocation missed concurrent route: %#v, %v", current, err)
	}
	if _, err := database.CreateRoute(ctx, request, now); !errors.Is(err, ErrRouteAuthority) {
		t.Fatalf("stale hosted creation replay = %v", err)
	}
	assertNoBuiltinAuthority(t, database)
	var teams int
	if err := database.pool.QueryRow(ctx, `SELECT count(*) FROM control.teams`).Scan(&teams); err != nil || teams != 0 {
		t.Fatalf("hosted mutation fabricated local teams: %d, %v", teams, err)
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
		route, err := database.CreateRoute(t.Context(), request, now)
		if err != nil {
			t.Fatal(err)
		}
		if suspended {
			if _, err := controlstatedb.New(database.pool).SuspendAuthorityRoute(t.Context(), controlstatedb.SuspendAuthorityRouteParams{
				RouteID: route.ID, SuspensionReason: text("test"), SuspendedAt: timestamptz(now),
			}); err != nil {
				t.Fatal(err)
			}
		}
	}
	count, err := database.DeleteExpiredEphemeralRoutes(t.Context(), now.Add(ephemeralRouteGracePeriod))
	if err != nil || count != 2 {
		t.Fatalf("mixed enabled/suspended expiry batch = %d, %v; want 2", count, err)
	}
	var deleted, audited int
	if err := database.pool.QueryRow(t.Context(), `
		SELECT count(*) FILTER (WHERE lifecycle_state = 'deleted' AND suspended_at IS NULL AND dns_state = 'removing'),
		       (SELECT count(*) FROM control.admin_audit_events WHERE request_id LIKE 'ephemeral_expiry/%')
		FROM control.routes WHERE ephemeral
	`).Scan(&deleted, &audited); err != nil || deleted != 2 || audited != 2 {
		t.Fatalf("deleted/audited batch = %d/%d, %v; want 2/2", deleted, audited, err)
	}
	if count, err := database.DeleteExpiredEphemeralRoutes(t.Context(), now.Add(ephemeralRouteGracePeriod)); err != nil || count != 0 {
		t.Fatalf("repeated expiry batch = %d, %v", count, err)
	}
}

type transactionAuthorityFixture struct {
	database       *Database
	now            time.Time
	owner          string
	member         Membership
	domain         Domain
	route          Route
	createRequest  CreateRouteRequest
	sessionRequest RouteSessionRequest
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
		IdentityID: owner, IdempotencyKey: "team", RequestDigest: sha256.Sum256([]byte("team")), DisplayName: "Transaction tests", MemberSlug: "owner",
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
	request := CreateRouteRequest{
		TeamID: team.ID, DomainID: domain.ID, MembershipID: member.ID, ActingIdentityID: memberIdentity,
		IdempotencyKey: "route", RequestDigest: sha256.Sum256([]byte("route")), CanonicalHostname: "api.member." + domain.CanonicalDomain,
		Target: "http://127.0.0.1:3000", RouteScope: RouteScopeMember, DNSState: RouteDNSPending, DNSAuthorityReference: domain.DNSAuthorityReference,
	}
	route, err := database.CreateRoute(t.Context(), request, now)
	if err != nil {
		t.Fatal(err)
	}
	return transactionAuthorityFixture{
		database: database, now: now, owner: owner, member: member, domain: domain, route: route, createRequest: request,
		sessionRequest: RouteSessionRequest{
			RouteID: route.ID, TeamID: team.ID, MembershipID: member.ID, ActingIdentityID: memberIdentity,
			RequireLocalAuthority: true, RetrySecret: secret[:], IdempotencyKey: "session", RequestDigest: sha256.Sum256([]byte("session")),
			PolicyRevision: uint64(route.PolicyRevision), ExpectedMutationRevision: route.MutationRevision,
			CertificateCacheKey: route.CanonicalHostname, CertificateScope: route.CanonicalHostname,
			CertificateIdentifiers: []string{route.CanonicalHostname}, CertificateChallenge: "dns-01",
		},
	}
}

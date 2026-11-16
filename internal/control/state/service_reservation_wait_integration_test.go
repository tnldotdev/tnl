package state

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/control/oidc"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
)

type reservationWaitFixture struct {
	d           *Database
	now         time.Time
	owner, team string
	member      Membership
	connection  IdentityConnectionSecret
	principal   ControlPrincipal
	company     oidc.TeamContext
	ctx         context.Context
	placement   ServicePlacement
}

func newReservationWaitFixture(t *testing.T, shared bool) reservationWaitFixture {
	t.Helper()
	d, now, owner, team := newAuthorityTeam(t)
	role := TeamRoleMember
	if shared {
		role = TeamRoleAdmin
	}
	_, member := allocationVisitorMember(t, d, team.ID, owner, "reservation-wait", role, now)
	domain := deploymentCustomDomain(t, d, ApplyProjectConfigurationRequest{TeamID: team.ID, ActorID: owner}, now)
	connection := companyTestConnection(t, d, team.ID, companyTestPrincipal(t, d, newOIDCSession(t, d, now), now), "approval", now)
	companyTestEligibility(t, d, connection, member.IdentityID, 1, true, now)
	if _, err := d.pool.Exec(t.Context(), `UPDATE control.identities SET issuer='https://company.example',subject=id WHERE id=$1`, member.IdentityID); err != nil {
		t.Fatal(err)
	}
	company := oidc.TeamContext{TeamID: team.ID, IdentityConnectionID: connection.ID, ConnectionRevision: connection.Revision,
		SourceID: connection.SourceID, Subject: "directory/" + member.IdentityID, AuthenticatedAt: now.Unix()}
	identity := OIDCIdentity{Issuer: "https://company.example", Subject: member.IdentityID, DisplayName: "Reservation owner",
		AssertionDigest: sha256.Sum256([]byte("reservation-company-session")), AssertionExpiry: now.Add(5 * time.Minute),
		TeamContexts: []oidc.TeamContext{company}}
	identity, err := companyBindTestIntent(t, d, identity, now)
	if err != nil {
		t.Fatal(err)
	}
	session, err := d.CreateOIDCControlSession(t.Context(), "tunnels.example.test", identity, time.Hour, 24*time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	principal := companyTestPrincipal(t, d, session, now)
	hostname := "preview." + member.MemberSlug + ".custom.example.test"
	if shared {
		hostname = "wait-shared.custom.example.test"
	}
	return reservationWaitFixture{d: d, now: now, owner: owner, team: team.ID, member: member, connection: connection,
		principal: principal, company: company, ctx: WithControlPrincipal(t.Context(), principal),
		placement: ServicePlacement{Reserve: true, DomainID: domain.ID, Hostname: hostname}}
}

func (f reservationWaitFixture) create(ctx context.Context, key string) (ServiceRecord, error) {
	return f.d.CreateServiceAt(ctx, f.team, f.member.IdentityID, "preview", key, f.placement, f.now,
		ServiceMetadata{}, &ProjectServiceConfiguration{Target: "app", Protocol: "http"})
}

func (f reservationWaitFixture) snapshot(t *testing.T) []byte {
	t.Helper()
	var snapshot []byte
	err := f.d.pool.QueryRow(t.Context(), `SELECT jsonb_build_object(
	    'services',(SELECT jsonb_agg(to_jsonb(s) ORDER BY id) FROM control.services s WHERE team_id=$1),
	    'endpoints',(SELECT jsonb_agg(to_jsonb(e) ORDER BY hostname) FROM control.service_endpoints e JOIN control.services s ON s.id=e.service_id WHERE s.team_id=$1),
	    'claims',(SELECT jsonb_agg(to_jsonb(c) ORDER BY namespace) FROM control.service_namespace_claims c WHERE domain_id=$2),
	    'receipts',(SELECT jsonb_agg(to_jsonb(r) ORDER BY idempotency_key) FROM control.service_creation_requests r WHERE created_by_identity_id=$3),
	    'grants',(SELECT jsonb_agg(to_jsonb(g) ORDER BY id) FROM control.visitor_grants g WHERE team_id=$1))`,
		f.team, f.placement.DomainID, f.member.IdentityID).Scan(&snapshot)
	if err != nil {
		t.Fatal(err)
	}
	return snapshot
}

func TestIntegrationMemberReservationDeadlineAfterBlockedAuthorization(t *testing.T) {
	for _, test := range []struct {
		operation, authority, gate string
	}{
		{"create", "company", "receipt"},
		{"recover", "company", "service"},
		{"same-key", "company", "service"},
		{"create", "eligibility", "deferred"},
		{"recover", "eligibility", "service"},
		{"same-key", "refresh", "service"},
		{"create", "access", "receipt"},
		{"recover", "actor", "membership"},
		{"create", "actor", "deferred"},
		{"recover", "signed-company", "service"},
		{"create", "current", "deferred"},
		{"recover", "signed-current", "membership"},
	} {
		t.Run(test.operation+"/"+test.authority+"/"+test.gate, func(t *testing.T) {
			f := newReservationWaitFixture(t, false)
			var original ServiceRecord
			if test.operation != "create" {
				var err error
				original, err = f.create(f.ctx, "seed")
				if err != nil {
					t.Fatal(err)
				}
			}
			key := "operation"
			if test.operation == "same-key" {
				key = "seed"
			}
			ctx, cancel := context.WithTimeout(f.ctx, 10*time.Second)
			workers := newIntegrationWorkers(t, cancel)
			defer workers.stop()
			until := f.now.Add(time.Second)
			supplied := ctx
			switch test.authority {
			case "company":
				if _, err := f.d.pool.Exec(ctx, `UPDATE control.company_session_contexts SET expires_at=$2 WHERE session_id=$1`, f.principal.SessionID, until); err != nil {
					t.Fatal(err)
				}
			case "eligibility":
				if _, err := f.d.pool.Exec(ctx, `UPDATE control.company_eligibility SET valid_until=$2 WHERE identity_connection_id=$1 AND identity_id=$3`, f.connection.ID, until, f.member.IdentityID); err != nil {
					t.Fatal(err)
				}
			case "refresh", "access":
				query := `UPDATE control.control_sessions SET access_expires_at=$2,refresh_expires_at=$2 WHERE id=$1`
				if test.authority == "access" {
					query = `UPDATE control.control_sessions SET access_expires_at=$2 WHERE id=$1`
				}
				if _, err := f.d.pool.Exec(ctx, query, f.principal.SessionID, until); err != nil {
					t.Fatal(err)
				}
			}
			if test.authority == "actor" || test.authority == "signed-company" || test.authority == "signed-current" {
				proof := managementActorProof(t, f.d, f.member.IdentityID, "reservation-wait-proof", f.now)
				proof.TeamContexts = []oidc.TeamContext{f.company}
				if test.authority == "actor" {
					proof.AssertionExpiry = until
				}
				if test.authority == "signed-company" {
					proof.TeamContexts[0].AuthenticatedAt = f.now.Add(-CompanyAuthenticationLifetime + time.Second).Unix()
				}
				supplied = WithServiceActorProof(ctx, proof, proof.Nonce)
			}
			before := f.snapshot(t)
			authoritySnapshot := func() []byte {
				t.Helper()
				var snapshot []byte
				err := f.d.pool.QueryRow(ctx, `SELECT jsonb_build_object(
				    'parent',(SELECT jsonb_build_array(access_expires_at,refresh_expires_at,revoked_at) FROM control.control_sessions WHERE id=$1),
				    'company',(SELECT jsonb_agg(jsonb_build_array(authenticated_at,expires_at) ORDER BY team_id) FROM control.company_session_contexts WHERE session_id=$1),
				    'eligibility',(SELECT valid_until FROM control.company_eligibility WHERE identity_connection_id=$2 AND identity_id=$3))`,
					f.principal.SessionID, f.connection.ID, f.member.IdentityID).Scan(&snapshot)
				if err != nil {
					t.Fatal(err)
				}
				return snapshot
			}
			originalAuthority := authoritySnapshot()
			gate, err := f.d.pool.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer rollbackTestTransaction(t, gate)
			switch test.gate {
			case "service":
				// a controlled row gate isolates the later service wait from the
				// outer team guard; this does not assert a production lock inversion.
				_, err = gate.Exec(ctx, `SELECT id FROM control.services WHERE id=$1 FOR UPDATE`, original.ID)
			case "membership":
				_, err = gate.Exec(ctx, `SELECT id FROM control.team_memberships WHERE id=$1 FOR KEY SHARE`, f.member.ID)
			default:
				_, err = gate.Exec(ctx, `SELECT pg_advisory_xact_lock(8172397)`)
				if err == nil {
					trigger := `CREATE TRIGGER reservation_wait BEFORE INSERT ON control.service_creation_requests`
					if test.gate == "deferred" {
						trigger = `CREATE CONSTRAINT TRIGGER reservation_wait AFTER INSERT ON control.service_creation_requests DEFERRABLE INITIALLY DEFERRED`
					}
					_, err = f.d.pool.Exec(ctx, `CREATE FUNCTION control.reservation_wait_gate() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_advisory_xact_lock(8172397); RETURN NEW; END $$; `+trigger+` FOR EACH ROW EXECUTE FUNCTION control.reservation_wait_gate()`)
				}
			}
			if err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			entered := make(chan time.Time, 1)
			var result ServiceRecord
			workers.Go(func() {
				entered <- time.Now()
				var err error
				result, err = f.create(supplied, key)
				done <- err
			})
			waitForPostgresBlock(t, ctx, f.d, int32(gate.Conn().PgConn().PID()), done)
			started := awaitIntegrationResult(t, ctx, entered)
			success := test.authority == "current" || test.authority == "signed-current"
			if !success {
				// the deadline is fixed before operation entry. row state stays
				// unchanged while the actual wait spends that original budget.
				timer := time.NewTimer(max(0, time.Until(started.Add(time.Second+20*time.Millisecond))))
				defer timer.Stop()
				select {
				case <-timer.C:
				case <-ctx.Done():
					t.Fatal(context.Cause(ctx))
				}
			}
			if err := gate.Commit(ctx); err != nil {
				t.Fatal(err)
			}
			err = awaitIntegrationResult(t, ctx, done)
			if !bytes.Equal(originalAuthority, authoritySnapshot()) {
				t.Fatal("reservation restarted or changed an original authorization deadline")
			}
			if success {
				if err != nil || result.ID == "" || test.operation == "recover" && result.ID != original.ID {
					t.Fatal("current authority was rejected or consumed twice", result, err)
				}
				if test.authority == "signed-current" {
					if _, err := f.d.GetService(supplied, result.ID, f.member.IdentityID); !errors.Is(err, ErrOIDCAssertionReplay) {
						t.Fatal("successful signed reservation failed to consume its original assertion exactly once", err)
					}
				}
			} else {
				want := ErrServiceAccess
				if test.authority == "actor" {
					want = ErrControlAuthentication
				} else if test.authority == "signed-company" {
					want = ErrServiceSourceSignInRequired
				}
				if !errors.Is(err, want) || result.ID != "" || !bytes.Equal(before, f.snapshot(t)) {
					t.Fatal("blocked reservation used expired authority or left durable state", result, err)
				}
			}
		})
	}
}

func TestIntegrationMemberReservationRechecksCurrentAuthorityAfterTeamWait(t *testing.T) {
	for _, boundary := range []string{"membership", "role", "session", "source", "domain", "namespace"} {
		t.Run(boundary, func(t *testing.T) {
			shared := boundary == "role" || boundary == "namespace"
			f := newReservationWaitFixture(t, shared)
			ctx, cancel := context.WithTimeout(f.ctx, 10*time.Second)
			workers := newIntegrationWorkers(t, cancel)
			defer workers.stop()
			before := f.snapshot(t)
			gate, err := f.d.pool.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer rollbackTestTransaction(t, gate)
			if _, err := controlstatedb.New(gate).LockLocalTeamForMutation(ctx, f.team); err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			var result ServiceRecord
			workers.Go(func() {
				var err error
				result, err = f.create(ctx, "blocked-current")
				done <- err
			})
			waitForPostgresBlock(t, ctx, f.d, int32(gate.Conn().PgConn().PID()), done)
			switch boundary {
			case "membership":
				_, err = gate.Exec(ctx, `UPDATE control.team_memberships SET removed_at=$2,removed_by_identity_id=$3 WHERE id=$1`, f.member.ID, f.now, f.owner)
			case "role":
				_, err = gate.Exec(ctx, `UPDATE control.team_memberships SET role='member' WHERE id=$1`, f.member.ID)
			case "session":
				_, err = gate.Exec(ctx, `UPDATE control.control_sessions SET revoked_at=$2,revoked_by=identity_id WHERE id=$1`, f.principal.SessionID, f.now)
			case "source":
				_, err = gate.Exec(ctx, `UPDATE control.identity_connections SET state='retired' WHERE id=$1`, f.connection.ID)
			case "domain":
				_, err = gate.Exec(ctx, `UPDATE control.domains SET state='releasing' WHERE id=$1`, f.placement.DomainID)
			case "namespace":
				_, err = controlstatedb.New(gate).ReserveInvitedMemberSlug(ctx, controlstatedb.ReserveInvitedMemberSlugParams{
					ID: mustOpaqueID(t, opaqueid.SlugReservationPrefix), TeamID: f.team, MemberSlug: "wait-shared",
					ReservedByIdentityID: text(f.owner), CreatedAt: timestamptz(f.now),
				})
			}
			if err != nil {
				t.Fatal(err)
			}
			if err := gate.Commit(ctx); err != nil {
				t.Fatal(err)
			}
			err = awaitIntegrationResult(t, ctx, done)
			if !errors.Is(err, ErrServiceAccess) || result.ID != "" || !bytes.Equal(before, f.snapshot(t)) {
				t.Fatal("team wait retained stale membership, session, domain, or namespace authority", result, err)
			}
		})
	}
}

package controlstate

import (
	"context"
	"crypto/sha256"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/tnldotdev/tnl/internal/controlstate/controlstatedb"
)

func TestIntegrationHostedRouteCreationDoesNotDeadlockSessionCreation(t *testing.T) {
	database, now := newCertificatePlanDatabase(t)
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	const identity = "identity_concurrent_creator"
	secret, err := database.EnsureExternalAuthorityPrincipal(ctx, identity, now)
	if err != nil {
		t.Fatal(err)
	}
	request := CreatePublicURLRequest{
		TeamID: "team_external", DomainID: "domain_external", MembershipID: "membership_external", ActingIdentityID: identity,
		IdempotencyKey: "first", RequestDigest: sha256.Sum256([]byte("first")), CanonicalHostname: "first.member.example.test",
		Target: "http://127.0.0.1:3000", PublicURLScope: PublicURLScopeMember, DNSState: PublicURLDNSUnmanaged,
		AuthorityIssuer: "https://authority.example.test", PolicyRevision: 1,
	}
	first, err := database.CreatePublicURL(ctx, request, now)
	if err != nil {
		t.Fatal(err)
	}
	gate, err := database.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer rollbackTestTransaction(t, gate)
	if _, err := gate.Exec(ctx, `SELECT control_name FROM control.maintenance_controls WHERE control_name = 'publish_run_creation' FOR UPDATE`); err != nil {
		t.Fatal(err)
	}
	workers := newIntegrationWorkers(t, cancel)
	defer workers.stop()
	var session PublishRunSetup
	sessionDone := make(chan error, 1)
	workers.Go(func() {
		var err error
		session, err = database.CreatePublishRun(ctx, PublishRunRequest{
			PublicURLID: first.ID, TeamID: first.TeamID, MembershipID: first.MembershipID, ActingIdentityID: identity,
			RetrySecret: secret[:], IdempotencyKey: "session", RequestDigest: sha256.Sum256([]byte("session")),
			PolicyRevision: 1, AuthorityIssuer: request.AuthorityIssuer, ExpectedMutationRevision: first.MutationRevision,
			CertificateCacheKey: first.CanonicalHostname, CertificateScope: first.CanonicalHostname,
			CertificateIdentifiers: []string{first.CanonicalHostname}, CertificateChallenge: "tls-alpn-01",
		}, now, time.Minute, time.Minute)
		sessionDone <- err
	})
	// The session holds the authority revision while waiting for the maintenance gate.
	sessionPID := waitForPostgresBlock(t, ctx, database, int32(gate.Conn().PgConn().PID()), sessionDone)
	siblingRequest := request
	siblingRequest.IdempotencyKey, siblingRequest.CanonicalHostname = "sibling", "sibling.member.example.test"
	siblingRequest.RequestDigest = sha256.Sum256([]byte("sibling"))
	var sibling PublicURL
	creatorDone := make(chan error, 1)
	workers.Go(func() {
		var err error
		sibling, err = database.CreatePublicURL(ctx, siblingRequest, now)
		creatorDone <- err
	})
	// The creator now holds the identity lock and waits for the session's authority revision.
	// Releasing the gate makes the session's INSERT check its identity foreign key.
	waitForPostgresBlock(t, ctx, database, sessionPID, creatorDone)
	if err := gate.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	for name, done := range map[string]<-chan error{"session": sessionDone, "creator": creatorDone} {
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("%s failed under concurrent route creation: %v", name, err)
			}
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
	}
	if t.Failed() {
		return
	}
	if session.PublicURLID != first.ID || session.PublishRunNumber != 1 || sibling.ID == first.ID || sibling.CanonicalHostname != siblingRequest.CanonicalHostname {
		t.Fatal("concurrent operations did not preserve their separate route identities")
	}
	var routes, sessions int
	if err := database.pool.QueryRow(ctx, `
		SELECT (SELECT count(*) FROM control.public_urls WHERE team_id = $1),
		       (SELECT count(*) FROM control.publish_runs WHERE team_id = $1)
	`, request.TeamID).Scan(&routes, &sessions); err != nil || routes != 2 || sessions != 1 {
		t.Fatalf("persisted routes/sessions = %d/%d, error %v; want 2/1", routes, sessions, err)
	}
	if _, err := database.pool.Exec(ctx, `UPDATE control.identities SET disabled_at = $2 WHERE id = $1`, identity, now); err != nil {
		t.Fatal(err)
	}
	if _, err := database.CreatePublicURL(ctx, siblingRequest, now); !errors.Is(err, ErrPublicURLAccess) {
		t.Fatalf("disabled creator was not rejected before idempotent reuse: %v", err)
	}
}

func TestIntegrationRouteCreatorLockPreservesIdentityProtection(t *testing.T) {
	database, now := newControlStateIntegrationDatabase(t, "creator_lock")
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	const identity = "identity_creator_lock"
	if _, err := database.EnsureExternalAuthorityPrincipal(ctx, identity, now); err != nil {
		t.Fatal(err)
	}
	owner, err := database.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer rollbackTestTransaction(t, owner)
	if _, err := controlstatedb.New(owner).LockPublicURLCreator(ctx, identity); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name, statement string
		blocked         bool
	}{
		{"foreign_key_check", `SELECT id FROM control.identities WHERE id = $1 FOR KEY SHARE`, false},
		{"another_creator", "", true},
		{"disable", `UPDATE control.identities SET disabled_at = now() WHERE id = $1`, true},
		{"delete", `DELETE FROM control.identities WHERE id = $1`, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			other, err := database.pool.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer rollbackTestTransaction(t, other)
			if _, err := other.Exec(ctx, `SET LOCAL lock_timeout = '100ms'`); err != nil {
				t.Fatal(err)
			}
			if test.statement == "" {
				_, err = controlstatedb.New(other).LockPublicURLCreator(ctx, identity)
			} else {
				_, err = other.Exec(ctx, test.statement, identity)
			}
			var postgresError *pgconn.PgError
			if test.blocked {
				if !errors.As(err, &postgresError) || postgresError.Code != "55P03" {
					t.Fatalf("identity mutation was not blocked by the creator: %v", err)
				}
			} else if err != nil {
				t.Fatalf("identity foreign-key check was blocked: %v", err)
			}
		})
	}
}

func TestIntegrationTeamCreationIdentityLockAvoidsDomainForeignKeyCycle(t *testing.T) {
	database, now := newControlStateIntegrationDatabase(t, "team_creator_domain_fk")
	session := newBuiltinSession(t, database, now)
	identity := session.Identity.Identity.ID
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	gate, err := database.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer rollbackTestTransaction(t, gate)
	if _, err := gate.Exec(ctx, `SELECT id FROM control.domains WHERE kind = 'managed' FOR UPDATE`); err != nil {
		t.Fatal(err)
	}
	workers := newIntegrationWorkers(t, cancel)
	created := make(chan error, 1)
	workers.Go(func() {
		_, err := database.CreateTeam(ctx, authorityTeamRequest(identity), now)
		created <- err
	})
	waitForPostgresBlock(t, ctx, database, int32(gate.Conn().PgConn().PID()), created)
	if _, err := gate.Exec(ctx, `SET LOCAL lock_timeout = '100ms'`); err != nil {
		t.Fatal(err)
	}
	// This models an identity foreign-key check performed by domain work while
	// team creation is waiting on the domain row.
	if _, err := gate.Exec(ctx, `SELECT id FROM control.identities WHERE id = $1 FOR KEY SHARE`, identity); err != nil {
		t.Fatalf("team creator blocked domain identity foreign-key work: %v", err)
	}
	if err := gate.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err := awaitIntegrationResult(t, ctx, created); err != nil {
		t.Fatal(err)
	}
}

func TestIntegrationTeamCreatorLockPreservesIdentityProtection(t *testing.T) {
	database, now := newControlStateIntegrationDatabase(t, "team_creator_lock")
	session := newBuiltinSession(t, database, now)
	identity := session.Identity.Identity.ID
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	owner, err := database.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer rollbackTestTransaction(t, owner)
	if _, err := controlstatedb.New(owner).LockIdentityForTeamCreation(ctx, identity); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name, statement string
		blocked         bool
	}{
		{"foreign_key_check", `SELECT id FROM control.identities WHERE id = $1 FOR KEY SHARE`, false},
		{"another_creator", "", true},
		{"disable", `UPDATE control.identities SET disabled_at = now() WHERE id = $1`, true},
		{"delete", `DELETE FROM control.identities WHERE id = $1`, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			other, err := database.pool.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer rollbackTestTransaction(t, other)
			if _, err := other.Exec(ctx, `SET LOCAL lock_timeout = '100ms'`); err != nil {
				t.Fatal(err)
			}
			if test.statement == "" {
				_, err = controlstatedb.New(other).LockIdentityForTeamCreation(ctx, identity)
			} else {
				_, err = other.Exec(ctx, test.statement, identity)
			}
			var postgresError *pgconn.PgError
			if test.blocked {
				if !errors.As(err, &postgresError) || postgresError.Code != "55P03" {
					t.Fatalf("identity mutation was not blocked by the team creator: %v", err)
				}
			} else if err != nil {
				t.Fatalf("identity foreign-key check was blocked: %v", err)
			}
		})
	}
}

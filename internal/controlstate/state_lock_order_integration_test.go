package controlstate

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/controlstate/controlstatedb"
	"github.com/tnldotdev/tnl/internal/publisheridentity"
)

func TestIntegrationStateLockOrderPublisherRevocation(t *testing.T) {
	for _, kind := range []string{"identity", "grant"} {
		t.Run(kind, func(t *testing.T) {
			d, now, r, _ := newPublishRunPrerequisites(t)
			u, err := d.GetPublicURLForAuthorization(t.Context(), r.PublicURLID)
			if err != nil {
				t.Fatal(err)
			}
			e := publisherEnrollment(t, d, CreatePublicURLRequest{TeamID: r.TeamID, ActingIdentityID: r.ActingIdentityID}, PublisherScope{TeamID: r.TeamID, Kind: "saved_url", PublicURLID: r.PublicURLID}, now)
			public, private, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			p, err := d.RedeemPublisherEnrollment(t.Context(), e.Key, public, now)
			if err != nil {
				t.Fatal(err)
			}
			plan, err := d.PublisherRunPlan(t.Context(), p, u, false)
			if err != nil {
				t.Fatal(err)
			}
			r.CertificateCacheKey, r.CertificateScope, r.CertificateIdentifiers, r.CertificateChallenge = plan.CacheKey, plan.Scope, plan.Identifiers, plan.ChallengeMethod
			r.PublisherIdentityID, r.PublisherGrantID, r.PublisherKeyID = p.ID, p.GrantID, p.KeyID
			r.PublisherRunProof, err = publisheridentity.SignRun(private, r.PublicURLID, r.IdempotencyKey)
			if err != nil {
				t.Fatal(err)
			}
			r.RetrySecret = nil
			setup, err := d.CreatePublishRun(t.Context(), r, now, time.Minute, time.Minute)
			if err != nil {
				t.Fatal(err)
			}
			auth := PublishRunAuthentication{PublicURLID: r.PublicURLID, PublishRunID: setup.PublishRunID, PublishRunNumber: setup.PublishRunNumber, PublishRunToken: setup.PublishRunToken}
			ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
			defer cancel()
			workers := newIntegrationWorkers(t, cancel)
			gate, err := d.pool.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer rollbackTestTransaction(t, gate)
			if _, err = controlstatedb.New(gate).LockPublishRun(ctx, setup.PublishRunID); err != nil {
				t.Fatal(err)
			}
			heartbeat := make(chan error, 1)
			workers.Go(func() {
				_, err := d.HeartbeatPublishRun(ctx, auth, now.Add(time.Second), time.Minute, time.Minute)
				heartbeat <- err
			})
			pid := waitForPostgresBlock(t, ctx, d, int32(gate.Conn().PgConn().PID()), heartbeat)
			revoked := make(chan error, 1)
			workers.Go(func() {
				if kind == "identity" {
					revoked <- d.RevokePublisherIdentity(ctx, r.TeamID, p.ID, r.ActingIdentityID, now.Add(2*time.Second))
				} else {
					revoked <- d.RevokePublisherGrant(ctx, r.TeamID, p.ID, p.GrantID, r.ActingIdentityID, now.Add(2*time.Second))
				}
			})
			waitForPostgresBlock(t, ctx, d, pid, revoked)
			if err = gate.Commit(ctx); err != nil {
				t.Fatal(err)
			}
			heartbeatErr, revokeErr := awaitIntegrationResult(t, ctx, heartbeat), awaitIntegrationResult(t, ctx, revoked)
			if heartbeatErr != nil || revokeErr != nil {
				t.Fatalf("heartbeat = %v; revocation = %v", heartbeatErr, revokeErr)
			}
			if _, err = d.HeartbeatPublishRun(ctx, auth, now.Add(3*time.Second), time.Minute, time.Minute); !errors.Is(err, ErrPublisherIdentity) && !errors.Is(err, ErrPublishRunStale) {
				t.Fatalf("revoked run heartbeat = %v", err)
			}
		})
	}
}

func stateLockActor(t *testing.T, d *Database, actor, nonce string, now time.Time) OIDCIdentity {
	t.Helper()
	if _, err := d.pool.Exec(t.Context(), `UPDATE control.identities SET kind='oidc',issuer='https://lock.example',subject=id WHERE id=$1`, actor); err != nil {
		t.Fatal(err)
	}
	return OIDCIdentity{Issuer: "https://lock.example", Subject: actor, Nonce: nonce, AssertionID: nonce,
		AssertionDigest: sha256.Sum256([]byte(nonce)), IssuedAt: now, AssertionExpiry: now.Add(time.Minute)}
}

func TestIntegrationStateLockOrderServiceActor(t *testing.T) {
	for _, operation := range []string{"list-grants", "create-grant", "create-service", "delete-service"} {
		t.Run(operation, func(t *testing.T) {
			d, now := newControlStateIntegrationDatabase(t, "service_actor_order")
			r := appliedProjectRequest(t, d, now)
			s, err := d.CreatePrivateService(t.Context(), r.TeamID, r.ActorID, "database", "database", now)
			if err != nil {
				t.Fatal(err)
			}
			identity := stateLockActor(t, d, r.ActorID, operation, now)
			otherRequest := authorityTeamRequest(r.ActorID)
			otherRequest.DisplayName, otherRequest.IdempotencyKey = "unrelated", "unrelated"
			other, err := d.CreateTeam(t.Context(), otherRequest, now)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			workers := newIntegrationWorkers(t, cancel)
			gate, err := d.pool.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer rollbackTestTransaction(t, gate)
			// an ordinary control-session apply queues on this guard before the
			// team row, without taking the signed actor's identity bootstrap lock.
			if _, err = gate.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('tnl:local-team:' || $1::text,0))`, r.TeamID); err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			workers.Go(func() {
				signed := WithServiceActorProof(ctx, identity, operation)
				var err error
				switch operation {
				case "list-grants":
					_, _, err = d.ListPrivateServiceGrants(signed, s.ID, r.ActorID, "")
				case "create-grant":
					_, err = d.CreatePrivateServiceGrant(signed, s.ID, r.ActorID, "team", "team", "", nil, now)
				case "create-service":
					_, err = d.CreatePrivateService(signed, r.TeamID, r.ActorID, "second", "second", now)
				case "delete-service":
					err = d.DeletePrivateService(signed, s.ID, r.ActorID, now)
				}
				done <- err
			})
			waitForPostgresBlock(t, ctx, d, int32(gate.Conn().PgConn().PID()), done)
			// ordinary apply does not participate in identity bootstrap. another
			// team's apply must finish even while this signed manager is blocked.
			unrelated := r
			unrelated.TeamID = other.ID
			if _, err = d.ApplyProjectConfiguration(ctx, unrelated); err != nil {
				t.Fatalf("unrelated control-session apply = %v", err)
			}
			if _, err = gate.Exec(ctx, `SELECT id FROM control.teams WHERE id=$1 FOR UPDATE NOWAIT`, r.TeamID); err != nil {
				t.Fatalf("signed manager took team row before advisory guard: %v", err)
			}
			if err = gate.Commit(ctx); err != nil {
				t.Fatal(err)
			}
			if err = awaitIntegrationResult(t, ctx, done); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestIntegrationStateLockOrderCompanyDecision(t *testing.T) {
	d, now, owner, team := newAuthorityTeam(t)
	identity := stateLockActor(t, d, owner, "decision", now)
	var member string
	if err := d.pool.QueryRow(t.Context(), `SELECT id FROM control.team_memberships WHERE team_id=$1 AND identity_id=$2`, team.ID, owner).Scan(&member); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	workers := newIntegrationWorkers(t, cancel)
	gate, err := d.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer rollbackTestTransaction(t, gate)
	// signed ReadCompanyConnections owns bootstrap before requesting the team.
	if err = controlstatedb.New(gate).LockIdentityBootstrap(ctx); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	workers.Go(func() {
		done <- d.SetCompanyMembershipDecision(WithCompanyActorProof(ctx, identity, "decision"), ControlPrincipal{}, team.ID, member, false, false, false, now)
	})
	waitForPostgresBlock(t, ctx, d, int32(gate.Conn().PgConn().PID()), done)
	if _, err = gate.Exec(ctx, `SET LOCAL lock_timeout='250ms'`); err != nil {
		t.Fatal(err)
	}
	if _, err = controlstatedb.New(gate).LockLocalTeamForMutation(ctx, team.ID); err != nil {
		t.Fatalf("company decision took team before identity bootstrap: %v", err)
	}
	if err = gate.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err = awaitIntegrationResult(t, ctx, done); err != nil {
		t.Fatal(err)
	}
	read := stateLockActor(t, d, owner, "read", now)
	if _, err = d.ReadCompanyConnections(WithCompanyActorProof(ctx, read, "read"), ControlPrincipal{}, team.ID, now); err != nil {
		t.Fatal(err)
	}
}

func TestIntegrationStateLockOrderApplyExpiration(t *testing.T) {
	d, now := newControlStateIntegrationDatabase(t, "apply_expiration_order")
	r := appliedProjectRequest(t, d, now)
	r.Configuration.Publishers = map[string]ProjectPublisherGroup{"production": {}}
	r.Configuration.Services = map[string]ProjectServiceConfiguration{
		"a": {Publisher: "production", Protocol: "tcp", Target: "localhost:5001"},
		"b": {Publisher: "production", Protocol: "tcp", Target: "localhost:5002"},
	}
	applied, err := d.ApplyProjectConfiguration(t.Context(), r)
	if err != nil {
		t.Fatal(err)
	}
	unrelated, err := d.CreatePrivateService(t.Context(), r.TeamID, r.ActorID, "unrelated", "unrelated", now)
	if err != nil {
		t.Fatal(err)
	}
	service := applied.Services[1].ServiceID
	e, err := d.IssuePublisherGroupEnrollment(t.Context(), r.TeamID, r.ProjectKey, "production", r.ActorID, 1, time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	replica := enrollAppliedGroup(t, d, r, e, now)
	access := groupAssignmentAccess(t, d, replica, replica.assignments.Services[1], now)
	prepared, err := d.PreparePrivateServiceRun(t.Context(), service, access.PublisherIdentity, "prepared", now, PrivateServiceMetadata{Protocol: "tcp", PublisherPool: true, TrustRevision: 1})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	workers := newIntegrationWorkers(t, cancel)
	gate, err := d.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer rollbackTestTransaction(t, gate)
	if _, err = controlstatedb.New(gate).LockPrivateServiceRun(ctx, controlstatedb.LockPrivateServiceRunParams{ID: prepared.RunID, PrivateServiceID: service}); err != nil {
		t.Fatal(err)
	}
	expired := make(chan error, 1)
	workers.Go(func() {
		_, err := d.ExpirePrivateServiceRuns(ctx, prepared.ExpiresAt)
		expired <- err
	})
	pid := waitForPostgresBlock(t, ctx, d, int32(gate.Conn().PgConn().PID()), expired)
	r.ExpectedRevision, r.Now = applied.Revision, prepared.ExpiresAt
	r.Configuration.Services = map[string]ProjectServiceConfiguration{}
	updated := make(chan error, 1)
	workers.Go(func() { _, err := d.ApplyProjectConfiguration(ctx, r); updated <- err })
	waitForPostgresBlock(t, ctx, d, pid, updated)
	if _, err = gate.Exec(ctx, `SELECT id FROM control.private_services WHERE id=$1 FOR UPDATE NOWAIT`, unrelated.ID); err != nil {
		t.Fatalf("apply locked a service outside its project: %v", err)
	}
	if err = gate.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	expireErr, applyErr := awaitIntegrationResult(t, ctx, expired), awaitIntegrationResult(t, ctx, updated)
	if expireErr != nil || applyErr != nil {
		t.Fatalf("expiration = %v; apply = %v", expireErr, applyErr)
	}
	var open int
	if err = d.pool.QueryRow(ctx, `SELECT count(*) FROM control.private_service_runs WHERE closed_at IS NULL`).Scan(&open); err != nil || open != 0 {
		t.Fatalf("open runs after removal = %d, %v", open, err)
	}
}

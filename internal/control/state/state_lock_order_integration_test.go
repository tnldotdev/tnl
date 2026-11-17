package state

import (
	"context"
	"crypto/sha256"
	"errors"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
)

func TestIntegrationStateLockOrderPublisherRevocation(t *testing.T) {
	for _, kind := range []string{"identity", "grant"} {
		t.Run(kind, func(t *testing.T) {
			f := newServicePublicationFixture(t)
			// keep a live run so heartbeat contends with revocation.
			ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
			defer cancel()
			workers := newIntegrationWorkers(t, cancel)
			defer workers.stop()
			gate, err := f.database.pool.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer rollbackTestTransaction(t, gate)
			if _, err = controlstatedb.New(gate).LockServiceRun(ctx, controlstatedb.LockServiceRunParams{ID: f.run.RunID, ServiceID: f.service.ID}); err != nil {
				t.Fatal(err)
			}
			heartbeat := make(chan error, 1)
			workers.Go(func() {
				_, err := f.database.HeartbeatServiceRun(ctx, f.service.ID, f.run.RunID, f.run.Token, f.now.Add(time.Second), ServiceRunHealth{StreamCapacity: 64})
				heartbeat <- err
			})
			pid := waitForPostgresBlock(t, ctx, f.database, int32(gate.Conn().PgConn().PID()), heartbeat)
			revoked := make(chan error, 1)
			actor := f.actor(t)
			workers.Go(func() {
				if kind == "identity" {
					revoked <- f.database.RevokePublisherIdentity(ctx, f.service.TeamID, f.publisher.ID, actor, f.now.Add(2*time.Second))
				} else {
					revoked <- f.database.RevokePublisherGrant(ctx, f.service.TeamID, f.publisher.ID, f.publisher.GrantID, actor, f.now.Add(2*time.Second))
				}
			})
			waitForPostgresBlock(t, ctx, f.database, pid, revoked)
			if err = gate.Commit(ctx); err != nil {
				t.Fatal(err)
			}
			heartbeatErr, revokeErr := awaitIntegrationResult(t, ctx, heartbeat), awaitIntegrationResult(t, ctx, revoked)
			if heartbeatErr != nil || revokeErr != nil {
				t.Fatalf("heartbeat = %v; revocation = %v", heartbeatErr, revokeErr)
			}
			if _, err = f.database.HeartbeatServiceRun(ctx, f.service.ID, f.run.RunID, f.run.Token, f.now.Add(3*time.Second), ServiceRunHealth{StreamCapacity: 64}); !errors.Is(err, ErrServiceAccess) {
				t.Fatalf("post-revocation heartbeat = %v", err)
			}
			var closed bool
			if err = f.database.pool.QueryRow(t.Context(), `SELECT state='closed' AND closed_at IS NOT NULL FROM control.service_runs WHERE id=$1`, f.run.RunID).Scan(&closed); err != nil || !closed {
				t.Fatalf("revoked run not closed: closed=%t err=%v", closed, err)
			}
			if kind == "identity" {
				var revokedAt bool
				if err = f.database.pool.QueryRow(t.Context(), `SELECT revoked_at IS NOT NULL FROM control.publisher_identities WHERE id=$1`, f.publisher.ID).Scan(&revokedAt); err != nil || !revokedAt {
					t.Fatalf("publisher identity not revoked: revoked=%t err=%v", revokedAt, err)
				}
			} else {
				var revokedAt bool
				if err = f.database.pool.QueryRow(t.Context(), `SELECT revoked_at IS NOT NULL FROM control.publisher_grants WHERE id=$1`, f.publisher.GrantID).Scan(&revokedAt); err != nil || !revokedAt {
					t.Fatalf("publisher grant not revoked: revoked=%t err=%v", revokedAt, err)
				}
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
			s, err := d.CreateServiceAt(t.Context(), r.TeamID, r.ActorID, "database", "database", ServicePlacement{}, now, ServiceMetadata{Protocol: "tcp"}, nil)
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
					_, _, err = d.ListServiceGrants(signed, s.ID, r.ActorID, "")
				case "create-grant":
					_, err = d.CreateServiceGrant(signed, s.ID, r.ActorID, "team", "team", "", nil, now)
				case "create-service":
					_, err = d.CreateServiceAt(signed, r.TeamID, r.ActorID, "second", "second", ServicePlacement{}, now, ServiceMetadata{Protocol: "tcp"}, nil)
				case "delete-service":
					err = d.DeleteService(signed, s.ID, r.ActorID, observedServiceDeletion(t, d, s.ID), now)
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
		done <- d.UpdateCompanyMembershipDecision(WithCompanyActorProof(ctx, identity, "decision"), ControlPrincipal{}, team.ID, member, CompanyMembershipDecision{}, now)
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
	r.Configuration.Settings = &DeploymentSettings{}
	r.Configuration.Services = map[string]ProjectServiceConfiguration{
		"a": {Protocol: "tcp", Target: "localhost:5001"},
		"b": {Protocol: "tcp", Target: "localhost:5002"},
	}
	r = selectedProjectRequest(r, "production")
	applied, err := d.ApplyProjectConfiguration(t.Context(), r)
	if err != nil {
		t.Fatal(err)
	}
	unrelated, err := d.CreateServiceAt(t.Context(), r.TeamID, r.ActorID, "unrelated", "unrelated", ServicePlacement{}, now, ServiceMetadata{Protocol: "tcp"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	service := applied.Services[1].ServiceID
	e, err := testDeploymentPublisherEnrollment(d, t.Context(), r.TeamID, r.ProjectKey, "production", r.ActorID, 1, time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	replica := enrollAppliedDeployment(t, d, r, e, now)
	access := deploymentAssignmentAccess(t, d, replica, replica.assignments.Services[1], now)
	prepared, err := d.PrepareServiceRun(t.Context(), service, access.PublisherIdentity, "prepared", now, ServiceRunRequest{Metadata: ServiceMetadata{Protocol: "tcp", PublisherPool: true, TrustRevision: 1}})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	gate, key := newExpirationProgressCloseGate(t, ctx, d, prepared.RunID)
	defer rollbackTestTransaction(t, gate)
	workers := newIntegrationWorkers(t, cancel)
	defer workers.stop()
	expired := make(chan error, 1)
	workers.Go(func() {
		count, err := d.ExpireServiceRuns(ctx, prepared.ExpiresAt)
		if err == nil && count != 1 {
			err = errors.New("admitted expiration did not close the exact prepared run")
		}
		expired <- err
	})
	// pause the actual close after owner/service/run acquisition, rather than
	// holding a run that nonblocking cleanup must now skip.
	pid := waitForExpirationProgressAdvisory(t, ctx, d, int32(gate.Conn().PgConn().PID()),
		"ExclusiveLock", "ExclusiveLock", key, "-- name: CloseServiceRun", expired)
	r.ExpectedRevision, r.Now = applied.Revision, prepared.ExpiresAt
	r.Configuration.Services = map[string]ProjectServiceConfiguration{}
	updated := make(chan error, 1)
	workers.Go(func() { _, err := d.ApplyProjectConfiguration(ctx, r); updated <- err })
	waitForExpirationProgressAdvisory(t, ctx, d, pid, "ShareLock", "ExclusiveLock",
		"tnl:local-team:"+r.TeamID, "-- name: LockLocalTeamForMutation", updated)
	if _, err = gate.Exec(ctx, `SELECT id FROM control.services WHERE id=$1 FOR UPDATE NOWAIT`, unrelated.ID); err != nil {
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
	if err = d.pool.QueryRow(ctx, `SELECT count(*) FROM control.service_runs WHERE closed_at IS NULL`).Scan(&open); err != nil || open != 0 {
		t.Fatalf("open runs after removal = %d, %v", open, err)
	}
}

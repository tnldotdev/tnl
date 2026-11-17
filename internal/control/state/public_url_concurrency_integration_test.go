package state

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
)

func TestIntegrationRouteCreationDoesNotDeadlockSessionCreation(t *testing.T) {
	f := newServicePublicationFixture(t)
	database, now := f.database, f.now
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	identity := f.actor(t)
	if err := database.CloseServiceRun(ctx, f.service.ID, f.run.RunID, f.run.Token, now); err != nil {
		t.Fatal(err)
	}
	gate, err := database.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer rollbackTestTransaction(t, gate)
	if _, err := gate.Exec(ctx, `SELECT operation FROM control.maintenance_controls WHERE operation = 'service_run_creation' FOR UPDATE`); err != nil {
		t.Fatal(err)
	}
	workers := newIntegrationWorkers(t, cancel)
	defer workers.stop()
	var session ServiceRunPreparation
	sessionDone := make(chan error, 1)
	workers.Go(func() {
		var err error
		session, err = database.PrepareServiceRun(ctx, f.service.ID, f.publisher, "concurrent", now,
			ServiceRunRequest{Metadata: f.service.ServiceMetadata})
		sessionDone <- err
	})
	// preparation owns admission while waiting for maintenance.
	sessionPID := waitForPostgresBlock(t, ctx, database, int32(gate.Conn().PgConn().PID()), sessionDone)
	var sibling ServiceRecord
	creatorDone := make(chan error, 1)
	workers.Go(func() {
		var err error
		sibling, err = database.CreateServiceAt(ctx, f.service.TeamID, identity, "sibling", "sibling",
			ServicePlacement{}, now, ServiceMetadata{}, &ProjectServiceConfiguration{Target: "localhost:3000"})
		creatorDone <- err
	})
	// the same team guard serializes creation without an identity FK cycle.
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
	if session.ServiceID != f.service.ID || session.RunNumber != 2 || sibling.ID == f.service.ID || sibling.Name != "sibling" {
		t.Fatal("concurrent operations did not preserve separate service identities")
	}
	var routes, sessions int
	if err := database.pool.QueryRow(ctx, `
		SELECT (SELECT count(*) FROM control.services WHERE team_id = $1),
		       (SELECT count(*) FROM control.service_runs WHERE team_id = $1)
	`, f.service.TeamID).Scan(&routes, &sessions); err != nil || routes != 2 || sessions != 2 {
		t.Fatalf("persisted services/runs = %d/%d, error %v; want 2/2", routes, sessions, err)
	}
	if _, err := database.pool.Exec(ctx, `UPDATE control.identities SET disabled_at = $2 WHERE id = $1`, identity, now); err != nil {
		t.Fatal(err)
	}
	if _, err := database.CreateServiceAt(ctx, f.service.TeamID, identity, "sibling", "sibling",
		ServicePlacement{}, now, ServiceMetadata{}, &ProjectServiceConfiguration{Target: "localhost:3000"}); !errors.Is(err, ErrServiceAccess) {
		t.Fatalf("disabled creator was not rejected before idempotent reuse: %v", err)
	}
}

func TestIntegrationTeamCreationIdentityLockAvoidsDomainForeignKeyCycle(t *testing.T) {
	database, now := newControlStateIntegrationDatabase(t, "team_creator_domain_fk")
	session := newOIDCSession(t, database, now)
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
	// this models an identity foreign-key check performed by domain work while
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
	session := newOIDCSession(t, database, now)
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

package state

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
)

func TestIntegrationTransactionLocalAuthorityLockOrder(t *testing.T) {
	for _, operation := range []string{"prepare", "update", "delete"} {
		t.Run(operation, func(t *testing.T) {
			f := newServicePublicationFixture(t)
			// prepare path needs no open run on this service.
			if operation == "prepare" {
				if err := f.database.CloseServiceRun(t.Context(), f.service.ID, f.run.RunID, f.run.Token, f.now); err != nil {
					t.Fatal(err)
				}
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
			operationDone := make(chan error, 1)
			workers.Go(func() {
				var err error
				switch operation {
				case "prepare":
					_, err = f.database.PrepareServiceRun(ctx, f.service.ID, f.publisher, "next", f.now, ServiceRunRequest{Metadata: f.service.ServiceMetadata})
				case "update":
					_, err = f.database.ConfigureService(ctx, f.service.ID, f.actor(t), f.service.ServiceMetadata, &ProjectServiceConfiguration{Target: "http://127.0.0.1:3001"}, ServiceUpdateConditions{}, f.now)
				case "delete":
					err = f.database.DeleteService(ctx, f.service.ID, f.actor(t), f.now)
				}
				operationDone <- err
			})
			// service operation must wait on the held service lock (real lock graph serialization).
			waitForPostgresBlock(t, ctx, f.database, int32(gate.Conn().PgConn().PID()), operationDone)
			if err := gate.Commit(ctx); err != nil {
				t.Fatal(err)
			}
			if err := awaitIntegrationResult(t, ctx, operationDone); err != nil {
				t.Fatalf("%s did not complete successfully after lock release: %v", operation, err)
			}
			switch operation {
			case "prepare":
				var open int
				if err := f.database.pool.QueryRow(t.Context(), `SELECT count(*) FROM control.service_runs WHERE service_id=$1 AND state='prepared'`, f.service.ID).Scan(&open); err != nil || open != 1 {
					t.Fatalf("prepare did not leave exactly one prepared run: count=%d err=%v", open, err)
				}
			case "delete":
				// durable no-resurrection: deleted service cannot be prepared/started again.
				if _, err := f.database.PrepareServiceRun(t.Context(), f.service.ID, f.publisher, "after-delete", f.now, ServiceRunRequest{Metadata: f.service.ServiceMetadata}); !errors.Is(err, ErrServiceAccess) {
					t.Fatalf("deleted service was resurrected by prepare: %v", err)
				}
			}
		})
	}
}

func TestIntegrationTransactionDNSAuthorityLockOrder(t *testing.T) {
	for _, saveFirst := range []bool{false, true} {
		t.Run(fmt.Sprintf("save_first_%t", saveFirst), func(t *testing.T) {
			database, now := newControlStateIntegrationDatabase(t, "dns_authority_order")
			session := newOIDCSession(t, database, now)
			owner := session.Identity.Identity.ID
			team, err := database.CreateTeam(t.Context(), CreateTeamRequest{
				IdentityID: owner, IdempotencyKey: "team", RequestDigest: sha256.Sum256([]byte("team")), DisplayName: "transaction-tests", MemberSlug: "owner",
			}, now)
			if err != nil {
				t.Fatal(err)
			}
			domain, err := database.ClaimTeamDomain(t.Context(), ClaimDomainRequest{
				IdentityID: owner, TeamID: team.ID, IdempotencyKey: "default-domain", RequestDigest: sha256.Sum256([]byte("default-domain")),
				Domain: "default.example.test", MakeDefault: true,
			}, now)
			if err != nil {
				t.Fatal(err)
			}
			work, found, err := database.ClaimDNSAuthorityWork(t.Context(), "ready-default", now, time.Minute)
			if err != nil || !found || work.Reference != domain.DNSAuthorityReference {
				t.Fatalf("claim default domain work: found=%t ref=%v err=%v", found, work.Reference, err)
			}
			work.State, work.ProviderZoneID, work.Nameservers = "ready", "ZDEFAULT", []string{"ns-1.example.test"}
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			gate, err := database.pool.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer rollbackTestTransaction(t, gate)
			if saveFirst {
				_, err = controlstatedb.New(gate).LockDNSAuthority(ctx, work.Reference)
			} else {
				_, err = controlstatedb.New(gate).LockTeamDomain(ctx, controlstatedb.LockTeamDomainParams{DomainID: domain.ID, TeamID: text(team.ID)})
			}
			if err != nil {
				t.Fatal(err)
			}
			workers := newIntegrationWorkers(t, cancel)
			defer workers.stop()
			saveDone, releaseDone := make(chan error, 1), make(chan error, 1)
			save := func() { _, err := database.SaveDNSAuthorityWork(ctx, work, now); saveDone <- err }
			release := func() { releaseDone <- database.ReleaseTeamDomain(ctx, owner, team.ID, domain.ID, now) }
			if saveFirst {
				workers.Go(save)
				firstPID := waitForPostgresBlock(t, ctx, database, int32(gate.Conn().PgConn().PID()), saveDone)
				workers.Go(release)
				waitForPostgresBlock(t, ctx, database, firstPID, releaseDone)
			} else {
				workers.Go(release)
				firstPID := waitForPostgresBlock(t, ctx, database, int32(gate.Conn().PgConn().PID()), releaseDone)
				workers.Go(save)
				waitForPostgresBlock(t, ctx, database, firstPID, saveDone)
			}
			if err := gate.Commit(ctx); err != nil {
				t.Fatal(err)
			}
			// one operation commits, the other must fail with a real conflict/stale outcome (no deadlock, no silent corruption).
			saveErr := awaitIntegrationResult(t, ctx, saveDone)
			releaseErr := awaitIntegrationResult(t, ctx, releaseDone)
			if saveErr == nil && releaseErr == nil {
				t.Fatal("both DNS authority operations succeeded; expected serialized conflict")
			}
			if saveErr != nil && releaseErr != nil {
				t.Fatalf("both DNS authority operations failed: save=%v release=%v", saveErr, releaseErr)
			}
		})
	}
}

func TestIntegrationTransactionExpiredReplacementNoResurrection(t *testing.T) {
	f := newServicePublicationFixture(t)
	if _, err := f.database.pool.Exec(t.Context(), `UPDATE control.service_runs SET publisher_expires_at=$2 WHERE id=$1`, f.run.RunID, f.now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if count, err := f.database.ExpireServiceRuns(t.Context(), f.now.Add(2*time.Second)); err != nil || count != 1 {
		t.Fatalf("expiry count=%d err=%v", count, err)
	}
	if _, err := f.database.StartServiceRun(t.Context(), f.service.ID, f.run.RunID, f.run.RunNumber, f.publisher, f.now.Add(2*time.Second)); !errors.Is(err, ErrServiceAccess) && !errors.Is(err, ErrServiceConflict) {
		t.Fatalf("expired run was resurrected: %v", err)
	}
	var closed bool
	if err := f.database.pool.QueryRow(t.Context(), `SELECT state='closed' AND closed_at IS NOT NULL AND NOT assignments_open FROM control.service_runs WHERE id=$1`, f.run.RunID).Scan(&closed); err != nil || !closed {
		t.Fatalf("expired run authority not durably closed: closed=%t err=%v", closed, err)
	}
}

func TestIntegrationTransactionEphemeralServiceExpiry(t *testing.T) {
	d, now := newControlStateIntegrationDatabase(t, "ephemeral_expiry")
	session := newOIDCSession(t, d, now)
	member := session.Identity.Memberships[0]
	actor := session.Identity.Identity.ID
	for i := range 2 {
		service, err := d.CreateServiceAt(t.Context(), member.TeamID, actor, fmt.Sprintf("e%d", i), fmt.Sprintf("e%d", i), ServicePlacement{}, now, ServiceMetadata{}, &ProjectServiceConfiguration{Target: "http://127.0.0.1:3000"})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := d.pool.Exec(t.Context(), `UPDATE control.services SET ephemeral=true, expires_at=$2 WHERE id=$1`, service.ID, now.Add(time.Second)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := d.ExpireServiceRuns(t.Context(), now.Add(2*time.Second)); err != nil {
		t.Fatal(err)
	}
	var remaining int
	if err := d.pool.QueryRow(t.Context(), `SELECT count(*) FROM control.services WHERE ephemeral AND deleted_at IS NULL`).Scan(&remaining); err != nil {
		t.Fatal(err)
	}
	if remaining != 0 {
		t.Fatalf("expired ephemeral services remained: %d", remaining)
	}
}

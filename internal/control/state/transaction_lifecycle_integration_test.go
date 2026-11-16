package state

import (
	"context"
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

package state

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestIntegrationServiceHeartbeatPreservesAuthorityGuards(t *testing.T) {
	for _, boundary := range []string{"owner", "service"} {
		t.Run(boundary, func(t *testing.T) {
			f := newServicePublicationFixture(t)
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			gate, err := f.database.pool.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer rollbackTestTransaction(t, gate)
			if boundary == "owner" {
				_, err = gate.Exec(ctx, `SELECT id FROM control.teams WHERE id=$1 FOR UPDATE`, f.service.TeamID)
			} else {
				_, err = gate.Exec(ctx, `SELECT id FROM control.services WHERE id=$1 FOR UPDATE`, f.service.ID)
			}
			if err != nil {
				t.Fatal(err)
			}
			workers := newIntegrationWorkers(t, cancel)
			defer workers.stop()
			done := make(chan error, 1)
			workers.Go(func() {
				_, err := f.database.HeartbeatServiceRun(ctx, f.service.ID, f.run.RunID, f.run.Token,
					f.now.Add(time.Second), ServiceRunHealth{Healthy: true, StreamCapacity: 64})
				done <- err
			})
			waitForPostgresBlock(t, ctx, f.database, int32(gate.Conn().PgConn().PID()), done)
			if _, err := gate.Exec(ctx, `UPDATE control.services SET enabled=false WHERE id=$1`, f.service.ID); err != nil {
				t.Fatal(err)
			}
			if err := gate.Commit(ctx); err != nil {
				t.Fatal(err)
			}
			if err := awaitIntegrationResult(t, ctx, done); !errors.Is(err, ErrServiceAccess) {
				t.Fatal("heartbeat missed the committed authority change", err)
			}
			var expiration time.Time
			if err := f.database.pool.QueryRow(ctx, `SELECT publisher_expires_at FROM control.service_runs WHERE id=$1`,
				f.run.RunID).Scan(&expiration); err != nil || !expiration.Equal(f.run.ExpiresAt) {
				t.Fatal("denied heartbeat extended the run", expiration, err)
			}
		})
	}
}

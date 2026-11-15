package state

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"
)

func TestIntegrationVisitorDeviceMutationLocksAuditParentsBeforeIdentityAndDevice(t *testing.T) {
	for _, operation := range []string{"enroll", "replay", "revoke"} {
		t.Run(operation, func(t *testing.T) {
			f := newServicePublicationFixture(t)
			d, actor := f.database, f.actor(t)
			key, _, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			var device VisitorDevice
			if operation != "enroll" {
				device, err = d.EnrollVisitorDevice(t.Context(), actor, key, f.now)
				if err != nil {
					t.Fatal(err)
				}
			}
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			gate, err := d.pool.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer rollbackTestTransaction(t, gate)
			if _, err := gate.Exec(ctx, `SELECT id FROM control.services WHERE id=$1 FOR UPDATE`, f.service.ID); err != nil {
				t.Fatal(err)
			}
			workers := newIntegrationWorkers(t, cancel)
			defer workers.stop()
			done := make(chan error, 1)
			workers.Go(func() {
				if operation == "revoke" {
					done <- d.RevokeVisitorDevice(ctx, actor, device.ID, f.now)
				} else {
					_, err := d.EnrollVisitorDevice(ctx, actor, key, f.now)
					done <- err
				}
			})
			waitForPostgresBlock(t, ctx, d, int32(gate.Conn().PgConn().PID()), done)
			var auditClockFree bool
			if err := gate.QueryRow(ctx, `SELECT pg_try_advisory_xact_lock(hashtextextended('tnl:service-audit:'||$1,0))`,
				f.service.TeamID).Scan(&auditClockFree); err != nil || !auditClockFree {
				t.Fatal("device mutation held the audit clock ahead of its service", auditClockFree, err)
			}
			// admission already owns this service before checking its person
			// or device. a waiting mutation must own neither child lock.
			if _, err := gate.Exec(ctx, `SELECT id FROM control.identities WHERE id=$1 FOR UPDATE NOWAIT`, actor); err != nil {
				t.Fatal("device mutation held the identity ahead of its audit service", err)
			}
			if device.ID != "" {
				if _, err := gate.Exec(ctx, `SELECT id FROM control.visitor_devices WHERE id=$1 FOR UPDATE NOWAIT`, device.ID); err != nil {
					t.Fatal("device mutation held the device ahead of its audit service", err)
				}
			}
			if err := gate.Commit(ctx); err != nil {
				t.Fatal(err)
			}
			if err := awaitIntegrationResult(t, ctx, done); err != nil {
				t.Fatal(err)
			}
			var events int
			eventType := "device.enroll"
			if operation == "revoke" {
				eventType = "device.revoke"
			}
			if err := d.pool.QueryRow(ctx, `SELECT count(*) FROM control.service_audit_events WHERE service_id=$1 AND event_type=$2`,
				f.service.ID, eventType).Scan(&events); err != nil || events != 1 {
				t.Fatal("device mutation lost its transactional, retry-stable audit", events, err)
			}
		})
	}
}

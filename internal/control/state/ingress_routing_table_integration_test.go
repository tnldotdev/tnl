package state

import (
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

func TestIntegrationRoutingSnapshotSelectsLatestBeforeFiltering(t *testing.T) {
	// admission reads current service runs and slots instead of replaying a
	// routing projection. an older ready row must never revive unavailable work.
	for _, name := range []string{
		"ready", "closed", "publisher expiry boundary", "certificate expiry boundary",
		"relay expiry boundary", "healthy surviving relay", "first readiness needs both relays",
		"unhealthy", "replacement not ready", "replacement ready", "another hostname",
	} {
		t.Run(name, func(t *testing.T) {
			f := newServicePublicationFixture(t)
			installPrivateTestCertificate(t, f.database, f.prepared, f.run, f.now)
			if name == "first readiness needs both relays" {
				f.readyConnection(t, 0, f.now)
			} else {
				f.readyConnections(t, f.now)
			}
			ready, err := f.database.HeartbeatServiceRun(t.Context(), f.service.ID, f.run.RunID, f.run.Token,
				f.now, ServiceRunHealth{Healthy: true, StreamCapacity: 64})
			if err != nil {
				t.Fatal(err)
			}
			want := true
			hostname := f.prepared.Hostname
			at := f.now
			switch name {
			case "closed":
				if err := f.database.CloseServiceRun(t.Context(), f.service.ID, f.run.RunID, f.run.Token, f.now); err != nil {
					t.Fatal(err)
				}
				want = false
			case "publisher expiry boundary":
				at, want = ready.ExpiresAt, false
			case "certificate expiry boundary":
				if _, err := f.database.pool.Exec(t.Context(), `UPDATE control.service_runs SET certificate_expires_at=$2 WHERE id=$1`, f.run.RunID, at); err != nil {
					t.Fatal(err)
				}
				want = false
			case "relay expiry boundary":
				at = at.Add(time.Second)
				if _, err := f.database.pool.Exec(t.Context(), `UPDATE control.relay_leases SET lease_expires_at=$1`, at); err != nil {
					t.Fatal(err)
				}
				want = false
			case "healthy surviving relay":
				slot := f.run.Connections[0]
				if _, err := f.database.DisconnectServicePublisherConnection(t.Context(), slot.PublisherConnectionID,
					f.run.RunID, f.run.RunNumber, slot.Revision, f.leases[slot.RelayServiceID].RelayLeaseIdentity, at, true); err != nil {
					t.Fatal(err)
				}
			case "first readiness needs both relays":
				if ready.State != "starting" {
					t.Fatal("one initial connection made the service ready", ready)
				}
				want = false
			case "unhealthy":
				if _, err := f.database.HeartbeatServiceRun(t.Context(), f.service.ID, f.run.RunID, f.run.Token,
					at, ServiceRunHealth{Healthy: false, StreamCapacity: 64}); err != nil {
					t.Fatal(err)
				}
				want = false
			case "replacement not ready", "replacement ready":
				previous := f.run
				if err := f.database.CloseServiceRun(t.Context(), f.service.ID, previous.RunID, previous.Token, at); err != nil {
					t.Fatal(err)
				}
				f.start(t, "replacement", at.Add(time.Second))
				at = at.Add(time.Second)
				if f.run.RunID == previous.RunID || f.run.RunNumber <= previous.RunNumber {
					t.Fatal("replacement reused the old run tuple", f.run)
				}
				want = name == "replacement ready"
				if want {
					installPrivateTestCertificate(t, f.database, f.prepared, f.run, at)
					f.readyConnections(t, at)
					if _, err := f.database.HeartbeatServiceRun(t.Context(), f.service.ID, f.run.RunID, f.run.Token,
						at, ServiceRunHealth{Healthy: true, StreamCapacity: 64}); err != nil {
						t.Fatal(err)
					}
				}
			case "another hostname":
				hostname, want = "other.example.test", false
			}
			tx, err := f.database.pool.Begin(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback(t.Context())
			id, number, until, err := selectRoutableServiceRun(t.Context(), tx, f.service.ID, hostname, at)
			if !want {
				if !errors.Is(err, pgx.ErrNoRows) {
					t.Fatalf("unavailable service selected historical readiness: run=%s number=%d err=%v", id, number, err)
				}
				return
			}
			if err != nil || id != f.run.RunID || number != f.run.RunNumber || !until.After(at) {
				t.Fatalf("selection lost the current live tuple: run=%s number=%d until=%s err=%v", id, number, until, err)
			}
		})
	}
}

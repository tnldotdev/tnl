package state

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
)

func TestIntegrationServiceRestoredExpiredReplacementQueuesBehindHeartbeatPlacement(t *testing.T) {
	f := newServicePublicationFixture(t)
	prepareServingPublisher(t, f)
	d, now := f.database, f.now
	actor := f.actor(t)
	team, err := d.CreateTeam(t.Context(), CreateTeamRequest{
		IdentityID: actor, DisplayName: "replacement-team", MemberSlug: "owner",
		IdempotencyKey: "replacement-team", RequestDigest: sha256.Sum256([]byte("replacement-team")),
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	service, err := d.CreateServiceAt(t.Context(), team.ID, actor, "replacement", "replacement", ServicePlacement{}, now,
		ServiceMetadata{Protocol: "http"}, &ProjectServiceConfiguration{Target: "localhost:3000"})
	if err != nil {
		t.Fatal(err)
	}
	enrollment := publisherEnrollment(t, d, serviceTestAuthority{TeamID: team.ID, ActingIdentityID: actor},
		PublisherScope{TeamID: team.ID, Kind: "service", ServiceID: service.ID}, now)
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	publisher, err := d.RedeemPublisherEnrollment(t.Context(), enrollment.Key, public, now)
	if err != nil {
		t.Fatal(err)
	}
	replacement := servicePublicationFixture{database: d, now: now, service: service, publisher: publisher, leases: f.leases}
	replacement.start(t, "original", now)
	prepareServingPublisher(t, replacement)
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	if _, err := d.pool.Exec(ctx, `UPDATE control.service_connection_slots SET state='closed'
		WHERE service_run_id=$1 AND connection_slot=0`, f.run.RunID); err != nil {
		t.Fatal(err)
	}
	if _, err := d.pool.Exec(ctx, `UPDATE control.service_runs SET publisher_expires_at=$2 WHERE id=$1`,
		replacement.run.RunID, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	assertAssignmentTotals(t, d.pool, 3)
	gate, err := d.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer rollbackTestTransaction(t, gate)
	// placement takes the assignment-total guard before these relay rows.
	// holding a relay row leaves that guard with the blocked heartbeat.
	if _, err := gate.Exec(ctx, `SELECT relay_service_id FROM control.relay_services ORDER BY relay_service_id FOR UPDATE`); err != nil {
		t.Fatal(err)
	}
	workers := newIntegrationWorkers(t, cancel)
	defer workers.stop()
	var heartbeat, replaced ServiceRunState
	heartbeatDone, replacementDone := make(chan error, 1), make(chan error, 1)
	at := now.Add(2 * time.Second)
	workers.Go(func() {
		var err error
		heartbeat, err = d.HeartbeatServiceRun(ctx, f.service.ID, f.run.RunID, f.run.Token, at,
			ServiceRunHealth{Healthy: true, StreamCapacity: 64})
		heartbeatDone <- err
	})
	heartbeatPID := waitForPostgresBlock(t, ctx, d, int32(gate.Conn().PgConn().PID()), heartbeatDone)
	workers.Go(func() {
		prepared, err := d.PrepareServiceRun(ctx, replacement.service.ID, replacement.publisher, "replacement", at,
			ServiceRunRequest{Metadata: replacement.service.ServiceMetadata})
		if err == nil {
			replaced, err = d.StartServiceRun(ctx, replacement.service.ID, prepared.RunID, prepared.RunNumber, replacement.publisher, at)
		}
		replacementDone <- err
	})
	// different teams prevent an owner guard from hiding this placement wait.
	waitForPostgresBlock(t, ctx, d, heartbeatPID, replacementDone)
	if err := gate.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err := awaitIntegrationResult(t, ctx, heartbeatDone); err != nil {
		t.Fatal(err)
	}
	if len(heartbeat.Connections) != 2 || heartbeat.Connections[0].State != "assigned" ||
		heartbeat.Connections[0].Revision != 2 || heartbeat.Connections[1].State != "ready" {
		t.Fatal("heartbeat did not replace only its closed connection", heartbeat.Connections)
	}
	if err := awaitIntegrationResult(t, ctx, replacementDone); err != nil {
		t.Fatal(err)
	}
	if replaced.RunID == replacement.run.RunID || replaced.RunNumber != replacement.run.RunNumber+1 ||
		len(replaced.Connections) != 2 {
		t.Fatal("expired replacement did not receive its own next run and two slots")
	}
	old, err := controlstatedb.New(d.pool).LockServiceRun(ctx,
		controlstatedb.LockServiceRunParams{ID: replacement.run.RunID, ServiceID: replacement.service.ID})
	if err != nil || !old.ClosedAt.Valid || old.State != "closed" || !old.AssignmentsOpen.Valid || old.AssignmentsOpen.Bool {
		t.Fatal("expired replacement retained its predecessor's assignment authority", err)
	}
	assertAssignmentTotals(t, d.pool, 4)
}

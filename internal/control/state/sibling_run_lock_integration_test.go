package state

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/observability/serviceaudit"
)

func TestIntegrationSiblingRunOperationsDuringHeartbeat(t *testing.T) {
	f, _, _ := newRunAliasServiceFixture(t)
	d := f.database
	a, b := f.publish(t, f.service), f.publish(t, f.service)
	enrollment := publisherEnrollment(t, d, serviceTestAuthority{TeamID: f.project.TeamID, ActingIdentityID: f.project.ActorID},
		PublisherScope{TeamID: f.project.TeamID, Kind: "service", ServiceID: f.service.ID}, f.now)
	signing, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	publisher, err := d.RedeemPublisherEnrollment(t.Context(), enrollment.Key, signing, f.now)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	device, err := d.EnrollVisitorDevice(ctx, f.project.ActorID, public, f.now)
	if err != nil {
		t.Fatal(err)
	}
	var issuance string
	if err := d.pool.QueryRow(ctx, `SELECT certificate_issuance_id FROM control.service_runs WHERE id=$1`, b.RunID).Scan(&issuance); err != nil {
		t.Fatal(err)
	}
	gate, err := d.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer rollbackTestTransaction(t, gate)
	if _, err := gate.Exec(ctx, `SELECT id FROM control.service_runs WHERE id=$1 FOR UPDATE`, a.RunID); err != nil {
		t.Fatal(err)
	}
	beat := func(r ServiceRunState) (ServiceRunState, error) {
		return d.HeartbeatServiceRun(ctx, r.ServiceID, r.RunID, r.Token, f.now, ServiceRunHealth{Healthy: true, StreamCapacity: 64})
	}
	workers := newIntegrationWorkers(t, cancel)
	defer workers.stop()
	heartbeat := make(chan error, 1)
	workers.Go(func() { _, err := beat(a); heartbeat <- err })
	waitForPostgresBlock(t, ctx, d, int32(gate.Conn().PgConn().PID()), heartbeat)

	if saved, err := d.GetServiceForPublisher(ctx, f.service.ID, publisher, f.now); err != nil || saved.ID != f.service.ID {
		t.Fatal("read service for a newly enrolled publisher during sibling heartbeat", err)
	}
	if page, err := d.ListConnectorPeerPairs(ctx, b.ServiceID, b.RunID, "", b.Token, f.now); err != nil || len(page.Items) != 0 {
		t.Fatal("sibling publisher could not reconcile its empty connector list", err)
	}
	event := serviceaudit.Observation{
		EventID: serviceaudit.NewID(), ServiceKind: "service", ServiceID: b.ServiceID,
		RunID: b.RunID, RunNumber: b.RunNumber, VisitorConnectionID: mustOpaqueID(t, opaqueid.VisitorConnectionPrefix),
		EventType: "http.decision", Outcome: "allowed", SourceIP: "192.0.2.10", OccurredAt: f.now,
	}
	if result, err := d.IngestServiceRunObservations(ctx, b.ServiceID, b.RunID, b.Token, b.RunNumber, serviceaudit.Batch{Events: []serviceaudit.Observation{event}}, f.now); err != nil || result.Accepted != 1 {
		t.Fatal("sibling publisher audit", result, err)
	}
	if _, err := d.GetServiceCertificateIssuance(ctx, b.ServiceID, b.RunID, b.Token, issuance, f.now); err != nil {
		t.Fatal("sibling certificate read", err)
	}
	selection, err := d.SelectServiceRun(ctx, b.ServiceID, f.project.ActorID, device.ID, f.now)
	if err != nil || selection.PairReady == nil {
		t.Fatal("connector run and relay selection", err)
	}
	old := b.Connections[0]
	lease := f.leases[old.RelayServiceID].RelayLeaseIdentity
	if _, err := d.DisconnectServicePublisherConnection(ctx, old.PublisherConnectionID, b.RunID, b.RunNumber, old.Revision, lease, f.now, false); err != nil {
		t.Fatal("sibling disconnect", err)
	}
	repaired, err := beat(b)
	if err != nil || len(repaired.Connections) != 2 || repaired.Connections[0].Revision <= old.Revision {
		t.Fatal("sibling replacement", err)
	}
	slot := repaired.Connections[0]
	nextLease := f.leases[slot.RelayServiceID].RelayLeaseIdentity
	if _, err := d.ClaimServicePublisherConnection(ctx, slot.PublisherConnectionID, b.ServiceID, b.RunID, b.RunNumber, slot.Revision,
		slot.Credential, netip.MustParseAddr("192.0.2.10"), nextLease, f.now); err != nil {
		t.Fatal("sibling claim", err)
	}
	if _, err := d.ReadyServicePublisherConnection(ctx, slot.PublisherConnectionID, b.RunID, b.RunNumber, slot.Revision, nextLease, f.now); err != nil {
		t.Fatal("sibling readiness", err)
	}
	if _, err := d.DisconnectServicePublisherConnection(ctx, old.PublisherConnectionID, b.RunID, b.RunNumber, old.Revision, lease, f.now, false); !errors.Is(err, ErrServiceAccess) {
		t.Fatal("stale disconnect", err)
	}
	if err := gate.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err := awaitIntegrationResult(t, ctx, heartbeat); err != nil {
		t.Fatal(err)
	}
}

func TestIntegrationQueuedRunClosePrecedesNewSiblingHeartbeat(t *testing.T) {
	f, _, _ := newRunAliasServiceFixture(t)
	a, b := f.publish(t, f.service), f.publish(t, f.service)
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	gate, err := f.database.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer rollbackTestTransaction(t, gate)
	if _, err := gate.Exec(ctx, `SELECT id FROM control.service_runs WHERE id=$1 FOR UPDATE`, b.RunID); err != nil {
		t.Fatal(err)
	}
	workers := newIntegrationWorkers(t, cancel)
	defer workers.stop()
	renew := func(r ServiceRunState) chan error {
		done := make(chan error, 1)
		workers.Go(func() {
			_, err := f.database.HeartbeatServiceRun(ctx, r.ServiceID, r.RunID, r.Token, f.now, ServiceRunHealth{Healthy: true, StreamCapacity: 64})
			done <- err
		})
		return done
	}
	reader := renew(b)
	readerPID := waitForPostgresBlock(t, ctx, f.database, int32(gate.Conn().PgConn().PID()), reader)
	closeA := make(chan error, 1)
	workers.Go(func() { closeA <- f.database.CloseServiceRun(ctx, a.ServiceID, a.RunID, a.Token, f.now) })
	writerPID := waitForPostgresBlock(t, ctx, f.database, readerPID, closeA)
	// this heartbeat must queue behind the already waiting close, even though
	// the active reader is for b and its service row lock is compatible.
	late := renew(a)
	waitForPostgresBlock(t, ctx, f.database, writerPID, late)
	if err := gate.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	for _, done := range []chan error{reader, closeA} {
		if err := awaitIntegrationResult(t, ctx, done); err != nil {
			t.Fatal(err)
		}
	}
	if err := awaitIntegrationResult(t, ctx, late); !errors.Is(err, ErrServiceAccess) {
		t.Fatal("late heartbeat did not observe run closure", err)
	}
}

func TestIntegrationConnectorPeerListQueuesBehindServiceEdit(t *testing.T) {
	f, _, _ := newRunAliasServiceFixture(t)
	run := f.publish(t, f.service)
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	edit, err := f.database.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer rollbackTestTransaction(t, edit)
	if err := queueRunWriter(ctx, edit, f.service.ID); err != nil {
		t.Fatal(err)
	}
	workers := newIntegrationWorkers(t, cancel)
	defer workers.stop()
	listed := make(chan error, 1)
	workers.Go(func() {
		_, err := f.database.ListConnectorPeerPairs(ctx, f.service.ID, run.RunID, "", run.Token, f.now)
		listed <- err
	})
	// the writer has not touched the service row yet.
	waitForPostgresBlock(t, ctx, f.database, int32(edit.Conn().PgConn().PID()), listed)
	if _, err := edit.Exec(ctx, `UPDATE control.services SET enabled=false WHERE id=$1`, f.service.ID); err != nil {
		t.Fatal(err)
	}
	if err := edit.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err := awaitIntegrationResult(t, ctx, listed); !errors.Is(err, ErrServiceAccess) {
		t.Fatal("candidate list missed service disablement", err)
	}
}

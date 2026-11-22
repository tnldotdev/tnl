package state

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net/netip"
	"testing"
	"time"
)

func TestIntegrationSiblingRunOperationsDuringHeartbeat(t *testing.T) {
	f, _, _ := newRunAliasServiceFixture(t)
	d := f.database
	a, b := f.publish(t, f.service), f.publish(t, f.service)
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

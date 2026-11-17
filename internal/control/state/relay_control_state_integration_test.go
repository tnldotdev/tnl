package state

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/security/credentials"
)

func TestIntegrationRelayControlState(t *testing.T) {
	database, now := newControlStateIntegrationDatabase(t, "relay_control_state")
	registration := relayLifecycleRegistration("relay-a")
	lease, err := database.RegisterRelay(t.Context(), registration, now, 30*time.Second)
	if err != nil || lease.RelayLeaseRevision != 1 || lease.RelayID != registration.RelayID || !lease.LeaseExpiresAt.Equal(now.Add(30*time.Second)) {
		t.Fatalf("initial lease = %#v, %v", lease, err)
	}
	repeated, err := database.RegisterRelay(t.Context(), registration, now.Add(time.Second), 30*time.Second)
	if err != nil || repeated.RelayLeaseRevision != lease.RelayLeaseRevision || !repeated.RegisteredAt.Equal(now) {
		t.Fatalf("repeated lease = %#v, %v", repeated, err)
	}
	conflict := registration
	conflict.RelayRunID = "conflicting-run"
	if _, err := database.RegisterRelay(t.Context(), conflict, now.Add(2*time.Second), 30*time.Second); !errors.Is(err, ErrRelayRegistrationConflict) {
		t.Fatalf("live run conflict: %v", err)
	}
	renewed, err := database.RenewRelay(t.Context(), RelayRenewal{RelayLeaseIdentity: lease.RelayLeaseIdentity, ReportedConnections: 1, ReportedStreams: 2}, now.Add(3*time.Second), 30*time.Second)
	if err != nil || renewed.ReportedConnections != 1 || renewed.ReportedStreams != 2 {
		t.Fatalf("renewed lease = %#v, %v", renewed, err)
	}
	stale := lease.RelayLeaseIdentity
	stale.RelayLeaseRevision++
	if _, err := database.RenewRelay(t.Context(), RelayRenewal{RelayLeaseIdentity: stale}, now.Add(4*time.Second), 30*time.Second); !errors.Is(err, ErrRelayLeaseStale) {
		t.Fatalf("stale renewal: %v", err)
	}
	replacement, err := database.RegisterRelay(t.Context(), conflict, renewed.LeaseExpiresAt, 30*time.Second)
	if err != nil || replacement.RelayLeaseRevision != renewed.RelayLeaseRevision+1 {
		t.Fatalf("replacement lease = %#v, %v", replacement, err)
	}
}

func TestIntegrationPublisherConnectionClaims(t *testing.T) {
	f := newServicePublicationFixture(t)
	plan := f.run.Connections[0]
	lease := f.leases[plan.RelayServiceID].RelayLeaseIdentity
	badCredential, _, err := credentials.NewPublisherConnectionCredential()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.database.ClaimServicePublisherConnection(t.Context(), plan.PublisherConnectionID, f.service.ID, f.run.RunID, f.run.RunNumber, plan.Revision, badCredential.String(), netip.MustParseAddr("127.0.0.1"), lease, f.now); !errors.Is(err, ErrServiceAccess) {
		t.Fatalf("bad credential: %v", err)
	}
	registration := relayLifecycleRegistration(plan.RelayServiceID)
	registration.RelayID, registration.RelayRunID = "claim-contender", "claim-contender-run"
	contender, err := f.database.RegisterRelay(t.Context(), registration, f.now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	workers := newIntegrationWorkers(t, cancel)
	type result struct {
		lease RelayLeaseIdentity
		err   error
	}
	results := make(chan result, 2)
	for _, candidate := range []RelayLeaseIdentity{lease, contender.RelayLeaseIdentity} {
		workers.Go(func() {
			_, err := f.database.ClaimServicePublisherConnection(ctx, plan.PublisherConnectionID, f.service.ID, f.run.RunID, f.run.RunNumber, plan.Revision, plan.Credential, netip.MustParseAddr("127.0.0.1"), candidate, f.now)
			results <- result{lease: candidate, err: err}
		})
	}
	var winners int
	var winner RelayLeaseIdentity
	for range 2 {
		r := awaitIntegrationResult(t, ctx, results)
		switch {
		case r.err == nil:
			winners++
			winner = r.lease
		case errors.Is(r.err, ErrServiceAccess):
		default:
			t.Fatalf("claim error: %v", r.err)
		}
	}
	if winners != 1 {
		t.Fatalf("expected exactly one winning claim, got %d", winners)
	}
	assertState := func(state string) {
		t.Helper()
		var matches bool
		if err := f.database.pool.QueryRow(ctx, `SELECT state=$2 AND
			CASE WHEN $2='closed' THEN relay_id IS NULL ELSE relay_id=$3 AND relay_run_id=$4 AND relay_lease_revision=$5 END
			FROM control.service_connection_slots WHERE publisher_connection_id=$1`, plan.PublisherConnectionID, state,
			winner.RelayID, winner.RelayRunID, int64(winner.RelayLeaseRevision)).Scan(&matches); err != nil || !matches {
			t.Fatal("claim lost exact state or relay ownership", state, err)
		}
	}
	assertState("connected")
	if _, err := f.database.ClaimServicePublisherConnection(ctx, plan.PublisherConnectionID, f.service.ID, f.run.RunID, f.run.RunNumber, plan.Revision, plan.Credential, netip.MustParseAddr("127.0.0.1"), winner, f.now); err != nil {
		t.Fatalf("claim replay: %v", err)
	}
	ready, err := f.database.ReadyServicePublisherConnection(ctx, plan.PublisherConnectionID, f.run.RunID, f.run.RunNumber, plan.Revision, winner, f.now)
	if err != nil || ready.ConnectionID != plan.PublisherConnectionID || ready.Revision != plan.Revision {
		t.Fatalf("ready connection = %#v, %v", ready, err)
	}
	assertState("ready")
	if _, err := f.database.ClaimServicePublisherConnection(ctx, plan.PublisherConnectionID, f.service.ID, f.run.RunID, f.run.RunNumber, plan.Revision, plan.Credential, netip.MustParseAddr("127.0.0.1"), winner, f.now); !errors.Is(err, ErrServiceAccess) {
		t.Fatalf("another handshake reused an established ready connection: %v", err)
	}

	other := f.run.Connections[1]
	otherLease := f.leases[other.RelayServiceID].RelayLeaseIdentity
	if _, err := f.database.ClaimServicePublisherConnection(ctx, other.PublisherConnectionID, f.service.ID, f.run.RunID, f.run.RunNumber, other.Revision, other.Credential, netip.MustParseAddr("127.0.0.1"), winner, f.now); !errors.Is(err, ErrServiceAccess) {
		t.Fatal("wrong relay service claim succeeded")
	}
	draining, err := f.database.BeginRelayDrain(ctx, otherLease, f.now, f.now.Add(time.Minute))
	if err != nil || !draining.Draining {
		t.Fatalf("draining lease = %#v, %v", draining, err)
	}
	if _, err := f.database.ClaimServicePublisherConnection(ctx, other.PublisherConnectionID, f.service.ID, f.run.RunID, f.run.RunNumber, other.Revision, other.Credential, netip.MustParseAddr("127.0.0.1"), otherLease, f.now); !errors.Is(err, ErrServiceAccess) {
		t.Fatalf("draining claim: %v", err)
	}
	closed, err := f.database.DisconnectServicePublisherConnection(ctx, plan.PublisherConnectionID, f.run.RunID, f.run.RunNumber, plan.Revision, winner, f.now.Add(time.Second), true)
	if err != nil {
		t.Fatalf("disconnect: %v", err)
	}
	if closed.ConnectionID != plan.PublisherConnectionID || closed.Revision != plan.Revision {
		t.Fatal("disconnect changed connection identity", closed)
	}
	assertState("closed")
	if _, err := f.database.DisconnectServicePublisherConnection(ctx, plan.PublisherConnectionID, f.run.RunID, f.run.RunNumber, plan.Revision, winner, f.now.Add(2*time.Second), true); !errors.Is(err, ErrServiceAccess) {
		t.Fatalf("disconnect replay: %v", err)
	}
}

func TestIntegrationRelayDrainRejectsExpiredRun(t *testing.T) {
	database, now := newControlStateIntegrationDatabase(t, "relay_drain_expiry")
	registration := RelayRegistration{
		RelayServiceID: "relay_service_a", RelayID: "relay_a", RelayRunID: "run_a", ProtocolVersion: 1,
		RelayAddress: "relay-a.example:443", TLSServerName: "relay-a.example",
		InternalRelayAddress: "relay-a.internal:9443", ConnectionCapacity: 10, StreamCapacity: 20,
	}
	lease, err := database.RegisterRelay(t.Context(), registration, now, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	deadline := now.Add(30 * time.Second)
	if _, err := database.BeginRelayDrain(t.Context(), lease.RelayLeaseIdentity, now.Add(time.Second), deadline); err != nil {
		t.Fatal(err)
	}
	for _, at := range []time.Time{deadline, deadline.Add(time.Second)} {
		if _, err := database.RenewRelay(t.Context(), RelayRenewal{
			RelayLeaseIdentity: lease.RelayLeaseIdentity,
		}, at, time.Minute); !errors.Is(err, ErrRelayLeaseStale) {
			t.Fatalf("renew drained run at %s: %v", at, err)
		}
		if _, err := database.RegisterRelay(t.Context(), registration, at, time.Minute); !errors.Is(err, ErrRelayRegistrationConflict) {
			t.Fatalf("re-register drained run at %s: %v", at, err)
		}
	}
	registration.RelayRunID = "run_restarted"
	restarted, err := database.RegisterRelay(t.Context(), registration, deadline.Add(2*time.Second), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if restarted.Draining || restarted.DrainDeadline != nil || restarted.RelayRunID != registration.RelayRunID ||
		restarted.RelayLeaseRevision != lease.RelayLeaseRevision+1 {
		t.Fatalf("restarted relay lease = %#v", restarted)
	}
	// liveness expiry permits the same undrained process to recover within its
	// serving authority, without changing its identity or lease revision.
	if !restarted.ServingUntil.After(restarted.LeaseExpiresAt) {
		t.Fatal("fixture did not separate relay liveness from serving authority")
	}
	recovered, err := database.RegisterRelay(t.Context(), registration, restarted.LeaseExpiresAt, time.Minute)
	if err != nil || recovered.Draining || recovered.RelayLeaseIdentity != restarted.RelayLeaseIdentity ||
		!recovered.RegisteredAt.Equal(restarted.RegisteredAt) ||
		!recovered.ServingUntil.Equal(restarted.LeaseExpiresAt.Add(database.servingTolerance())) {
		t.Fatalf("recovered relay lease = %#v, %v", recovered, err)
	}
	// actual serving expiry cannot recover that process. a new process must
	// acquire the next revision instead of reviving the expired authority.
	if _, err := database.RenewRelay(t.Context(), RelayRenewal{RelayLeaseIdentity: recovered.RelayLeaseIdentity},
		recovered.ServingUntil, time.Minute); !errors.Is(err, ErrRelayLeaseStale) {
		t.Fatal("expired relay serving authority accepted a renewal", err)
	}
	if _, err := database.RegisterRelay(t.Context(), registration, recovered.ServingUntil, time.Minute); !errors.Is(err, ErrRelayRegistrationConflict) {
		t.Fatal("expired relay serving authority accepted the same process", err)
	}
	registration.RelayRunID = "run_after_serving_expiry"
	replacement, err := database.RegisterRelay(t.Context(), registration, recovered.ServingUntil, time.Minute)
	if err != nil || replacement.Draining || replacement.RelayRunID != registration.RelayRunID ||
		replacement.RelayLeaseRevision != recovered.RelayLeaseRevision+1 {
		t.Fatal("replacement did not fence expired relay authority", replacement, err)
	}
}

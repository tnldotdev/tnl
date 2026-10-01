package controlstate

import (
	"context"
	"crypto/sha256"
	"errors"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/credentials"
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
	f := newPublishRunFixture(t)
	database, now := f.database, f.now
	plan := f.setup.PublisherConnections[0]
	digest, err := credentials.ParsePublisherConnectionCredential(plan.PublisherConnectionCredential)
	if err != nil {
		t.Fatal(err)
	}
	base := PublisherConnectionClaimRequest{ConnectionAssignmentIdentity: plan.ConnectionAssignmentIdentity,
		RelayLeaseIdentity: f.leases[plan.RelayServiceID].RelayLeaseIdentity, CredentialDigest: [32]byte(digest)}
	bad := base
	bad.ClaimID, bad.CredentialDigest = "bad", sha256.Sum256([]byte("wrong"))
	if _, err := database.ClaimPublisherConnection(t.Context(), bad, now); !errors.Is(err, ErrPublisherConnectionCredential) {
		t.Fatalf("bad credential: %v", err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	workers := newIntegrationWorkers(t, cancel)
	type result struct {
		claim      PublisherConnectionClaimRequest
		connection ClaimedPublisherConnection
		err        error
	}
	results := make(chan result, 2)
	for _, transport := range []string{"quic", "tcp"} {
		workers.Go(func() {
			claim := base
			claim.ClaimID = transport
			connection, err := database.ClaimPublisherConnection(ctx, claim, now)
			results <- result{claim, connection, err}
		})
	}
	var winner PublisherConnectionClaimRequest
	for range 2 {
		result := awaitIntegrationResult(t, ctx, results)
		switch {
		case result.err == nil:
			if winner.ClaimID != "" {
				t.Fatal("both transport candidates claimed one connection")
			}
			winner = result.claim
			if result.connection.State != "connected" || result.connection.ClaimID != winner.ClaimID {
				t.Fatalf("claimed connection = %#v", result.connection)
			}
		case !errors.Is(result.err, ErrPublisherConnectionAlreadyClaimed):
			t.Fatalf("losing claim: %v", result.err)
		}
	}
	if winner.ClaimID == "" {
		t.Fatal("neither transport candidate claimed the connection")
	}
	if _, err := database.ClaimPublisherConnection(ctx, winner, now); err != nil {
		t.Fatalf("claim replay: %v", err)
	}
	ready, err := database.MarkPublisherConnectionReady(ctx, winner, now)
	if err != nil || ready.State != "ready" || ready.ReadyAt == nil {
		t.Fatalf("ready connection = %#v, %v", ready, err)
	}
	if replay, err := database.ClaimPublisherConnection(ctx, winner, now); err != nil || replay.State != "ready" {
		t.Fatalf("ready claim replay = %#v, %v", replay, err)
	}
	other := f.setup.PublisherConnections[1]
	otherDigest, err := credentials.ParsePublisherConnectionCredential(other.PublisherConnectionCredential)
	if err != nil {
		t.Fatal(err)
	}
	wrongService := winner
	wrongService.ConnectionAssignmentIdentity, wrongService.CredentialDigest, wrongService.ClaimID = other.ConnectionAssignmentIdentity, [32]byte(otherDigest), "wrong-service"
	if _, err := database.ClaimPublisherConnection(ctx, wrongService, now); !errors.Is(err, ErrPublisherConnectionRelayService) {
		t.Fatalf("wrong service claim: %v", err)
	}
	otherLease := f.leases[other.RelayServiceID]
	draining, err := database.BeginRelayDrain(ctx, otherLease.RelayLeaseIdentity, now, now.Add(time.Minute))
	if err != nil || !draining.Draining {
		t.Fatalf("draining lease = %#v, %v", draining, err)
	}
	wrongService.RelayLeaseIdentity = otherLease.RelayLeaseIdentity
	if _, err := database.ClaimPublisherConnection(ctx, wrongService, now); !errors.Is(err, ErrRelayDraining) {
		t.Fatalf("draining claim: %v", err)
	}
	closed, err := database.DisconnectPublisherConnection(ctx, winner, now.Add(time.Second), true)
	if err != nil || closed.State != "closed" {
		t.Fatalf("disconnected connection = %#v, %v", closed, err)
	}
	if _, err := database.DisconnectPublisherConnection(ctx, winner, now.Add(2*time.Second), true); !errors.Is(err, ErrConnectionAssignmentStale) {
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
	// ordinary lease expiry still permits recovery by a process run that has not drained.
	recovered, err := database.RegisterRelay(t.Context(), registration, restarted.LeaseExpiresAt, time.Minute)
	if err != nil || recovered.Draining || recovered.RelayLeaseRevision != restarted.RelayLeaseRevision+1 {
		t.Fatalf("recovered relay lease = %#v, %v", recovered, err)
	}
}

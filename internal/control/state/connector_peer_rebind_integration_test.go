package state

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

func connectorRebindRequest(t *testing.T, f connectorPairFixture, pair ConnectorPeerPair, phase string, at time.Time) ConnectorPeerPairRebindRequest {
	t.Helper()
	proof := tunnelv1.ConnectorPeerPairRebindProof{Phase: phase, ServiceID: pair.ServiceID, PairID: pair.ID, IdempotencyKey: f.request.IdempotencyKey,
		ExpectedGeneration: pair.DeliveryGeneration, RequestedAt: at, ServiceRunID: pair.ServiceRunID, RunNumber: pair.RunNumber, PublisherIdentityID: pair.PublisherIdentityID,
		TrustRevision: pair.TrustRevision, Subject: pair.Subject}
	if phase != "inspect" {
		proof.OperationID, _ = opaqueid.New(opaqueid.IdempotencyPrefix)
	}
	if phase == "prepare" {
		relays := f.request.proof().ExpectedRelays
		proof.ExpectedRelays = append([]tunnelv1.ConnectorPeerPairRelay{}, relays[:]...)
	}
	return signConnectorRebind(t, f, proof)
}

func signConnectorRebind(t *testing.T, f connectorPairFixture, proof tunnelv1.ConnectorPeerPairRebindProof) ConnectorPeerPairRebindRequest {
	t.Helper()
	message, err := proof.Message()
	if err != nil {
		t.Fatal(err)
	}
	return ConnectorPeerPairRebindRequest{Proof: proof, Source: f.request.Source, Signature: ed25519.Sign(f.key, message)}
}

func connectorRebindProofs(t *testing.T, pair ConnectorPeerPair, role uint8) []tunnelv1.ConnectorPeerPairPathProof {
	t.Helper()
	secret, err := base64.RawURLEncoding.Strict().DecodeString(pair.SessionKey)
	if err != nil || len(secret) != 32 {
		t.Fatal("session key", err)
	}
	defer clear(secret)
	var key [32]byte
	copy(key[:], secret)
	defer clear(key[:])
	proofs := make([]tunnelv1.ConnectorPeerPairPathProof, 2)
	for slot := range 2 {
		nonce := make([]byte, 16)
		if _, err := rand.Read(nonce); err != nil {
			t.Fatal(err)
		}
		challenge, err := tunnelv1.ConnectorPeerBindingProbe(pair.ID, pair.OperationID, pair.DeliveryGeneration, pair.BindingChallenge, role, uint8(slot), nonce)
		if err != nil {
			t.Fatal(err)
		}
		frame, err := tunnelv1.SignPeerPacketFrame(tunnelv1.PeerPacket{Kind: tunnelv1.PeerProbeReply, Sender: 1 - role, Path: uint8(slot), Sequence: uint64(slot + 1), Total: 16, Payload: challenge[:], BindingGeneration: uint64(pair.DeliveryGeneration)}, key)
		if err != nil {
			t.Fatal(err)
		}
		proofs[slot] = tunnelv1.ConnectorPeerPairPathProof{ConnectionSlot: slot, ProbeNonce: base64.RawURLEncoding.EncodeToString(nonce), ReplyFrame: base64.RawURLEncoding.EncodeToString(frame)}
	}
	return proofs
}

func connectorRebindClaimBoth(t *testing.T, f connectorPairFixture, pair ConnectorPeerPair, source netip.Addr, at time.Time) {
	t.Helper()
	for slot := range 2 {
		claim, err := testClaimConnectorPeerPairLeg(t, f.d, t.Context(), pair.Relays[slot].RelayLease, source, testConnectorLegProof(t, pair, slot, at, f.key), at)
		if err != nil || claim.Key != pair.Key || claim.BindingState != tunnelv1.ConnectorPeerLegBindingPrepared {
			t.Fatal("pending claim", err)
		}
	}
}

func connectorRebindReport(t *testing.T, f connectorPairFixture, pair ConnectorPeerPair, phase string, at time.Time) ConnectorPeerPairPrepared {
	t.Helper()
	report := ConnectorPeerPairPrepared{Phase: phase, OperationID: pair.OperationID, BindingChallenge: pair.BindingChallenge, DeliveryID: pair.DeliveryID, DeliveryGeneration: pair.DeliveryGeneration, BindingExpiresAt: pair.ExpiresAt}
	if phase == "proved" {
		report.PathProofs = connectorRebindProofs(t, pair, 1)
	}
	if err := f.d.ConfirmConnectorPeerPairPrepared(t.Context(), pair.ServiceID, pair.ServiceRunID, pair.ID, f.run.Token, report, at); err != nil {
		t.Fatal("publisher report", phase, err)
	}
	return report
}

func TestIntegrationConnectorRebindRetainsOwnerAndFencesOldBinding(t *testing.T) {
	f := newConnectorPairFixture(t)
	pair := f.create(t)
	for slot := range 2 {
		f.claim(t, pair, slot, f.now)
	}
	f.report(t, pair, pair.ExpiresAt, f.now)
	prepare := connectorRebindRequest(t, f, pair, "prepare", f.now.Add(time.Second))
	state, err := f.d.RebindConnectorPeerPair(f.visitor, pair.ServiceID, pair.ID, prepare, prepare.Proof.RequestedAt)
	if err != nil || state.Pending == nil || state.Active == nil {
		t.Fatal("prepare", err)
	}
	pending := *state.Pending
	if pending.ID != pair.ID || pending.SessionKey != pair.SessionKey || pending.Key == pair.Key || pending.DeliveryID != pair.DeliveryID || pending.DeliveryGeneration <= pair.DeliveryGeneration || pending.TrustRevision != pair.TrustRevision || state.Active.DeliveryGeneration != pair.DeliveryGeneration {
		t.Fatal("prepare transferred session identity")
	}
	retry, err := f.d.RebindConnectorPeerPair(f.visitor, pair.ServiceID, pair.ID, prepare, f.now.Add(2*time.Second))
	if err != nil || retry.Pending == nil || retry.Pending.Key != pending.Key || !retry.PendingUntil.Equal(state.PendingUntil) {
		t.Fatal("uncertain preparation issued new authority", err)
	}
	connectorRebindClaimBoth(t, f, pending, netip.MustParseAddr("192.0.2.11"), f.now.Add(2*time.Second))
	var unreported bool
	if err := f.d.pool.QueryRow(t.Context(), `SELECT publisher_prepared_until IS NULL AND publisher_proved_until IS NULL AND publisher_proof_digest IS NULL FROM control.connector_peer_pending_bindings WHERE pair_id=$1`, pair.ID).Scan(&unreported); err != nil || !unreported {
		t.Fatal("relay claims fabricated publisher installation or path evidence", err)
	}
	delivery, err := f.d.DeliverConnectorPeerPair(t.Context(), pair.ServiceID, pair.ServiceRunID, pair.ID, pending.DeliveryGeneration, f.run.Token, f.now.Add(2*time.Second))
	if err != nil || delivery.SessionKey != pair.SessionKey || delivery.Key != pending.Key || delivery.BindingState != "prepared" {
		t.Fatal("pending publisher delivery", err)
	}
	connectorRebindReport(t, f, pending, "installed", f.now.Add(2*time.Second))
	activate := prepare.Proof
	activate.Phase = "activate"
	activate.ExpectedGeneration = pending.DeliveryGeneration
	activate.ExpectedRelays = nil
	activate.BindingChallenge = pending.BindingChallenge
	activate.PathProofs = connectorRebindProofs(t, pending, 0)
	activate.RequestedAt = f.now.Add(3 * time.Second)
	request := signConnectorRebind(t, f, activate)
	var hasProof bool
	if err := f.d.pool.QueryRow(t.Context(), `SELECT publisher_proved_until IS NOT NULL FROM control.connector_peer_pending_bindings WHERE pair_id=$1`, pair.ID).Scan(&hasProof); err != nil || hasProof {
		t.Fatal("installation report unexpectedly contained path evidence", err)
	}
	if got, err := f.d.RebindConnectorPeerPair(f.visitor, pair.ServiceID, pair.ID, request, activate.RequestedAt); !errors.Is(err, ErrServiceAccess) {
		t.Fatalf("activation skipped publisher path proof: phase=%s status=%s generation=%d error=%v", request.Proof.Phase, got.OperationStatus, got.OperationGeneration, err)
	}
	proved := connectorRebindReport(t, f, pending, "proved", f.now.Add(2*time.Second))
	var proofUntil time.Time
	if err := f.d.pool.QueryRow(t.Context(), `SELECT publisher_proved_until FROM control.connector_peer_pending_bindings WHERE pair_id=$1`, pair.ID).Scan(&proofUntil); err != nil {
		t.Fatal(err)
	}
	if err := f.d.ConfirmConnectorPeerPairPrepared(t.Context(), pair.ServiceID, pair.ServiceRunID, pair.ID, f.run.Token, proved, f.now.Add(3*time.Second)); err != nil {
		t.Fatal(err)
	}
	var after time.Time
	if err := f.d.pool.QueryRow(t.Context(), `SELECT publisher_proved_until FROM control.connector_peer_pending_bindings WHERE pair_id=$1`, pair.ID).Scan(&after); err != nil || !after.Equal(proofUntil) {
		t.Fatal("duplicate proof advanced freshness", err)
	}
	active, err := f.d.RebindConnectorPeerPair(f.visitor, pair.ServiceID, pair.ID, request, activate.RequestedAt)
	if err != nil || active.Active == nil || active.Pending != nil || active.Active.DeliveryGeneration != pending.DeliveryGeneration || active.Active.SourceIP.String() != "192.0.2.11" || active.Active.SessionKey != pair.SessionKey {
		t.Fatal("activation", err)
	}
	if retry, err := f.d.RebindConnectorPeerPair(f.visitor, pair.ServiceID, pair.ID, request, f.now.Add(4*time.Second)); err != nil || retry.Active == nil || !retry.Active.ExpiresAt.Equal(active.Active.ExpiresAt) {
		t.Fatal("lost activation reply extended authority", err)
	}
	oldProof := testConnectorLegProof(t, pair, 0, f.now.Add(4*time.Second), f.key)
	if _, err := testClaimConnectorPeerPairLeg(t, f.d, t.Context(), pair.Relays[0].RelayLease, netip.MustParseAddr("192.0.2.10"), oldProof, oldProof.RequestedAt); !errors.Is(err, ErrServiceAccess) {
		t.Fatal("retired generation regained claim", err)
	}
	newProof := testConnectorLegProof(t, *active.Active, 0, f.now.Add(4*time.Second), f.key)
	claim, err := testClaimConnectorPeerPairLeg(t, f.d, t.Context(), active.Active.Relays[0].RelayLease, active.Active.SourceIP, newProof, newProof.RequestedAt)
	if err != nil || claim.BindingState != tunnelv1.ConnectorPeerLegBindingActive || claim.Key != pending.Key {
		t.Fatal("active claim observation", err)
	}
	var count int
	if err := f.d.pool.QueryRow(t.Context(), `SELECT count(*) FROM control.connector_peer_audit_bindings WHERE pair_id=$1`, pair.ID).Scan(&count); err != nil || count != 2 {
		t.Fatal("source history overwritten", count, err)
	}
}

func TestIntegrationConnectorRebindAbortExpiryAndConcurrentCAS(t *testing.T) {
	f := newConnectorPairFixture(t)
	pair := f.create(t)
	prepare := connectorRebindRequest(t, f, pair, "prepare", f.now.Add(time.Second))
	var workers sync.WaitGroup
	results := make(chan ConnectorPeerPairRebindState, 2)
	failures := make(chan error, 2)
	for range 2 {
		workers.Go(func() {
			state, err := f.d.RebindConnectorPeerPair(f.visitor, pair.ServiceID, pair.ID, prepare, prepare.Proof.RequestedAt)
			results <- state
			failures <- err
		})
	}
	workers.Wait()
	a, b := <-results, <-results
	if err := <-failures; err != nil {
		t.Fatal(err)
	}
	if err := <-failures; err != nil {
		t.Fatal(err)
	}
	if a.Pending == nil || b.Pending == nil || a.Pending.Key != b.Pending.Key || a.HighWaterGeneration != b.HighWaterGeneration {
		t.Fatal("concurrent exact preparation allocated twice")
	}
	abort := prepare.Proof
	abort.Phase = "abort"
	abort.ExpectedGeneration = a.HighWaterGeneration
	abort.ExpectedRelays = nil
	abort.RequestedAt = f.now.Add(2 * time.Second)
	request := signConnectorRebind(t, f, abort)
	state, err := f.d.RebindConnectorPeerPair(f.visitor, pair.ServiceID, pair.ID, request, abort.RequestedAt)
	if err != nil || state.Pending != nil || state.HighWaterGeneration != a.HighWaterGeneration || state.OperationStatus != "aborted" {
		t.Fatal("abort", err)
	}
	if retry, err := f.d.RebindConnectorPeerPair(f.visitor, pair.ServiceID, pair.ID, prepare, f.now.Add(3*time.Second)); err != nil || retry.Pending != nil || retry.OperationStatus != "aborted" {
		t.Fatal("old prepare revived aborted revision", err)
	}
	next := connectorRebindRequest(t, f, pair, "prepare", f.now.Add(3*time.Second))
	next.Proof.ExpectedGeneration = state.HighWaterGeneration
	next = signConnectorRebind(t, f, next.Proof)
	state, err = f.d.RebindConnectorPeerPair(f.visitor, pair.ServiceID, pair.ID, next, next.Proof.RequestedAt)
	if err != nil || state.Pending == nil || state.HighWaterGeneration != a.HighWaterGeneration+1 {
		t.Fatal("high-water reuse", err)
	}
	inspect := connectorRebindRequest(t, f, pair, "inspect", f.now.Add(14*time.Second))
	state, err = f.d.RebindConnectorPeerPair(f.visitor, pair.ServiceID, pair.ID, inspect, inspect.Proof.RequestedAt)
	if err != nil || state.Pending != nil || state.OperationStatus != "expired" || state.HighWaterGeneration != a.HighWaterGeneration+1 {
		t.Fatal("expired operation retained secrets or lost high-water", err)
	}
}

func TestIntegrationConnectorRebindDenialPrecedesChangedSourceAndAssignment(t *testing.T) {
	f := newConnectorPairFixture(t)
	pair := f.create(t)
	for slot := range 2 {
		f.claim(t, pair, slot, f.now)
	}
	at := f.now.Add(time.Second)
	proof := testConnectorLegProof(t, pair, 0, at, f.key)
	if _, err := testClaimConnectorPeerPairLeg(t, f.d, t.Context(), pair.Relays[0].RelayLease, netip.MustParseAddr("192.0.2.11"), proof, at); !errors.Is(err, ErrConnectorPeerBindingStale) {
		t.Fatal("authorized source change became denial", err)
	}
	connection, _ := opaqueid.New(opaqueid.PublisherConnectionPrefix)
	if _, err := f.d.pool.Exec(t.Context(), `UPDATE control.service_connection_slots SET publisher_connection_id=$2,connection_assignment_revision=connection_assignment_revision+1 WHERE publisher_connection_id=$1`, pair.Relays[0].PublisherConnectionID, connection); err != nil {
		t.Fatal(err)
	}
	if _, err := testClaimConnectorPeerPairLeg(t, f.d, t.Context(), pair.Relays[0].RelayLease, netip.MustParseAddr("192.0.2.10"), proof, at); !errors.Is(err, ErrConnectorPeerBindingStale) {
		t.Fatal("authorized assignment change became denial", err)
	}
	if _, err := f.d.pool.Exec(t.Context(), `UPDATE control.visitor_devices SET revoked_at=$2 WHERE id=$1`, pair.Subject.DeviceID, at); err != nil {
		t.Fatal(err)
	}
	if _, err := testClaimConnectorPeerPairLeg(t, f.d, t.Context(), pair.Relays[0].RelayLease, netip.MustParseAddr("192.0.2.11"), proof, at); err == nil || errors.Is(err, ErrConnectorPeerBindingStale) {
		t.Fatal("revocation became rebind retry", err)
	}
}

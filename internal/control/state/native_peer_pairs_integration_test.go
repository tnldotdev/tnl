package state

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

func testNativeLegProof(t *testing.T, pair NativePeerPair, slot int, at time.Time, key ed25519.PrivateKey) tunnelv1.NativePairLegProof {
	t.Helper()
	leg := pair.Relays[slot]
	p := tunnelv1.NativePairLegProof{PairID: pair.ID, DeliveryGeneration: pair.DeliveryGeneration,
		ServiceID: pair.ServiceID, ServiceRunID: pair.ServiceRunID, RunNumber: pair.RunNumber,
		PublisherIdentityID: pair.PublisherIdentityID, ConnectionSlot: slot,
		PublisherConnectionID: leg.PublisherConnectionID, AssignmentRevision: leg.AssignmentRevision,
		RelayServiceID: leg.RelayLease.RelayServiceID, RelayID: leg.RelayLease.RelayID,
		RelayRunID: leg.RelayLease.RelayRunID, RelayLeaseRevision: leg.RelayLease.RelayLeaseRevision,
		RequestedAt: at, Nonce: make([]byte, 32)}
	if _, err := rand.Read(p.Nonce); err != nil {
		t.Fatal(err)
	}
	message, err := p.Message()
	if err != nil {
		t.Fatal(err)
	}
	p.Signature = ed25519.Sign(key, message)
	return p
}

func testClaimNativePeerPairLeg(t *testing.T, d *Database, ctx context.Context, lease RelayLeaseIdentity, source netip.Addr, proof tunnelv1.NativePairLegProof, now time.Time) (NativePeerPairLegClaim, error) {
	t.Helper()
	seed := sha256.Sum256([]byte(lease.RelayRunID))
	message, err := proof.RelayClaimMessage(source)
	if err != nil {
		t.Fatal(err)
	}
	return d.ClaimNativePeerPairLeg(ctx, lease, source, proof, ed25519.Sign(ed25519.NewKeyFromSeed(seed[:]), message), now)
}

func testNativePairRelays(run ServiceRunState, leases map[string]RelayLease) (relays [2]NativePeerPairRelay) {
	for index, slot := range run.Connections {
		lease := leases[slot.RelayServiceID]
		relays[index] = NativePeerPairRelay{PublisherConnectionID: slot.PublisherConnectionID, AssignmentRevision: slot.Revision,
			RelayLease: lease.RelayLeaseIdentity, RelayAddress: lease.RelayAddress, TLSServerName: lease.TLSServerName}
	}
	return
}

func rotateNativePairStorage(t *testing.T, d *Database, pair NativePeerPair) *Database {
	t.Helper()
	ctx := t.Context()
	var oldCiphertext []byte
	var oldKeyID string
	if err := d.pool.QueryRow(ctx, `SELECT key_ciphertext,storage_key_id FROM control.native_peer_pairs WHERE id=$1`, pair.ID).
		Scan(&oldCiphertext, &oldKeyID); err != nil || oldKeyID != d.storageKey.CurrentID() {
		t.Fatal("pair was not sealed under the original storage key", err)
	}
	newKey := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{11}, 32))
	databaseURL := d.pool.Config().ConnString()
	rotating, err := Open(ctx, databaseURL, newKey, testStorageKey)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(rotating.Close)
	lock, err := rotating.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer rollbackTestTransaction(t, lock)
	if _, err := lock.Exec(ctx, `SELECT id FROM control.native_peer_pairs WHERE id=$1 FOR UPDATE`, pair.ID); err != nil {
		t.Fatal(err)
	}
	for {
		rotated, err := rotating.ReencryptStorageSecrets(ctx, 1)
		if err != nil || rotated > 1 {
			t.Fatal("bounded key rotation failed", rotated, err)
		}
		if rotated == 0 {
			break
		}
	}
	if remaining, err := rotating.countPreviousStorageSecrets(ctx); err != nil || remaining != 1 {
		t.Fatal("locked native pair was omitted from previous-key count", remaining, err)
	}
	wait, cancel := context.WithTimeout(ctx, 350*time.Millisecond)
	err = rotating.CompleteStorageKeyRotation(wait)
	cancel()
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("rotation completed while an old-key native pair was locked", err)
	}
	if err := lock.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	if err := rotating.CompleteStorageKeyRotation(ctx); err != nil {
		t.Fatal(err)
	}
	if remaining, err := rotating.countPreviousStorageSecrets(ctx); err != nil || remaining != 0 {
		t.Fatal("completed rotation left a previous-key pair", remaining, err)
	}
	rotating.Close()
	d.Close()
	reopened, err := Open(ctx, databaseURL, newKey, "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(reopened.Close)
	var ciphertext []byte
	var keyID string
	if err := reopened.pool.QueryRow(ctx, `SELECT key_ciphertext,storage_key_id FROM control.native_peer_pairs WHERE id=$1`, pair.ID).
		Scan(&ciphertext, &keyID); err != nil || keyID != reopened.storageKey.CurrentID() || bytes.Equal(ciphertext, oldCiphertext) {
		t.Fatal("pair retained its previous ciphertext or key ID", err)
	}
	return reopened
}

func TestIntegrationNativePeerPairExactAuthority(t *testing.T) {
	f := newPublishRunFixture(t)
	d, now, ctx := f.database, f.now, t.Context()
	session := newOIDCSession(t, d, now)
	principal := ControlPrincipal{IdentityID: session.Identity.Identity.ID, SessionID: session.SessionID}
	visitor := WithControlPrincipal(ctx, principal)
	actor := oidcRouteRequest(t, d, now)
	service, err := d.CreateServiceAt(visitor, actor.TeamID, principal.IdentityID, "pair", "pair", ServicePlacement{}, now, ServiceMetadata{Protocol: "tcp"})
	if err != nil {
		t.Fatal(err)
	}
	enrollment := publisherEnrollment(t, d, actor, PublisherScope{TeamID: actor.TeamID, Kind: "service", ServiceID: service.ID}, now)
	publisherKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	publisher, err := d.RedeemPublisherEnrollment(ctx, enrollment.Key, publisherKey, now)
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := d.PrepareServiceRun(ctx, service.ID, publisher, "pair", now, ServiceMetadata{Protocol: "tcp", TrustRevision: 1})
	if err != nil {
		t.Fatal(err)
	}
	run, err := d.StartServiceRun(ctx, service.ID, prepared.RunID, prepared.RunNumber, publisher, now)
	if err != nil {
		t.Fatal(err)
	}
	const directory = "https://acme.example.test/directory"
	if _, err := d.EnsureACMEAccount(ctx, directory, "operator@example.test", now); err != nil {
		t.Fatal(err)
	}
	certificateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{DNSNames: prepared.CertificatePlan.Identifiers}, certificateKey)
	if err != nil {
		t.Fatal(err)
	}
	issuance, err := d.CreateServiceCertificateIssuance(ctx, service.ID, run.RunID, run.Token, directory, "pair", run.RunNumber, csr, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.pool.Exec(ctx, `UPDATE control.service_runs SET certificate_issuance_id=$2,certificate_expires_at=$3 WHERE id=$1`, run.RunID, issuance.ID, now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	for _, slot := range run.Connections {
		lease := f.leases[slot.RelayServiceID].RelayLeaseIdentity
		if _, err := d.ClaimServicePublisherConnection(ctx, slot.PublisherConnectionID, service.ID, run.RunID, run.RunNumber, slot.Revision, slot.Credential, lease, now); err != nil {
			t.Fatal(err)
		}
		if _, err := d.ReadyServicePublisherConnection(ctx, slot.PublisherConnectionID, run.RunID, run.RunNumber, slot.Revision, lease, now); err != nil {
			t.Fatal(err)
		}
	}
	if state, err := d.HeartbeatServiceRun(ctx, service.ID, run.RunID, run.Token, now); err != nil || state.State != "ready" {
		t.Fatal("service run is not ready", err)
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	device, err := d.EnrollVisitorDevice(visitor, principal.IdentityID, public, now)
	if err != nil {
		t.Fatal(err)
	}
	request := NativePeerPairRequest{ServiceID: service.ID, ServiceRunID: run.RunID, RunNumber: run.RunNumber,
		PublisherIdentityID: publisher.ID, IdempotencyKey: "one", Subject: VisitorSubject{Kind: tunnelv1.VisitorHumanDevice, IdentityID: principal.IdentityID, DeviceID: device.ID}, Source: DeviceTokenSource{DeviceID: device.ID},
		Action: "create", RequestedAt: now, ExpectedRelays: testNativePairRelays(run, f.leases)}
	sign := func(r *NativePeerPairRequest) {
		t.Helper()
		message, err := r.proof().Message()
		if err != nil {
			t.Fatal(err)
		}
		r.Signature = ed25519.Sign(private, message)
	}
	sign(&request)
	first, err := d.PrepareNativePeerPair(visitor, request, now)
	if err != nil {
		t.Fatal(err)
	}
	if first.ID == "" || first.Key == "" || first.DeliveryGeneration < 1 || !first.ExpiresAt.After(now) || first.ExpiresAt.After(run.ExpiresAt) || first.Relays[0].RelayLease.RelayServiceID == first.Relays[1].RelayLease.RelayServiceID {
		t.Fatal("pair escaped its exact ready run and two distinct leases")
	}
	sourceIP := netip.MustParseAddr("192.0.2.10")
	leg0 := testNativeLegProof(t, first, 0, now, private)
	claimMessage, err := leg0.RelayClaimMessage(sourceIP)
	if err != nil {
		t.Fatal(err)
	}
	// a cluster-authenticated caller with the lease ID and public key still
	// cannot claim this leg without the process's private key.
	publicOnly := f.leases[first.Relays[0].RelayLease.RelayServiceID].PeerSigningPublicKey
	if _, err := d.ClaimNativePeerPairLeg(ctx, first.Relays[0].RelayLease, sourceIP, leg0,
		ed25519.Sign(ed25519.NewKeyFromSeed(publicOnly), claimMessage), now); !errors.Is(err, ErrServiceAccess) {
		t.Fatal("public lease key authorized a native peer leg", err)
	}
	relaySeed := sha256.Sum256([]byte(first.Relays[0].RelayLease.RelayRunID))
	if _, err := d.ClaimNativePeerPairLeg(ctx, first.Relays[0].RelayLease, netip.MustParseAddr("192.0.2.11"), leg0,
		ed25519.Sign(ed25519.NewKeyFromSeed(relaySeed[:]), claimMessage), now); !errors.Is(err, ErrServiceAccess) {
		t.Fatal("signature for a different relay-observed source authorized a leg", err)
	}
	if _, err := d.pool.Exec(ctx, `UPDATE control.relay_leases SET peer_signing_public_key=NULL WHERE relay_id=$1`, first.Relays[0].RelayLease.RelayID); err != nil {
		t.Fatal(err)
	}
	if _, err := testClaimNativePeerPairLeg(t, d, ctx, first.Relays[0].RelayLease, sourceIP, leg0, now); !errors.Is(err, ErrServiceAccess) {
		t.Fatal("missing-key lease authorized a native peer leg", err)
	}
	if _, err := d.pool.Exec(ctx, `UPDATE control.relay_leases SET peer_signing_public_key=$2 WHERE relay_id=$1`, first.Relays[0].RelayLease.RelayID, publicOnly); err != nil {
		t.Fatal(err)
	}
	claim0, err := testClaimNativePeerPairLeg(t, d, ctx, first.Relays[0].RelayLease, sourceIP, leg0, now)
	if err != nil || claim0.Key != first.Key || claim0.SourceIP != sourceIP || claim0.ExpiresAt.After(first.ExpiresAt) ||
		claim0.PairID != first.ID || claim0.DeliveryGeneration != first.DeliveryGeneration {
		t.Fatal("exact relay leg did not receive bounded delivery", err)
	}
	if bytes.Contains([]byte(claim0.String()+claim0.GoString()), []byte(first.Key)) {
		t.Fatal("claim formatted the key")
	}
	if _, err := testClaimNativePeerPairLeg(t, d, ctx, first.Relays[0].RelayLease, sourceIP, leg0, now); !errors.Is(err, ErrServiceAccess) {
		t.Fatal("replayed proof recovered key", err)
	}
	other := testNativeLegProof(t, first, 1, now, private)
	if claim, err := testClaimNativePeerPairLeg(t, d, ctx, first.Relays[1].RelayLease, sourceIP, other, now); err != nil || claim.Key != first.Key || claim.ConnectionSlot != 1 {
		t.Fatal("sibling relay could not claim its own leg", err)
	}
	if _, err := testClaimNativePeerPairLeg(t, d, ctx, first.Relays[1].RelayLease, sourceIP, leg0, now); !errors.Is(err, ErrServiceAccess) {
		t.Fatal("sibling relay obtained other leg", err)
	}
	if _, err := d.pool.Exec(ctx, `UPDATE control.relay_services SET relay_address=$2 WHERE relay_service_id=$1`,
		first.Relays[0].RelayLease.RelayServiceID, "relay-changed.example.test:443"); err != nil {
		t.Fatal(err)
	}
	if _, err := testClaimNativePeerPairLeg(t, d, ctx, first.Relays[0].RelayLease, sourceIP,
		testNativeLegProof(t, first, 0, now.Add(time.Microsecond), private), now.Add(time.Microsecond)); !errors.Is(err, ErrServiceAccess) {
		t.Fatal("changed relay address retained its old pair key", err)
	}
	if _, err := d.PrepareNativePeerPair(visitor, request, now); !errors.Is(err, ErrServiceAccess) {
		t.Fatal("changed relay address prepared stale assignment", err)
	}
	if _, err := d.pool.Exec(ctx, `UPDATE control.relay_services SET relay_address=$2 WHERE relay_service_id=$1`,
		first.Relays[0].RelayLease.RelayServiceID, first.Relays[0].RelayAddress); err != nil {
		t.Fatal(err)
	}
	wrongProcess := testNativeLegProof(t, first, 0, now.Add(time.Microsecond), private)
	wrongProcess.RelayServiceID = first.Relays[1].RelayLease.RelayServiceID
	wrongProcess.RelayID = first.Relays[1].RelayLease.RelayID
	wrongProcess.RelayRunID = first.Relays[1].RelayLease.RelayRunID
	wrongProcess.RelayLeaseRevision = first.Relays[1].RelayLease.RelayLeaseRevision
	wrongMessage, err := wrongProcess.Message()
	if err != nil {
		t.Fatal(err)
	}
	wrongProcess.Signature = ed25519.Sign(private, wrongMessage)
	if _, err := testClaimNativePeerPairLeg(t, d, ctx, first.Relays[1].RelayLease, sourceIP, wrongProcess, wrongProcess.RequestedAt); !errors.Is(err, ErrServiceAccess) {
		t.Fatal("signed proof for the wrong relay process obtained key", err)
	}
	wrongLease := first.Relays[0].RelayLease
	wrongLease.RelayLeaseRevision++
	if _, err := testClaimNativePeerPairLeg(t, d, ctx, wrongLease, sourceIP, leg0, now); !errors.Is(err, ErrServiceAccess) {
		t.Fatal("wrong relay lease revision obtained key", err)
	}
	writtenAgain := testNativeLegProof(t, first, 0, now.Add(time.Microsecond), private)
	if claim, err := testClaimNativePeerPairLeg(t, d, ctx, first.Relays[0].RelayLease, sourceIP, writtenAgain, writtenAgain.RequestedAt); err != nil || claim.Key != first.Key {
		t.Fatal("fresh same-source retry lost delivery", err)
	}
	if _, err := testClaimNativePeerPairLeg(t, d, ctx, first.Relays[0].RelayLease, sourceIP, leg0, writtenAgain.RequestedAt); !errors.Is(err, ErrServiceAccess) {
		t.Fatal("older proof recovered key after retry", err)
	}
	if _, err := testClaimNativePeerPairLeg(t, d, ctx, first.Relays[0].RelayLease, netip.MustParseAddr("192.0.2.11"), testNativeLegProof(t, first, 0, now.Add(2*time.Microsecond), private), now.Add(2*time.Microsecond)); !errors.Is(err, ErrServiceAccess) {
		t.Fatal("new source reused an existing relay claim", err)
	}
	var claimCount int
	if err := d.pool.QueryRow(ctx, `SELECT count(*) FROM control.native_peer_pair_leg_claims WHERE pair_id=$1`, first.ID).Scan(&claimCount); err != nil || claimCount != 2 {
		t.Fatal("claim retries exceeded one stored nonce per relay leg", claimCount, err)
	}
	again, err := d.PrepareNativePeerPair(visitor, request, now)
	if err != nil || again.ID != first.ID || again.Key != first.Key || again.DeliveryGeneration != first.DeliveryGeneration || !again.ExpiresAt.Equal(first.ExpiresAt) {
		t.Fatal("uncertain response retry changed the exact delivery", err)
	}
	var retries sync.WaitGroup
	for range 4 {
		retries.Go(func() {
			got, err := d.PrepareNativePeerPair(visitor, request, now)
			if err != nil || got.ID != first.ID || got.Key != first.Key || got.DeliveryGeneration != first.DeliveryGeneration {
				t.Errorf("concurrent uncertain delivery changed the pair: %v", err)
			}
		})
	}
	retries.Wait()
	d = rotateNativePairStorage(t, d, first)
	rotatedRetry, err := d.PrepareNativePeerPair(visitor, request, now)
	if err != nil || rotatedRetry.ID != first.ID || rotatedRetry.Key != first.Key || rotatedRetry.DeliveryGeneration != first.DeliveryGeneration {
		t.Fatal("retry lost the exact pair or advanced delivery after retiring the old storage key", err)
	}
	grantDeadline := now.Add(2 * time.Second)
	if _, err := d.pool.Exec(ctx, `UPDATE control.publisher_grants SET expires_at=$2 WHERE id=$1`, publisher.GrantID, grantDeadline); err != nil {
		t.Fatal(err)
	}
	clipped, err := d.PrepareNativePeerPair(visitor, request, now)
	if err != nil || clipped.ExpiresAt.After(grantDeadline) || clipped.ID != first.ID || clipped.DeliveryGeneration != first.DeliveryGeneration {
		t.Fatal("retry outlived the publisher grant's earlier deadline", err)
	}
	var savedDeadline time.Time
	if err := d.pool.QueryRow(ctx, `SELECT expires_at FROM control.native_peer_pairs WHERE id=$1`, first.ID).Scan(&savedDeadline); err != nil || !savedDeadline.Equal(clipped.ExpiresAt) {
		t.Fatal("durable relay claim deadline was not clipped with the delivery", err)
	}
	if _, err := d.pool.Exec(ctx, `UPDATE control.publisher_grants SET expires_at=NULL WHERE id=$1`, publisher.GrantID); err != nil {
		t.Fatal(err)
	}
	if _, err := d.PrepareNativePeerPair(ctx, request, now); !errors.Is(err, ErrVisitorPermission) {
		t.Fatal("signed proof without a current control session recovered pair", err)
	}
	wrongRun := request
	wrongRun.RunNumber++
	sign(&wrongRun)
	if _, err := d.PrepareNativePeerPair(visitor, wrongRun, now); !errors.Is(err, ErrServiceAccess) {
		t.Fatal("replaced run number recovered pair", err)
	}
	staleRunProof := testNativeLegProof(t, first, 0, now.Add(3*time.Microsecond), private)
	staleRunProof.RunNumber++
	message, err := staleRunProof.Message()
	if err != nil {
		t.Fatal(err)
	}
	staleRunProof.Signature = ed25519.Sign(private, message)
	if _, err := testClaimNativePeerPairLeg(t, d, ctx, first.Relays[0].RelayLease, sourceIP, staleRunProof, staleRunProof.RequestedAt); !errors.Is(err, ErrServiceAccess) {
		t.Fatal("stale run obtained key", err)
	}
	if _, err := d.pool.Exec(ctx, `UPDATE control.publisher_grants SET revoked_at=$2 WHERE id=$1`, publisher.GrantID, now); err != nil {
		t.Fatal(err)
	}
	if _, err := d.PrepareNativePeerPair(visitor, request, now); !errors.Is(err, ErrServiceAccess) {
		t.Fatal("revoked publisher grant recovered pair", err)
	}
	if _, err := testClaimNativePeerPairLeg(t, d, ctx, first.Relays[0].RelayLease, sourceIP, testNativeLegProof(t, first, 0, now.Add(4*time.Microsecond), private), now.Add(4*time.Microsecond)); !errors.Is(err, ErrServiceAccess) {
		t.Fatal("revoked publisher grant recovered relay key", err)
	}
	if _, err := d.pool.Exec(ctx, `UPDATE control.publisher_grants SET revoked_at=NULL WHERE id=$1`, publisher.GrantID); err != nil {
		t.Fatal(err)
	}
	if _, err := d.pool.Exec(ctx, `UPDATE control.visitor_grants SET revoked_at=$2 WHERE service_id=$1`, service.ID, now); err != nil {
		t.Fatal(err)
	}
	if _, err := d.PrepareNativePeerPair(visitor, request, now); !errors.Is(err, ErrVisitorPermission) {
		t.Fatal("removed service visitor grant recovered pair", err)
	}
	if _, err := d.pool.Exec(ctx, `UPDATE control.visitor_grants SET revoked_at=NULL WHERE service_id=$1`, service.ID); err != nil {
		t.Fatal(err)
	}
	bad := request
	bad.IdempotencyKey = "different"
	if _, err := d.PrepareNativePeerPair(visitor, bad, now); !errors.Is(err, ErrServiceAccess) {
		t.Fatal("altered request reused signed proof", err)
	}
	sign(&bad)
	if _, err := d.PrepareNativePeerPair(visitor, bad, now); !errors.Is(err, ErrServiceConflict) {
		t.Fatal("replacement without an exact prior delivery succeeded", err)
	}
	bad = request
	bad.Subject.DeviceID = device.ID[:len(device.ID)-1] + "0"
	if _, err := d.PrepareNativePeerPair(visitor, bad, now); err == nil {
		t.Fatal("wrong enrolled subject obtained pair")
	}
	replacement := request
	replacement.Action, replacement.IdempotencyKey = "replace", "replacement"
	replacement.PreviousPairID, replacement.PreviousGeneration = first.ID, first.DeliveryGeneration
	replacement.RequestedAt = now.Add(time.Millisecond)
	sign(&replacement)
	second, err := d.PrepareNativePeerPair(visitor, replacement, replacement.RequestedAt)
	if err != nil || second.ID == first.ID || second.Key == first.Key || second.DeliveryGeneration <= first.DeliveryGeneration {
		t.Fatal("signed replacement did not rotate the exact delivery", err)
	}
	if claim, err := testClaimNativePeerPairLeg(t, d, ctx, second.Relays[0].RelayLease, sourceIP, testNativeLegProof(t, second, 0, replacement.RequestedAt, private), replacement.RequestedAt); err != nil || claim.Key != second.Key {
		t.Fatal("new delivery could not claim its own leg", err)
	}
	var oldClaims int
	if err := d.pool.QueryRow(ctx, `SELECT count(*) FROM control.native_peer_pair_leg_claims WHERE pair_id=$1`, first.ID).Scan(&oldClaims); err != nil || oldClaims != 0 {
		t.Fatal("replacement retained old relay claims", oldClaims, err)
	}
	replacedRetry, err := d.PrepareNativePeerPair(visitor, replacement, replacement.RequestedAt)
	if err != nil || replacedRetry.ID != second.ID || replacedRetry.Key != second.Key || replacedRetry.DeliveryGeneration != second.DeliveryGeneration {
		t.Fatal("uncertain replacement response advanced delivery twice", err)
	}
	if _, err := d.PrepareNativePeerPair(visitor, request, replacement.RequestedAt); !errors.Is(err, ErrServiceConflict) {
		t.Fatal("old signed creation recovered superseded pair", err)
	}
	staleDelivery := replacement
	staleDelivery.IdempotencyKey = "stale-delivery"
	sign(&staleDelivery)
	if _, err := d.PrepareNativePeerPair(visitor, staleDelivery, replacement.RequestedAt); !errors.Is(err, ErrServiceConflict) {
		t.Fatal("stale signed replacement advanced delivery", err)
	}
	stale := replacement
	stale.PreviousPairID, stale.PreviousGeneration = second.ID, second.DeliveryGeneration
	stale.IdempotencyKey = "stale-assignment"
	stale.ExpectedRelays[0].AssignmentRevision++
	sign(&stale)
	if _, err := d.PrepareNativePeerPair(visitor, stale, replacement.RequestedAt); !errors.Is(err, ErrServiceAccess) {
		t.Fatal("signed stale assignment rotated pair", err)
	}
	if _, err := d.pool.Exec(ctx, `UPDATE control.service_connection_slots SET connection_assignment_revision=connection_assignment_revision+1 WHERE publisher_connection_id=$1`, first.Relays[0].PublisherConnectionID); err != nil {
		t.Fatal(err)
	}
	if _, err := d.PrepareNativePeerPair(visitor, replacement, replacement.RequestedAt); !errors.Is(err, ErrServiceAccess) {
		t.Fatal("replaced assignment recovered pair", err)
	}
	if _, err := testClaimNativePeerPairLeg(t, d, ctx, second.Relays[0].RelayLease, sourceIP, testNativeLegProof(t, second, 0, replacement.RequestedAt.Add(time.Microsecond), private), replacement.RequestedAt.Add(time.Microsecond)); !errors.Is(err, ErrServiceAccess) {
		t.Fatal("replaced ready assignment recovered relay key", err)
	}
	if _, err := d.pool.Exec(ctx, `UPDATE control.service_connection_slots SET connection_assignment_revision=connection_assignment_revision-1 WHERE publisher_connection_id=$1`, first.Relays[0].PublisherConnectionID); err != nil {
		t.Fatal(err)
	}
	if _, err := d.pool.Exec(ctx, `UPDATE control.relay_leases SET lease_expires_at=$2 WHERE relay_id=$1`, first.Relays[0].RelayLease.RelayID, now.Add(time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if _, err := d.PrepareNativePeerPair(visitor, request, now.Add(time.Second)); !errors.Is(err, ErrServiceAccess) {
		t.Fatal("expired relay lease recovered pair", err)
	}
	if _, err := testClaimNativePeerPairLeg(t, d, ctx, second.Relays[0].RelayLease, sourceIP, testNativeLegProof(t, second, 0, now.Add(time.Second), private), now.Add(time.Second)); !errors.Is(err, ErrServiceAccess) {
		t.Fatal("expired relay lease recovered relay key", err)
	}
	if err := d.RevokeVisitorDevice(visitor, principal.IdentityID, device.ID, now); err != nil {
		t.Fatal(err)
	}
	if _, err := testClaimNativePeerPairLeg(t, d, ctx, first.Relays[0].RelayLease, sourceIP, testNativeLegProof(t, second, 0, now.Add(5*time.Microsecond), private), now.Add(5*time.Microsecond)); !errors.Is(err, ErrServiceAccess) {
		t.Fatal("revoked native subject recovered relay key", err)
	}
	if _, err := d.PrepareNativePeerPair(visitor, request, now); err == nil {
		t.Fatal("revoked device recovered pair")
	}
	if removed, err := d.CleanupExpiredNativePeerPairs(ctx, second.ExpiresAt, 1); err != nil || removed != 0 {
		t.Fatal("cleanup dropped the replay fence before old proofs expired", removed, err)
	}
	if removed, err := d.CleanupExpiredNativePeerPairs(ctx, now.Add(6*time.Minute), 1); err != nil || removed != 1 {
		t.Fatal("expired pair material was not pruned after the replay fence", removed, err)
	}
	var remainingClaims int
	if err := d.pool.QueryRow(ctx, `SELECT count(*) FROM control.native_peer_pair_leg_claims WHERE pair_id=$1`, second.ID).Scan(&remainingClaims); err != nil || remainingClaims != 0 {
		t.Fatal("expired pair retained relay claim material", remainingClaims, err)
	}
	if _, err := d.PrepareNativePeerPair(visitor, request, now.Add(6*time.Minute)); !errors.Is(err, ErrServiceAccess) {
		t.Fatal("old signed creation recreated a cleaned pair", err)
	}
}

func TestIntegrationNativePeerPairWorkloadCredentialAndSelectedService(t *testing.T) {
	d, now, _, leases := newPublishRunPrerequisites(t)
	ctx := t.Context()
	r := appliedProjectRequest(t, d, now)
	r.Configuration = workloadConfiguration()
	api := r.Configuration.Services["api"]
	api.Target = "http://api.internal:3000"
	api.HTTP = &config.HTTPService{Access: &config.Access{Mode: "restricted", IP: []string{"192.0.2.0/24"}}}
	r.Configuration.Services["api"] = api
	applied, err := d.ApplyProjectConfiguration(ctx, r)
	if err != nil {
		t.Fatal(err)
	}
	var serviceID string
	for _, service := range applied.Services {
		if service.Service == "api" {
			serviceID = service.ServiceID
		}
	}
	if serviceID == "" {
		t.Fatal("no applied api service")
	}
	enrollment, err := d.IssuePublisherGroupEnrollment(ctx, r.TeamID, r.ProjectKey, "production", r.ActorID, 1, time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	replica := enrollAppliedGroup(t, d, r, enrollment, now)
	var assignment PublisherGroupServiceAssignment
	for _, candidate := range replica.assignments.Services {
		if candidate.ServiceID == serviceID {
			assignment = candidate
		}
	}
	access := groupAssignmentAccess(t, d, replica, assignment, now)
	prep, err := d.PrepareServiceRun(ctx, serviceID, access.PublisherIdentity, "peer-pair", now,
		ServiceMetadata{Protocol: assignment.Configuration.Protocol, PublisherPool: true, TrustRevision: assignment.TrustRevision})
	if err != nil {
		t.Fatal(err)
	}
	run, err := d.StartServiceRun(ctx, serviceID, prep.RunID, prep.RunNumber, access.PublisherIdentity, now)
	if err != nil {
		t.Fatal(err)
	}
	installPrivateTestCertificate(t, d, prep, run, now)
	for _, slot := range run.Connections {
		lease := leases[slot.RelayServiceID].RelayLeaseIdentity
		if _, err := d.ClaimServicePublisherConnection(ctx, slot.PublisherConnectionID, serviceID, run.RunID, run.RunNumber, slot.Revision, slot.Credential, lease, now); err != nil {
			t.Fatal(err)
		}
		if _, err := d.ReadyServicePublisherConnection(ctx, slot.PublisherConnectionID, run.RunID, run.RunNumber, slot.Revision, lease, now); err != nil {
			t.Fatal(err)
		}
	}
	if state, err := d.HeartbeatServiceRun(ctx, serviceID, run.RunID, run.Token, now); err != nil || state.State != "ready" {
		t.Fatal("applied service run is not ready", err)
	}
	shortRelayDeadline := now.Add(10 * time.Second)
	for _, lease := range leases {
		if _, err := d.pool.Exec(ctx, `UPDATE control.relay_leases SET lease_expires_at=$2 WHERE relay_id=$1`, lease.RelayID, shortRelayDeadline); err != nil {
			t.Fatal(err)
		}
	}
	exchange, private := workloadExchange(t, r, now)
	exchange.Services = []string{"api"}
	signWorkloadRequest(&exchange, private)
	workload, err := d.ExchangeWorkload(ctx, exchange, now)
	if err != nil {
		t.Fatal(err)
	}
	request := NativePeerPairRequest{ServiceID: serviceID, ServiceRunID: run.RunID, RunNumber: run.RunNumber,
		PublisherIdentityID: access.PublisherIdentity.ID, Subject: workload.Subject, Source: WorkloadTokenSource{Credential: workload.Credential}, IdempotencyKey: "workload",
		Action: "create", RequestedAt: now, ExpectedRelays: testNativePairRelays(run, leases)}
	message, err := request.proof().Message()
	if err != nil {
		t.Fatal(err)
	}
	request.Signature = ed25519.Sign(private, message)
	pair, err := d.PrepareNativePeerPair(ctx, request, now)
	if err != nil || !pair.ExpiresAt.After(shortRelayDeadline) || pair.ExpiresAt.After(workload.LeaseExpiresAt) {
		t.Fatal("workload pair outlived confirmed authority", err)
	}
	proof := testNativeLegProof(t, pair, 0, now, private)
	if _, err := testClaimNativePeerPairLeg(t, d, ctx, pair.Relays[0].RelayLease, netip.MustParseAddr("198.51.100.10"), proof, now); !errors.Is(err, ErrServiceAccess) {
		t.Fatal("connector hint overrode relay-observed IP policy", err)
	}
	if claim, err := testClaimNativePeerPairLeg(t, d, ctx, pair.Relays[0].RelayLease, netip.MustParseAddr("192.0.2.10"), proof, now); err != nil || claim.Key != pair.Key {
		t.Fatal("allowed observed source lost delivery", err)
	}
	for _, lease := range leases {
		if _, err := d.RenewRelay(ctx, RelayRenewal{RelayLeaseIdentity: lease.RelayLeaseIdentity}, now.Add(9*time.Second), time.Hour); err != nil {
			t.Fatal("relay lease did not renew independently of the pair", err)
		}
	}
	bad := request
	bad.Source = WorkloadTokenSource{Credential: "wlc_wrong"}
	if _, err := d.PrepareNativePeerPair(ctx, bad, now); !errors.Is(err, ErrWorkloadDenied) {
		t.Fatal("wrong workload credential recovered pair", err)
	}
	if _, err := d.HeartbeatServiceRun(ctx, serviceID, run.RunID, run.Token, now.Add(30*time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := d.RenewWorkloadSession(ctx, workload.ID, workload.Credential, now.Add(31*time.Second)); err != nil {
		t.Fatal(err)
	}
	unchanged, err := d.PrepareNativePeerPair(ctx, request, now.Add(31*time.Second))
	if err != nil || unchanged.ID != pair.ID || unchanged.Key != pair.Key || unchanged.DeliveryGeneration != pair.DeliveryGeneration || !unchanged.ExpiresAt.Equal(pair.ExpiresAt) {
		t.Fatal("creation retry extended pair after parent leases renewed", err)
	}
	renew := request
	renew.Action, renew.PreviousPairID, renew.PreviousGeneration = "renew", pair.ID, pair.DeliveryGeneration
	renew.RequestedAt = now.Add(32 * time.Second)
	message, err = renew.proof().Message()
	if err != nil {
		t.Fatal(err)
	}
	renew.Signature = ed25519.Sign(private, message)
	firstRenewal, err := d.RenewNativePeerPair(ctx, renew, renew.RequestedAt)
	if err != nil || firstRenewal.ID != pair.ID || firstRenewal.Key != pair.Key || firstRenewal.DeliveryGeneration != pair.DeliveryGeneration || !firstRenewal.ExpiresAt.After(pair.ExpiresAt) {
		t.Fatal("fresh recheck did not extend the pair after the first run heartbeat", err)
	}
	if _, err := d.HeartbeatServiceRun(ctx, serviceID, run.RunID, run.Token, now.Add(60*time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := d.RenewWorkloadSession(ctx, workload.ID, workload.Credential, now.Add(62*time.Second)); err != nil {
		t.Fatal(err)
	}
	uncertain, err := d.RenewNativePeerPair(ctx, renew, now.Add(63*time.Second))
	if err != nil || !uncertain.ExpiresAt.Equal(firstRenewal.ExpiresAt) || uncertain.DeliveryGeneration != pair.DeliveryGeneration {
		t.Fatal("replayed renewal silently extended the serving deadline", err)
	}
	renew.RequestedAt = now.Add(64 * time.Second)
	message, err = renew.proof().Message()
	if err != nil {
		t.Fatal(err)
	}
	renew.Signature = ed25519.Sign(private, message)
	secondRenewal, err := d.RenewNativePeerPair(ctx, renew, renew.RequestedAt)
	if err != nil || secondRenewal.ID != pair.ID || secondRenewal.Key != pair.Key || secondRenewal.DeliveryGeneration != pair.DeliveryGeneration || !secondRenewal.ExpiresAt.After(firstRenewal.ExpiresAt) {
		t.Fatal("second fresh recheck did not extend inner pair lifetime", err)
	}
	var lastAuthorized time.Time
	if err := d.pool.QueryRow(ctx, `SELECT last_authorized_at FROM control.native_peer_pairs WHERE id=$1`, pair.ID).Scan(&lastAuthorized); err != nil || !lastAuthorized.Equal(renew.RequestedAt) || secondRenewal.ExpiresAt.After(lastAuthorized.Add(5*time.Minute)) {
		t.Fatal("pair outlived its last successful authorization", err)
	}
	if _, err := d.PrepareNativePeerPair(ctx, request, now.Add(31*time.Second)); !errors.Is(err, ErrServiceConflict) {
		t.Fatal("delayed retry from before fresh authorization rolled back the deadline", err)
	}
	if _, err := d.HeartbeatServiceRun(ctx, serviceID, run.RunID, run.Token, now.Add(90*time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := d.RenewWorkloadSession(ctx, workload.ID, workload.Credential, now.Add(93*time.Second)); err != nil {
		t.Fatal(err)
	}
	late := now.Add(106 * time.Second)
	renew.RequestedAt = late
	message, err = renew.proof().Message()
	if err != nil {
		t.Fatal(err)
	}
	renew.Signature = ed25519.Sign(private, message)
	if _, err := d.RenewNativePeerPair(ctx, renew, late); !errors.Is(err, ErrServiceAccess) {
		t.Fatal("expired pair was renewed after its serving deadline", err)
	}
	if _, err := d.PrepareNativePeerPair(ctx, request, late); !errors.Is(err, ErrServiceConflict) {
		t.Fatal("expired creation proof revived the old delivery", err)
	}
	replacement := request
	replacement.Action, replacement.IdempotencyKey, replacement.RequestedAt = "replace", "workload-replacement", late
	replacement.PreviousPairID, replacement.PreviousGeneration = pair.ID, pair.DeliveryGeneration
	message, err = replacement.proof().Message()
	if err != nil {
		t.Fatal(err)
	}
	replacement.Signature = ed25519.Sign(private, message)
	newPair, err := d.PrepareNativePeerPair(ctx, replacement, late)
	if err != nil || newPair.ID == pair.ID || newPair.Key == pair.Key || newPair.DeliveryGeneration <= pair.DeliveryGeneration {
		t.Fatal("fresh signed replacement did not recover after expiry", err)
	}
	if err := d.RevokeWorkloadSession(ctx, workload.ID, workload.Credential, late.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := d.PrepareNativePeerPair(ctx, replacement, late.Add(time.Second)); !errors.Is(err, ErrWorkloadDenied) {
		t.Fatal("revoked workload credential recovered pair", err)
	}
}

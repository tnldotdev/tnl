package state

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/netip"
	"time"

	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

// NativePeerPairLegClaim is delivery authority for one relay leg. the key is
// secret material; the relay must still check its local session and application
// stream admission before using it.
type NativePeerPairLegClaim struct {
	PairID             string
	DeliveryID         [16]byte
	DeliveryGeneration int64
	ConnectionSlot     int
	Key                string
	SourceIP           netip.Addr
	ObservedAt         time.Time
	ExpiresAt          time.Time
}

func (NativePeerPairLegClaim) String() string   { return "native peer pair leg claim" }
func (NativePeerPairLegClaim) GoString() string { return "native peer pair leg claim" }

// ClaimNativePeerPairLeg verifies a signature from the exact current relay
// process. the split private relay HTTP API also authenticates the cluster
// secret; standalone calls in-process.
// observedSource comes from the relay socket, never from a connector frame,
// STUN, ICE, or an HTTP forwarding header.
func (d *Database) ClaimNativePeerPairLeg(ctx context.Context, lease RelayLeaseIdentity, observedSource netip.Addr, proof tunnelv1.NativePairLegProof, relaySignature []byte, now time.Time) (result NativePeerPairLegClaim, retErr error) {
	started := time.Now()
	checkedNow := func() time.Time { return now.Add(time.Since(started)) }
	message, err := proof.Message()
	relayMessage, relayErr := proof.RelayClaimMessage(observedSource)
	requestAt := proof.RequestedAt.UTC().Truncate(time.Microsecond)
	if err != nil || relayErr != nil || len(relaySignature) != ed25519.SignatureSize || d.storageKey == nil || now.IsZero() ||
		!observedSource.IsValid() || observedSource.Zone() != "" || validateRelayLeaseIdentity(lease) != nil ||
		lease.RelayServiceID != proof.RelayServiceID || lease.RelayID != proof.RelayID ||
		lease.RelayRunID != proof.RelayRunID || lease.RelayLeaseRevision != proof.RelayLeaseRevision ||
		requestAt.After(now.Add(5*time.Second)) || !requestAt.Add(30*time.Second).After(now) {
		return result, ErrServiceAccess
	}
	observedSource = observedSource.Unmap()
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return result, err
	}
	defer rollback(ctx, tx, "claim native peer pair leg", &retErr)()
	if err = lockServiceAdmission(ctx, tx, proof.ServiceID); err != nil {
		return result, err
	}
	q := controlstatedb.New(tx)
	run, err := q.LockServiceRun(ctx, controlstatedb.LockServiceRunParams{ID: proof.ServiceRunID, ServiceID: proof.ServiceID})
	if err != nil {
		return result, publisherLookupError(err, ErrServiceAccess)
	}
	if run.RunNumber != proof.RunNumber || run.PublisherIdentityID != proof.PublisherIdentityID ||
		run.State != "ready" || !run.Healthy || !activeServiceRun(run, now) ||
		!run.CertificateExpiresAt.Valid || !run.CertificateExpiresAt.Time.After(now) {
		return result, ErrServiceAccess
	}
	if _, err = q.GetServiceRunPublisherIdentity(ctx, controlstatedb.GetServiceRunPublisherIdentityParams{
		ID: run.ID, ServiceID: run.ServiceID, RunNumber: run.RunNumber, PublisherIdentityID: run.PublisherIdentityID,
		PublisherGrantID: run.PublisherGrantID, PublisherKeyID: run.PublisherKeyID, Now: timestamptz(now),
	}); err != nil {
		return result, publisherLookupError(err, ErrServiceAccess)
	}
	current, err := q.GetRelayLeaseForClaim(ctx, lease.RelayID)
	if err != nil {
		return result, publisherLookupError(err, ErrServiceAccess)
	}
	if validateClaimRelayLease(current, lease, proof.RelayServiceID, now) != nil ||
		len(current.PeerSigningPublicKey) != ed25519.PublicKeySize ||
		!ed25519.Verify(current.PeerSigningPublicKey, relayMessage, relaySignature) {
		return result, ErrServiceAccess
	}
	// the run lock serializes assignment replacements. require the exact ready
	// slot, including its process claim, rather than just a matching service.
	slots, err := q.ListServiceConnectionSlots(ctx, run.ID)
	if err != nil {
		return result, err
	}
	if len(slots) != 2 {
		return result, ErrServiceAccess
	}
	slot := slots[proof.ConnectionSlot]
	if int(slot.ConnectionSlot) != proof.ConnectionSlot || slot.ServiceID != proof.ServiceID || slot.RunNumber != proof.RunNumber ||
		slot.PublisherConnectionID != proof.PublisherConnectionID || slot.ConnectionAssignmentRevision != proof.AssignmentRevision ||
		slot.RelayServiceID != lease.RelayServiceID || slot.State != "ready" || !slot.SessionOpen ||
		!slot.RelayID.Valid || slot.RelayID.String != lease.RelayID || !slot.RelayRunID.Valid || slot.RelayRunID.String != lease.RelayRunID ||
		!slot.RelayLeaseRevision.Valid || slot.RelayLeaseRevision.Int64 != int64(lease.RelayLeaseRevision) {
		return result, ErrServiceAccess
	}
	pair, err := q.LockNativePeerPairForLegClaim(ctx, proof.PairID)
	if err != nil {
		return result, publisherLookupError(err, ErrServiceAccess)
	}
	if pair.ServiceID != run.ServiceID || pair.ServiceRunID != run.ID || pair.RunNumber != run.RunNumber ||
		pair.PublisherIdentityID != run.PublisherIdentityID || pair.DeliveryGeneration != proof.DeliveryGeneration ||
		!pair.ExpiresAt.Time.After(now) {
		return result, ErrServiceAccess
	}
	var delivered [2]NativePeerPairRelay
	if json.Unmarshal(pair.Slots, &delivered) != nil || delivered[proof.ConnectionSlot].PublisherConnectionID != slot.PublisherConnectionID ||
		delivered[proof.ConnectionSlot].AssignmentRevision != slot.ConnectionAssignmentRevision || delivered[proof.ConnectionSlot].RelayLease != lease ||
		delivered[proof.ConnectionSlot].RelayAddress != slot.RelayAddress || delivered[proof.ConnectionSlot].RelayAddress != current.RelayAddress ||
		delivered[proof.ConnectionSlot].TLSServerName != slot.TlsServerName || delivered[proof.ConnectionSlot].TLSServerName != current.TlsServerName {
		return result, ErrServiceAccess
	}
	checked := checkedNow()
	if validateClaimRelayLease(current, lease, proof.RelayServiceID, checked) != nil ||
		!requestAt.Add(30*time.Second).After(checked) {
		return result, ErrServiceAccess
	}
	_, key, until, err := nativePeerPairSubjectKey(ctx, tx, pair, checked)
	if err != nil {
		return result, err
	}
	if len(key) != ed25519.PublicKeySize || !ed25519.Verify(key, message, proof.Signature) {
		return result, ErrServiceAccess
	}
	if err = d.serviceHTTPSourceAllowed(ctx, q, proof.ServiceID, observedSource); err != nil {
		return result, err
	}
	publisherUntil, err := nativePeerPublisherAuthority(ctx, tx, run, checkedNow())
	if err != nil {
		return result, err
	}
	deadline := minTime(pair.ExpiresAt.Time, minTime(until, publisherUntil))
	if !deadline.After(checkedNow()) {
		return result, ErrServiceAccess
	}
	nonce := sha256.Sum256(proof.Nonce)
	if _, err = q.SaveNativePeerPairLegClaim(ctx, controlstatedb.SaveNativePeerPairLegClaimParams{
		PairID: pair.ID, ConnectionSlot: int16(proof.ConnectionSlot), RequestedAt: timestamptz(requestAt),
		NonceDigest: nonce[:], SourceIp: observedSource, RelayID: lease.RelayID, RelayRunID: lease.RelayRunID,
		RelayLeaseRevision: int64(lease.RelayLeaseRevision),
		CheckedAt:          timestamptz(checked), ConfirmedUntil: timestamptz(deadline),
	}); err != nil {
		return result, publisherLookupError(err, ErrServiceAccess)
	}
	if err = q.LimitNativePeerPreparedForClaim(ctx, controlstatedb.LimitNativePeerPreparedForClaimParams{PairID: pair.ID, ConfirmedUntil: timestamptz(deadline)}); err != nil {
		return result, err
	}
	secret, _, err := d.storageKey.Open(pair.StorageKeyID, nativePeerPairKeyContext(pair.ID), pair.KeyCiphertext)
	if err != nil {
		return result, err
	}
	defer clear(secret)
	digest := sha256.Sum256(secret)
	if !bytes.Equal(digest[:], pair.KeyDigest) {
		return result, ErrServiceAccess
	}
	if len(pair.DeliveryID) != len(result.DeliveryID) {
		return result, ErrServiceAccess
	}
	copy(result.DeliveryID[:], pair.DeliveryID)
	if result.DeliveryID == [16]byte{} {
		return NativePeerPairLegClaim{}, ErrServiceAccess
	}
	result = NativePeerPairLegClaim{PairID: pair.ID, DeliveryGeneration: pair.DeliveryGeneration,
		DeliveryID: result.DeliveryID, ConnectionSlot: proof.ConnectionSlot, Key: base64.RawURLEncoding.EncodeToString(secret), SourceIP: observedSource, ObservedAt: now, ExpiresAt: deadline}
	if !deadline.After(checkedNow()) || !current.LeaseExpiresAt.Time.After(checkedNow()) || !requestAt.Add(30*time.Second).After(checkedNow()) {
		return NativePeerPairLegClaim{}, ErrServiceAccess
	}
	if err = tx.Commit(ctx); err != nil {
		return NativePeerPairLegClaim{}, err
	}
	if !deadline.After(checkedNow()) {
		return NativePeerPairLegClaim{}, ErrServiceAccess
	}
	return result, nil
}

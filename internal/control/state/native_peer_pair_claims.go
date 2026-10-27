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

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

// NativePeerPairLegClaim is delivery authority for one relay leg. the key is
// secret material; the relay must still check its local session and application
// stream admission before using it.
type NativePeerPairLegClaim struct {
	PairID             string
	DeliveryGeneration int64
	ConnectionSlot     int
	Key                string
	SourceIP           netip.Addr
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
	subject := VisitorSubject{Kind: pair.SubjectKind}
	if subject.Kind == tunnelv1.VisitorHumanDevice {
		subject.DeviceID = pair.SubjectID
		if err = tx.QueryRow(ctx, `SELECT identity_id FROM control.visitor_devices WHERE id=$1 AND revoked_at IS NULL`, pair.SubjectID).Scan(&subject.IdentityID); err != nil {
			return result, publisherLookupError(err, ErrServiceAccess)
		}
	} else {
		subject.WorkloadSessionID = pair.SubjectID
	}
	key, until, err := AuthenticateVisitorSubjectKey(ctx, tx, subject, proof.ServiceID, now)
	if err != nil {
		return result, err
	}
	if len(key) != ed25519.PublicKeySize || !ed25519.Verify(key, message, proof.Signature) {
		return result, ErrServiceAccess
	}
	if err = d.serviceHTTPSourceAllowed(ctx, q, proof.ServiceID, observedSource); err != nil {
		return result, err
	}
	deadline := minTime(pair.ExpiresAt.Time, minTime(until, minTime(run.PublisherExpiresAt.Time, run.CertificateExpiresAt.Time)))
	var grantExpiry pgtype.Timestamptz
	if err = tx.QueryRow(ctx, `SELECT expires_at FROM control.publisher_grants WHERE id=$1 AND publisher_identity_id=$2 AND kind='service' AND service_id=$3 AND revoked_at IS NULL`, run.PublisherGrantID, run.PublisherIdentityID, run.ServiceID).Scan(&grantExpiry); err != nil {
		return result, publisherLookupError(err, ErrServiceAccess)
	}
	if grantExpiry.Valid {
		deadline = minTime(deadline, grantExpiry.Time)
	}
	if !deadline.After(now) {
		return result, ErrServiceAccess
	}
	nonce := sha256.Sum256(proof.Nonce)
	if _, err = q.SaveNativePeerPairLegClaim(ctx, controlstatedb.SaveNativePeerPairLegClaimParams{
		PairID: pair.ID, ConnectionSlot: int16(proof.ConnectionSlot), RequestedAt: timestamptz(requestAt),
		NonceDigest: nonce[:], SourceIp: observedSource, RelayID: lease.RelayID, RelayRunID: lease.RelayRunID,
		RelayLeaseRevision: int64(lease.RelayLeaseRevision),
	}); err != nil {
		return result, publisherLookupError(err, ErrServiceAccess)
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
	result = NativePeerPairLegClaim{PairID: pair.ID, DeliveryGeneration: pair.DeliveryGeneration,
		ConnectionSlot: proof.ConnectionSlot, Key: base64.RawURLEncoding.EncodeToString(secret), SourceIP: observedSource, ExpiresAt: deadline}
	if err = tx.Commit(ctx); err != nil {
		return NativePeerPairLegClaim{}, err
	}
	return result, nil
}

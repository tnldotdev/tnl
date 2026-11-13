package state

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math"
	"time"

	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/policy/visitorscope"
	"github.com/tnldotdev/tnl/internal/security/visitortoken"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

type ConnectorPeerPairRebindRequest struct {
	Proof     tunnelv1.ConnectorPeerPairRebindProof
	Source    VisitorTokenSource
	Signature []byte
}

type ConnectorPeerPairRebindState struct {
	Active, Pending              *ConnectorPeerPair
	HighWaterGeneration          int64
	PendingUntil                 time.Time
	ReadyRelays                  []ConnectorPeerPairRelay
	OperationID, OperationStatus string
	OperationGeneration          int64
}

func (ConnectorPeerPairRebindState) String() string   { return "connector network binding state" }
func (ConnectorPeerPairRebindState) GoString() string { return "connector network binding state" }

func (d *Database) RebindConnectorPeerPair(ctx context.Context, serviceID, pairID string, r ConnectorPeerPairRebindRequest, now time.Time) (result ConnectorPeerPairRebindState, retErr error) {
	clock := newAuthorizationClock(now)
	p := r.Proof
	message, err := p.Message()
	requestAt := p.RequestedAt.UTC().Truncate(time.Microsecond)
	if err != nil || p.ServiceID != serviceID || p.PairID != pairID || now.IsZero() || d.storageKey == nil || len(r.Signature) != ed25519.SignatureSize ||
		requestAt.After(now.Add(5*time.Second)) || !requestAt.Add(5*time.Minute).After(now) {
		return result, ErrServiceAccess
	}
	switch r.Source.(type) {
	case DeviceTokenSource, WorkloadTokenSource, RegisteredKeyTokenSource:
	default:
		return result, ErrServiceAccess
	}
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return result, err
	}
	defer rollback(ctx, tx, "rebind connector peer", &retErr)()
	authority, err := d.visitorAuthorityForSource(ctx, tx, visitorscope.Scope{Kind: visitorscope.Service, ID: serviceID}, r.Source, clock)
	if err != nil {
		return result, err
	}
	subject, err := visitortoken.ConnectorSubject(authority.Permission.Subject)
	if err != nil || subject != p.Subject || len(authority.PublicKey) != ed25519.PublicKeySize || !ed25519.Verify(authority.PublicKey, message, r.Signature) {
		return result, ErrServiceAccess
	}
	q := controlstatedb.New(tx)
	run, err := q.LockServiceRun(ctx, controlstatedb.LockServiceRunParams{ID: p.ServiceRunID, ServiceID: serviceID})
	if err != nil {
		return result, publisherLookupError(err, ErrServiceAccess)
	}
	pair, err := q.GetConnectorPeerPairForOwner(ctx, controlstatedb.GetConnectorPeerPairForOwnerParams{SubjectKind: subject.Kind, SubjectID: connectorPairSubjectID(subject), ServiceRunID: run.ID, OwnerKey: p.IdempotencyKey})
	if err != nil {
		return result, publisherLookupError(err, ErrServiceAccess)
	}
	if pair.ID != pairID || pair.RunNumber != p.RunNumber || pair.PublisherIdentityID != p.PublisherIdentityID || pair.TrustRevision != p.TrustRevision {
		return result, ErrServiceAccess
	}
	if subject.Kind == tunnelv1.VisitorHumanDevice {
		principal, _ := ctx.Value(controlPrincipalKey{}).(ControlPrincipal)
		if !pair.ParentControlSessionID.Valid || principal.SessionID != pair.ParentControlSessionID.String {
			return result, ErrServiceAccess
		}
	}
	_, _, until, err := d.connectorPeerSessionAuthority(ctx, tx, run, pair, clock.current())
	if err != nil {
		return result, err
	}
	until = minTime(until, minTime(authority.ConnectorUntil, authority.Permission.ExpiresAt))
	until = minTime(until, requestAt.Add(5*time.Minute))
	authorityUntil := until
	pair, err = expireConnectorPeerPending(ctx, tx, pair, clock.current())
	if err != nil {
		return result, err
	}
	digest := sha256.Sum256(message)
	ready, err := connectorPairReadySelection(ctx, tx, run.ID, serviceID, run.RunNumber, clock.current())
	if err != nil {
		return result, err
	}
	switch p.Phase {
	case "inspect":
	case "prepare":
		if pair.RebindOperationID == p.OperationID {
			if !bytes.Equal(pair.RebindPrepareDigest, digest[:]) {
				return result, ErrServiceConflict
			}
			break
		}
		if pair.RebindStatus.String == "pending" || p.ExpectedGeneration != pair.HighWaterGeneration || pair.HighWaterGeneration == math.MaxInt64 {
			return result, ErrServiceConflict
		}
		if ready == nil || run.State != "ready" {
			return result, ErrConnectorPeerBindingStale
		}
		var expected [2]ConnectorPeerPairRelay
		for slot, relay := range p.ExpectedRelays {
			expected[slot] = rebindStateRelay(relay)
		}
		if expected != ready.Relays {
			return result, ErrConnectorPeerBindingStale
		}
		leases, err := q.ReadConnectorPeerObservationRelayBounds(ctx, controlstatedb.ReadConnectorPeerObservationRelayBoundsParams{ServiceRunID: run.ID, ServiceID: serviceID, Now: timestamptz(clock.current())})
		if err != nil {
			return result, err
		}
		if len(leases) != 2 {
			return result, ErrConnectorPeerBindingStale
		}
		until = minTime(until, minTime(leases[0].LeaseExpiresAt.Time, leases[1].LeaseExpiresAt.Time))
		secret, challenge := make([]byte, 32), make([]byte, 32)
		if _, err = rand.Read(secret); err != nil {
			return result, err
		}
		defer clear(secret)
		if _, err = rand.Read(challenge); err != nil {
			return result, err
		}
		sealed, err := d.storageKey.Seal(connectorPeerPairKeyContext(pair.ID), secret)
		if err != nil {
			return result, err
		}
		hash := sha256.Sum256(secret)
		slots, err := json.Marshal(ready.Relays)
		if err != nil {
			return result, err
		}
		generation := pair.HighWaterGeneration + 1
		pendingUntil := minTime(pair.ExpiresAt.Time, minTime(now.Add(10*time.Second), minTime(authority.ConnectorUntil, authority.Permission.ExpiresAt)))
		if _, err = tx.Exec(ctx, `INSERT INTO control.connector_peer_pending_bindings(pair_id,delivery_generation,operation_id,challenge,slots,key_ciphertext,key_digest,storage_key_id,created_at,pending_until)
			VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`, pair.ID, generation, p.OperationID, challenge, string(slots), sealed, hash[:], d.storageKey.CurrentID(), now, pendingUntil); err != nil {
			return result, err
		}
		if _, err = tx.Exec(ctx, `UPDATE control.connector_peer_pairs SET high_water_generation=$2,rebind_operation_id=$3,rebind_generation=$2,rebind_status='pending',
			rebind_prepare_digest=$4,rebind_activate_digest=NULL,rebind_abort_digest=NULL WHERE id=$1`, pair.ID, generation, p.OperationID, digest[:]); err != nil {
			return result, err
		}
		until = minTime(until, pendingUntil)
	case "activate":
		if pair.RebindOperationID != p.OperationID || pair.RebindGeneration.Int64 != p.ExpectedGeneration {
			return result, ErrServiceConflict
		}
		if pair.RebindStatus.String == "active" {
			if !bytes.Equal(pair.RebindActivateDigest, digest[:]) {
				return result, ErrServiceConflict
			}
			break
		}
		if pair.RebindStatus.String != "pending" {
			return result, ErrServiceConflict
		}
		revision, _, bound, err := connectorPeerBindingRevision(ctx, tx, pair, p.ExpectedGeneration, clock.current())
		if err != nil {
			return result, err
		}
		if base64.RawURLEncoding.EncodeToString(revision.BindingChallenge) != p.BindingChallenge {
			return result, ErrServiceAccess
		}
		binding, err := d.connectorPeerPairBinding(ctx, tx, run, revision, clock.current())
		if err != nil {
			return result, err
		}
		if !binding.claimsCurrent || !revision.PublisherPreparedUntil.Valid || !revision.PublisherPreparedUntil.Time.After(clock.current()) ||
			!revision.PublisherProvedUntil.Valid || !revision.PublisherProvedUntil.Time.After(clock.current()) || len(revision.PublisherProofDigest) != sha256.Size {
			return result, ErrServiceAccess
		}
		if err = d.verifyConnectorPeerPathProofs(revision, p.PathProofs, 0); err != nil {
			return result, err
		}
		until = minTime(until, minTime(bound, minTime(binding.recheckAt, revision.PublisherProvedUntil.Time)))
		if _, err = tx.Exec(ctx, `UPDATE control.connector_peer_pairs SET slots=$2,delivery_generation=$3,key_ciphertext=$4,key_digest=$5,storage_key_id=$6,
			binding_operation_id=$7,binding_challenge=$8,publisher_prepared_until=$9,publisher_proved_until=$10,publisher_proof_digest=$11,
			rebind_status='active',rebind_activate_digest=$12 WHERE id=$1`, pair.ID, string(revision.Slots), revision.DeliveryGeneration, revision.KeyCiphertext, revision.KeyDigest,
			revision.StorageKeyID, revision.BindingOperationID, revision.BindingChallenge, revision.PublisherPreparedUntil, revision.PublisherProvedUntil, revision.PublisherProofDigest, digest[:]); err != nil {
			return result, err
		}
		if err = saveConnectorPeerAuditBinding(ctx, tx, revision, binding, binding.expiresAt); err != nil {
			return result, err
		}
		if _, err = tx.Exec(ctx, `UPDATE control.connector_peer_audit_bindings SET retired_at=COALESCE(retired_at,$3) WHERE pair_id=$1 AND delivery_generation<>$2`, pair.ID, revision.DeliveryGeneration, now); err != nil {
			return result, err
		}
		if _, err = tx.Exec(ctx, `DELETE FROM control.connector_peer_pair_leg_claims WHERE pair_id=$1 AND delivery_generation<>$2`, pair.ID, revision.DeliveryGeneration); err != nil {
			return result, err
		}
		if _, err = tx.Exec(ctx, `DELETE FROM control.connector_peer_pending_bindings WHERE pair_id=$1`, pair.ID); err != nil {
			return result, err
		}
	case "abort":
		if pair.RebindOperationID != p.OperationID || pair.RebindGeneration.Int64 != p.ExpectedGeneration {
			return result, ErrServiceConflict
		}
		if pair.RebindStatus.String == "aborted" {
			if !bytes.Equal(pair.RebindAbortDigest, digest[:]) {
				return result, ErrServiceConflict
			}
			break
		}
		if pair.RebindStatus.String != "pending" {
			return result, ErrServiceConflict
		}
		if _, err = tx.Exec(ctx, `DELETE FROM control.connector_peer_pair_leg_claims WHERE pair_id=$1 AND delivery_generation=$2`, pair.ID, p.ExpectedGeneration); err != nil {
			return result, err
		}
		if _, err = tx.Exec(ctx, `DELETE FROM control.connector_peer_pending_bindings WHERE pair_id=$1`, pair.ID); err != nil {
			return result, err
		}
		if _, err = tx.Exec(ctx, `UPDATE control.connector_peer_pairs SET rebind_status='aborted',rebind_abort_digest=$2 WHERE id=$1`, pair.ID, digest[:]); err != nil {
			return result, err
		}
	}
	pair, err = q.LockConnectorPeerPairForLegClaim(ctx, pair.ID)
	if err != nil {
		return result, err
	}
	active, err := d.connectorPeerSnapshot(ctx, tx, pair, subject, now, false, authorityUntil)
	if err != nil {
		return result, err
	}
	if ready == nil || active.Relays != ready.Relays {
		active.BindingState = "suspended"
	}
	result.Active = &active
	result.HighWaterGeneration = pair.HighWaterGeneration
	result.ReadyRelays = []ConnectorPeerPairRelay{}
	if ready != nil {
		result.ReadyRelays = append(result.ReadyRelays, ready.Relays[:]...)
	}
	result.OperationID, result.OperationStatus, result.OperationGeneration = pair.RebindOperationID, pair.RebindStatus.String, pair.RebindGeneration.Int64
	if pair.RebindStatus.String == "pending" {
		revision, _, bound, err := connectorPeerBindingRevision(ctx, tx, pair, pair.RebindGeneration.Int64, clock.current())
		if err != nil {
			return ConnectorPeerPairRebindState{}, err
		}
		pending, err := d.connectorPeerSnapshot(ctx, tx, revision, subject, now, true, bound)
		if err != nil {
			return ConnectorPeerPairRebindState{}, err
		}
		result.Pending = &pending
		result.PendingUntil = bound
		until = minTime(until, bound)
	}
	if err = d.lockRegisteredVisitorAuthority(ctx, tx, r.Source, authority.Permission, clock); err != nil {
		return ConnectorPeerPairRebindState{}, err
	}
	if _, err = tx.Exec(ctx, "SET CONSTRAINTS ALL IMMEDIATE"); err != nil {
		return ConnectorPeerPairRebindState{}, err
	}
	if !until.After(clock.current()) {
		return ConnectorPeerPairRebindState{}, ErrServiceAccess
	}
	commit, stop := context.WithDeadline(ctx, clock.started.Add(until.Sub(now)))
	defer stop()
	if err = tx.Commit(commit); err != nil {
		return ConnectorPeerPairRebindState{}, err
	}
	if !until.After(clock.current()) {
		return ConnectorPeerPairRebindState{}, ErrServiceAccess
	}
	return result, nil
}

func rebindStateRelay(relay tunnelv1.ConnectorPeerPairRelay) ConnectorPeerPairRelay {
	return ConnectorPeerPairRelay{PublisherConnectionID: relay.PublisherConnectionID, AssignmentRevision: relay.AssignmentRevision, RelayAddress: relay.RelayAddress, TLSServerName: relay.TLSServerName,
		RelayLease: RelayLeaseIdentity{RelayServiceID: relay.RelayLease.RelayServiceID, RelayID: relay.RelayLease.RelayID, RelayRunID: relay.RelayLease.RelayRunID, RelayLeaseRevision: relay.RelayLease.RelayLeaseRevision}}
}

// path evidence authenticates the opposite endpoint, exact operation and revision.
// it grants no visitor permission and cannot substitute for current relay claims.
func (d *Database) verifyConnectorPeerPathProofs(pair controlstatedb.ControlConnectorPeerPair, proofs []tunnelv1.ConnectorPeerPairPathProof, role uint8) error {
	if len(proofs) != 2 {
		return ErrServiceAccess
	}
	encoded, err := d.connectorPeerSessionKey(pair)
	if err != nil {
		return err
	}
	secret, err := base64.RawURLEncoding.Strict().DecodeString(encoded)
	if err != nil {
		return ErrServiceAccess
	}
	defer clear(secret)
	var key [32]byte
	copy(key[:], secret)
	defer clear(key[:])
	for slot, proof := range proofs {
		if proof.ConnectionSlot != slot || proof.Validate() != nil {
			return ErrServiceAccess
		}
		nonce, _ := base64.RawURLEncoding.Strict().DecodeString(proof.ProbeNonce)
		challenge, err := tunnelv1.ConnectorPeerBindingProbe(pair.ID, pair.BindingOperationID, pair.DeliveryGeneration, base64.RawURLEncoding.EncodeToString(pair.BindingChallenge), role, uint8(slot), nonce)
		if err != nil {
			return ErrServiceAccess
		}
		frame, _ := base64.RawURLEncoding.Strict().DecodeString(proof.ReplyFrame)
		packet, err := tunnelv1.VerifyPeerPacketFrame(frame, key)
		if err != nil || packet.Kind != tunnelv1.PeerProbeReply || packet.Sender != 1-role || int(packet.Path) != slot || packet.BindingGeneration != uint64(pair.DeliveryGeneration) || !bytes.Equal(packet.Payload, challenge[:]) {
			return ErrServiceAccess
		}
	}
	return nil
}

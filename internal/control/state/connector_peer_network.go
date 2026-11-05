package state

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
)

var ErrConnectorPeerBindingStale = errors.New("connector network binding is stale")

func connectorPeerSessionKeyContext(id string) string { return "connector-peer-session/" + id }

func (d *Database) connectorPeerSessionKey(pair controlstatedb.ControlConnectorPeerPair) (string, error) {
	if len(pair.SessionKeyCiphertext) == 0 || !pair.SessionKeyStorageKeyID.Valid {
		return "", ErrServiceAccess
	}
	return d.connectorPeerSecret(pair.SessionKeyStorageKeyID.String, connectorPeerSessionKeyContext(pair.ID), pair.SessionKeyCiphertext, pair.SessionKeyDigest)
}

func (d *Database) connectorPeerSecret(keyID, scope string, ciphertext, digest []byte) (string, error) {
	secret, _, err := d.storageKey.Open(keyID, scope, ciphertext)
	if err != nil {
		return "", err
	}
	defer clear(secret)
	hash := sha256.Sum256(secret)
	if len(secret) != 32 || !bytes.Equal(hash[:], digest) {
		return "", ErrServiceAccess
	}
	return base64.RawURLEncoding.EncodeToString(secret), nil
}

// retained authority is independent of network readiness, but not of prior run
// readiness, the original parent, metadata, publisher grants, or absolute expiry.
func (d *Database) connectorPeerSessionAuthority(ctx context.Context, tx pgx.Tx, run controlstatedb.ControlServiceRun, pair controlstatedb.ControlConnectorPeerPair, now time.Time) (VisitorSubject, ed25519.PublicKey, time.Time, error) {
	if pair.ServiceID != run.ServiceID || pair.ServiceRunID != run.ID || pair.RunNumber != run.RunNumber || pair.PublisherIdentityID != run.PublisherIdentityID ||
		!pair.ExpiresAt.Time.After(now) || pair.LastAuthorizedAt.Time.After(now) || len(pair.SessionKeyCiphertext) == 0 ||
		!run.ReadyAt.Valid || !run.Healthy || !activeServiceRun(run, now) || !run.CertificateExpiresAt.Valid || !run.CertificateExpiresAt.Time.After(now) {
		return VisitorSubject{}, nil, time.Time{}, ErrServiceAccess
	}
	service, err := controlstatedb.New(tx).GetService(ctx, pair.ServiceID)
	if err != nil {
		return VisitorSubject{}, nil, time.Time{}, err
	}
	if !service.Enabled || service.DeletedAt.Valid || service.TrustRevision != pair.TrustRevision {
		return VisitorSubject{}, nil, time.Time{}, ErrServiceAccess
	}
	publisherUntil, err := connectorPeerPublisherAuthority(ctx, tx, run, now)
	if err != nil {
		return VisitorSubject{}, nil, time.Time{}, err
	}
	subject, key, subjectUntil, err := connectorPeerPairSubjectKey(ctx, tx, pair, now)
	return subject, key, minTime(pair.ExpiresAt.Time, minTime(publisherUntil, subjectUntil)), err
}

// the owner row is the active binding projection. only one pending row exists;
// callers retain the owner lock throughout projection, validation, and commit.
func connectorPeerBindingRevision(ctx context.Context, tx pgx.Tx, pair controlstatedb.ControlConnectorPeerPair, generation int64, now time.Time) (controlstatedb.ControlConnectorPeerPair, bool, time.Time, error) {
	if generation == pair.DeliveryGeneration {
		return pair, false, pair.ExpiresAt.Time, nil
	}
	pending, err := controlstatedb.New(tx).GetConnectorPeerPendingBinding(ctx, pair.ID)
	if err != nil {
		return pair, false, time.Time{}, publisherLookupError(err, ErrServiceAccess)
	}
	if pending.DeliveryGeneration != generation || !pending.PendingUntil.Time.After(now) || pair.RebindStatus.String != "pending" {
		return pair, false, time.Time{}, ErrServiceAccess
	}
	pair.DeliveryGeneration, pair.Slots = pending.DeliveryGeneration, pending.Slots
	pair.KeyCiphertext, pair.KeyDigest, pair.StorageKeyID = pending.KeyCiphertext, pending.KeyDigest, pending.StorageKeyID
	pair.BindingOperationID, pair.BindingChallenge = pending.OperationID, pending.Challenge
	pair.PublisherPreparedUntil, pair.PublisherProvedUntil, pair.PublisherProofDigest = pending.PublisherPreparedUntil, pending.PublisherProvedUntil, pending.PublisherProofDigest
	return pair, true, minTime(pair.ExpiresAt.Time, pending.PendingUntil.Time), nil
}

func expireConnectorPeerPending(ctx context.Context, tx pgx.Tx, pair controlstatedb.ControlConnectorPeerPair, now time.Time) (controlstatedb.ControlConnectorPeerPair, error) {
	if pair.RebindStatus.String != "pending" {
		return pair, nil
	}
	var expired bool
	err := tx.QueryRow(ctx, `SELECT pending_until<=$2 OR $3::timestamptz<=$2 FROM control.connector_peer_pending_bindings WHERE pair_id=$1`, pair.ID, now, pair.ExpiresAt.Time).Scan(&expired)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return pair, err
	}
	if !expired && err == nil {
		return pair, nil
	}
	if _, err := tx.Exec(ctx, `DELETE FROM control.connector_peer_pending_bindings WHERE pair_id=$1;
		`, pair.ID); err != nil {
		return pair, err
	}
	if _, err := tx.Exec(ctx, `DELETE FROM control.connector_peer_pair_leg_claims WHERE pair_id=$1 AND delivery_generation<>$2`, pair.ID, pair.DeliveryGeneration); err != nil {
		return pair, err
	}
	if _, err := tx.Exec(ctx, `UPDATE control.connector_peer_pairs SET rebind_status='expired' WHERE id=$1`, pair.ID); err != nil {
		return pair, err
	}
	return controlstatedb.New(tx).LockConnectorPeerPairForLegClaim(ctx, pair.ID)
}

func (d *Database) connectorPeerSnapshot(ctx context.Context, tx pgx.Tx, row controlstatedb.ControlConnectorPeerPair, subject VisitorSubject, now time.Time, pending bool, bound time.Time) (ConnectorPeerPair, error) {
	p := ConnectorPeerPair{ID: row.ID, ServiceID: row.ServiceID, ServiceRunID: row.ServiceRunID, PublisherIdentityID: row.PublisherIdentityID,
		Subject: subject, RunNumber: row.RunNumber, DeliveryGeneration: row.DeliveryGeneration, TrustRevision: row.TrustRevision,
		OperationID: row.BindingOperationID, BindingChallenge: base64.RawURLEncoding.EncodeToString(row.BindingChallenge), ObservedAt: now, ExpiresAt: bound, BindingState: "active"}
	if len(row.DeliveryID) != len(p.DeliveryID) || json.Unmarshal(row.Slots, &p.Relays) != nil {
		return ConnectorPeerPair{}, ErrServiceAccess
	}
	copy(p.DeliveryID[:], row.DeliveryID)
	var err error
	p.SessionKey, err = d.connectorPeerSessionKey(row)
	if err != nil {
		return ConnectorPeerPair{}, err
	}
	p.Key, err = d.connectorPeerSecret(row.StorageKeyID, connectorPeerPairKeyContext(row.ID), row.KeyCiphertext, row.KeyDigest)
	if err != nil {
		return ConnectorPeerPair{}, err
	}
	if row.PublisherPreparedUntil.Valid {
		p.PublisherPreparedUntil = minTime(row.PublisherPreparedUntil.Time, bound)
	}
	if row.PublisherProvedUntil.Valid {
		p.PublisherProvedUntil = minTime(row.PublisherProvedUntil.Time, bound)
	}
	if pending {
		p.BindingState = "prepared"
		if p.PublisherPreparedUntil.After(now) {
			p.BindingState = "installed"
		}
		if p.PublisherProvedUntil.After(now) {
			p.BindingState = "proved"
		}
	}
	claims, err := controlstatedb.New(tx).ReadConnectorPeerBindingClaims(ctx, controlstatedb.ReadConnectorPeerBindingClaimsParams{PairID: row.ID, DeliveryGeneration: row.DeliveryGeneration})
	if err != nil {
		return ConnectorPeerPair{}, err
	}
	if len(claims) == 2 && claims[0].SourceIp == claims[1].SourceIp {
		p.SourceIP = claims[0].SourceIp
	}
	return p, nil
}

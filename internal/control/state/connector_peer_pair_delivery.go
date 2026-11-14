package state

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/netip"
	"time"

	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

type ConnectorPeerPairDelivery struct {
	PairID, ServiceID, ServiceRunID, PublisherIdentityID         string
	RunNumber, DeliveryGeneration, TrustRevision                 int64
	PublicURLID, PublishRunID                                    string
	PublishRunNumber                                             int64
	Subject                                                      VisitorSubject
	DeliveryID                                                   [16]byte
	Key, SessionKey, OperationID, BindingChallenge, BindingState string
	SourceIP                                                     netip.Addr
	Relays                                                       [2]ConnectorPeerPairRelay
	ObservedAt, ExpiresAt                                        time.Time
}

func (ConnectorPeerPairDelivery) String() string   { return "connector peer pair delivery" }
func (ConnectorPeerPairDelivery) GoString() string { return "connector peer pair delivery" }

func (d *Database) DeliverConnectorPeerPair(ctx context.Context, serviceID, runID, pairID string, generation int64, token string, now time.Time) (ConnectorPeerPairDelivery, error) {
	return d.connectorPeerPairDelivery(ctx, connectorPeerPublisherSource{serviceID: serviceID, runID: runID, token: token}, pairID, generation, now, nil)
}

func (d *Database) DeliverPublicURLConnectorPeerPair(ctx context.Context, auth PublishRunAuthentication, pairID string, generation int64, now time.Time) (ConnectorPeerPairDelivery, error) {
	return d.connectorPeerPairDelivery(ctx, connectorPeerPublisherSource{publishRun: &auth}, pairID, generation, now, nil)
}

type ConnectorPeerPairPrepared struct {
	DeliveryID                           [16]byte
	DeliveryGeneration                   int64
	BindingExpiresAt                     time.Time
	Phase, OperationID, BindingChallenge string
	PathProofs                           []tunnelv1.ConnectorPeerPairPathProof
}

func (d *Database) ConfirmConnectorPeerPairPrepared(ctx context.Context, serviceID, runID, pairID, token string, prepared ConnectorPeerPairPrepared, now time.Time) error {
	_, err := d.connectorPeerPairDelivery(ctx, connectorPeerPublisherSource{serviceID: serviceID, runID: runID, token: token}, pairID, prepared.DeliveryGeneration, now, &prepared)
	return err
}

func (d *Database) ConfirmPublicURLConnectorPeerPairPrepared(ctx context.Context, auth PublishRunAuthentication, pairID string, prepared ConnectorPeerPairPrepared, now time.Time) error {
	_, err := d.connectorPeerPairDelivery(ctx, connectorPeerPublisherSource{publishRun: &auth}, pairID, prepared.DeliveryGeneration, now, &prepared)
	return err
}

// delivery and reports share the same transaction-local authority checks. a
// publisher must retain its existing in-memory owner; this cannot reconstruct it.
func (d *Database) connectorPeerPairDelivery(ctx context.Context, source connectorPeerPublisherSource, pairID string, generation int64, now time.Time, prepared *ConnectorPeerPairPrepared) (result ConnectorPeerPairDelivery, retErr error) {
	clock := newAuthorizationClock(now)
	if generation < 1 || pairID == "" || now.IsZero() || d.storageKey == nil {
		return result, ErrServiceAccess
	}
	if prepared != nil && (prepared.DeliveryID == [16]byte{} || !prepared.BindingExpiresAt.After(now) || prepared.Phase != "installed" && prepared.Phase != "proved") {
		return result, ErrServiceAccess
	}
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return result, err
	}
	defer rollback(ctx, tx, "deliver connector peer binding", &retErr)()
	q := controlstatedb.New(tx)
	publication, err := d.connectorPeerPublisherPublication(ctx, tx, source, clock.current())
	if err != nil {
		return result, err
	}
	pair, err := q.LockConnectorPeerPairForLegClaim(ctx, pairID)
	if err != nil {
		return result, publisherLookupError(err, ErrServiceAccess)
	}
	pair, pending, bound, err := connectorPeerBindingRevision(ctx, tx, pair, generation, clock.current())
	if err != nil {
		return result, err
	}
	binding, err := d.connectorPeerPublicationBinding(ctx, tx, publication, pair, clock.current())
	if err != nil {
		return result, err
	}
	until := minTime(bound, binding.recheckAt)
	if !binding.claimsCurrent || !until.After(clock.current()) || len(pair.DeliveryID) != 16 {
		return result, ErrServiceAccess
	}
	result = ConnectorPeerPairDelivery{PairID: pair.ID, ServiceID: pair.ServiceID, ServiceRunID: pair.ServiceRunID, PublisherIdentityID: pair.PublisherIdentityID,
		PublicURLID: pair.PublicURLID, PublishRunID: pair.PublishRunID, PublishRunNumber: pair.PublishRunNumber,
		RunNumber: pair.RunNumber, DeliveryGeneration: generation, TrustRevision: pair.TrustRevision, Subject: binding.subject, SourceIP: binding.source,
		Relays: binding.relays, ObservedAt: now, ExpiresAt: minTime(bound, binding.expiresAt), OperationID: pair.BindingOperationID,
		BindingChallenge: base64.RawURLEncoding.EncodeToString(pair.BindingChallenge), BindingState: "active"}
	copy(result.DeliveryID[:], pair.DeliveryID)
	if pending {
		result.BindingState = "prepared"
	}
	if prepared != nil {
		if prepared.DeliveryID != result.DeliveryID || prepared.BindingExpiresAt.After(result.ExpiresAt) || !prepared.BindingExpiresAt.After(clock.current()) {
			return ConnectorPeerPairDelivery{}, ErrServiceAccess
		}
		phase := prepared.Phase
		if prepared.OperationID != pair.BindingOperationID || prepared.BindingChallenge != result.BindingChallenge ||
			phase == "installed" && len(prepared.PathProofs) != 0 {
			return ConnectorPeerPairDelivery{}, ErrServiceAccess
		}
		if pair.PublisherPreparedUntil.Valid && !pair.PublisherPreparedUntil.Time.After(clock.current()) {
			return ConnectorPeerPairDelivery{}, ErrServiceAccess
		}
		reportUntil := minTime(prepared.BindingExpiresAt, result.ExpiresAt).UTC().Truncate(time.Microsecond)
		if phase == "proved" {
			if !pair.PublisherPreparedUntil.Valid || !pair.PublisherPreparedUntil.Time.After(clock.current()) || len(pair.BindingChallenge) != 32 {
				return ConnectorPeerPairDelivery{}, ErrServiceAccess
			}
			if err = d.verifyConnectorPeerPathProofs(pair, prepared.PathProofs, 1); err != nil {
				return ConnectorPeerPairDelivery{}, err
			}
			proofBytes, err := json.Marshal(prepared.PathProofs)
			if err != nil {
				return ConnectorPeerPairDelivery{}, err
			}
			digest := sha256.Sum256(proofBytes)
			if !bytes.Equal(pair.PublisherProofDigest, digest[:]) {
				provedUntil := minTime(now.Add(5*time.Second), minTime(reportUntil, pair.PublisherPreparedUntil.Time))
				if pending {
					_, err = tx.Exec(ctx, `UPDATE control.connector_peer_pending_bindings SET publisher_proved_until=$2,publisher_proof_digest=$3 WHERE pair_id=$1`, pairID, provedUntil, digest[:])
				} else {
					_, err = tx.Exec(ctx, `UPDATE control.connector_peer_pairs SET publisher_proved_until=$2,publisher_proof_digest=$3 WHERE id=$1`, pairID, provedUntil, digest[:])
				}
				if err != nil {
					return ConnectorPeerPairDelivery{}, err
				}
			}
		} else {
			if pending {
				_, err = tx.Exec(ctx, `UPDATE control.connector_peer_pending_bindings SET publisher_prepared_until=LEAST($3,GREATEST(publisher_prepared_until,$2)) WHERE pair_id=$1`, pairID, reportUntil, result.ExpiresAt)
			} else {
				_, err = tx.Exec(ctx, `UPDATE control.connector_peer_pairs SET publisher_prepared_until=LEAST($3,GREATEST(publisher_prepared_until,$2)) WHERE id=$1`, pairID, reportUntil, result.ExpiresAt)
			}
			if err != nil {
				return ConnectorPeerPairDelivery{}, err
			}
		}
		if !pending {
			if err = saveConnectorPeerAuditBinding(ctx, tx, pair, binding, reportUntil); err != nil {
				return ConnectorPeerPairDelivery{}, err
			}
		}
	} else {
		result.Key, err = d.connectorPeerSecret(pair.StorageKeyID, connectorPeerPairKeyContext(pair.ID), pair.KeyCiphertext, pair.KeyDigest)
		if err != nil {
			return ConnectorPeerPairDelivery{}, err
		}
		result.SessionKey, err = d.connectorPeerSessionKey(pair)
		if err != nil {
			return ConnectorPeerPairDelivery{}, err
		}
	}
	if _, err = tx.Exec(ctx, "SET CONSTRAINTS ALL IMMEDIATE"); err != nil {
		return ConnectorPeerPairDelivery{}, err
	}
	if !until.After(clock.current()) {
		return ConnectorPeerPairDelivery{}, ErrServiceAccess
	}
	commit, stop := context.WithDeadline(ctx, clock.started.Add(until.Sub(now)))
	defer stop()
	if err = tx.Commit(commit); err != nil {
		return ConnectorPeerPairDelivery{}, err
	}
	if !until.After(clock.current()) {
		return ConnectorPeerPairDelivery{}, ErrServiceAccess
	}
	return result, nil
}

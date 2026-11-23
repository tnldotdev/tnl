package state

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

type ConnectorPeerPairRetireRequest struct {
	Proof                   tunnelv1.ConnectorPeerPairRetireProof
	SessionProof, Signature []byte
}

func (ConnectorPeerPairRetireRequest) String() string {
	return "connector peer pair retirement request"
}
func (ConnectorPeerPairRetireRequest) GoString() string {
	return "connector peer pair retirement request"
}

type ConnectorPeerPairRetirementObservation struct {
	ObservedAt, RetiredAt, RetainedUntil time.Time
}

type ConnectorPeerPairRetirement struct {
	PairID, ServiceID, ServiceRunID, PublisherIdentityID string
	DeliveryID, IdempotencyKey                           string
	RunNumber, OwnerRevision                             int64
	Retirement                                           ConnectorPeerPairRetirementObservation
}

func connectorPeerPairUnretired(pair controlstatedb.ControlConnectorPeerPair) bool {
	return pair.OwnerRevision == 1 && !pair.RetiredAt.Valid && len(pair.RetireRequestDigest) == 0
}

func connectorPeerPairRetainedUntil(pair controlstatedb.ControlConnectorPeerPair) time.Time {
	if pair.ExpiresAt.Time.After(pair.ReplayFenceUntil.Time) {
		return pair.ExpiresAt.Time
	}
	return pair.ReplayFenceUntil.Time
}

// retained retirement facts remain readable after a team or service is deleted.
// lock the owner before the service without requiring current serving authority.
func lockConnectorPeerRetirementOwner(ctx context.Context, tx pgx.Tx, serviceID string) error {
	var team, guest pgtype.Text
	err := tx.QueryRow(ctx, `SELECT team_id,guest_id FROM control.services WHERE id=$1`, serviceID).Scan(&team, &guest)
	if err != nil {
		return publisherLookupError(err, ErrServiceAccess)
	}
	q := controlstatedb.New(tx)
	switch {
	case team.Valid && !guest.Valid:
		_, err = q.LockConnectorPeerRetirementTeam(ctx, team.String)
	case guest.Valid && !team.Valid:
		_, err = q.LockConnectorPeerRetirementGuest(ctx, guest.String)
	default:
		return ErrServiceAccess
	}
	return publisherLookupError(err, ErrServiceAccess)
}

// RetireConnectorPeerPair commits only an exact negative fact. snapshot signature
// and stable session MAC remain verifiable after parent or serving revocation.
func (d *Database) RetireConnectorPeerPair(ctx context.Context, serviceID, pairID string, r ConnectorPeerPairRetireRequest, now time.Time) (result ConnectorPeerPairRetirement, retErr error) {
	clock := newAuthorizationClock(now)
	p := r.Proof
	if now.IsZero() || d.storageKey == nil || p.ServiceID != serviceID || p.PairID != pairID ||
		len(r.Signature) != ed25519.SignatureSize || p.RequestedAt.After(now.Add(5*time.Second)) {
		return result, ErrServiceAccess
	}
	if _, err := p.Message(r.SessionProof); err != nil {
		return result, ErrServiceAccess
	}
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return result, err
	}
	defer rollback(ctx, tx, "retire connector peer pair", &retErr)()
	q := controlstatedb.New(tx)
	if err := lockConnectorPeerRetirementOwner(ctx, tx, serviceID); err != nil {
		return result, err
	}
	if _, err := q.LockService(ctx, serviceID); err != nil {
		return result, publisherLookupError(err, ErrServiceAccess)
	}
	run, err := q.LockServiceRun(ctx, controlstatedb.LockServiceRunParams{ID: p.ServiceRunID, ServiceID: serviceID})
	if err != nil {
		return result, publisherLookupError(err, ErrServiceAccess)
	}
	pair, err := q.LockConnectorPeerPairForLegClaim(ctx, pairID)
	if err != nil {
		return result, publisherLookupError(err, ErrServiceAccess)
	}
	// no parent, grant, certificate, policy, or credential lookup follows this lock.
	delivery, err := tunnelv1.ParsePeerDeliveryIdentifier(p.DeliveryID)
	if err != nil || pair.ServiceID != serviceID || pair.ServiceRunID != p.ServiceRunID || pair.RunNumber != p.RunNumber ||
		pair.PublisherIdentityID != p.PublisherIdentityID || run.RunNumber != p.RunNumber || run.PublisherIdentityID != p.PublisherIdentityID ||
		!run.StartedAt.Valid || !run.ReadyAt.Valid || pair.OwnerKey != p.IdempotencyKey || pair.IdempotencyKey != p.IdempotencyKey ||
		!bytes.Equal(pair.DeliveryID, delivery[:]) || p.VerifySignature(ed25519.PublicKey(pair.OwnerPublicKey), r.SessionProof, r.Signature) != nil {
		return result, ErrServiceAccess
	}
	until := connectorPeerPairRetainedUntil(pair)
	checked := clock.current()
	if !until.After(checked) || checked.Before(pair.LastAuthorizedAt.Time) ||
		!pair.SessionKeyStorageKeyID.Valid || len(pair.SessionKeyCiphertext) == 0 {
		return result, ErrServiceAccess
	}
	secret, _, err := d.storageKey.Open(pair.SessionKeyStorageKeyID.String, connectorPeerSessionKeyContext(pair.ID), pair.SessionKeyCiphertext)
	if err != nil {
		return result, err
	}
	defer clear(secret)
	sessionDigest := sha256.Sum256(secret)
	if len(secret) != sha256.Size || subtle.ConstantTimeCompare(sessionDigest[:], pair.SessionKeyDigest) != 1 ||
		p.VerifySessionProof(secret, r.SessionProof) != nil {
		return result, ErrServiceAccess
	}
	digest, err := p.RequestDigest(r.SessionProof, r.Signature)
	if err != nil {
		return result, ErrServiceAccess
	}
	if pair.RetiredAt.Valid {
		if pair.OwnerRevision != 2 || subtle.ConstantTimeCompare(pair.RetireRequestDigest, digest[:]) != 1 {
			return result, ErrServiceConflict
		}
	} else {
		requestAt := p.RequestedAt.UTC().Truncate(time.Microsecond)
		checked = clock.current()
		if !connectorPeerPairUnretired(pair) || requestAt.After(checked.Add(5*time.Second)) ||
			!requestAt.Add(5*time.Minute).After(checked) || !until.After(checked) {
			return result, ErrServiceAccess
		}
		pair, err = q.RetireConnectorPeerPair(ctx, controlstatedb.RetireConnectorPeerPairParams{
			ID: pairID, ServiceID: serviceID, ServiceRunID: p.ServiceRunID, RunNumber: p.RunNumber,
			PublisherIdentityID: p.PublisherIdentityID, DeliveryID: delivery[:], OwnerKey: p.IdempotencyKey,
			Now: timestamptz(checked.UTC().Truncate(time.Microsecond)), RetireRequestDigest: digest[:],
		})
		if err != nil {
			return result, publisherLookupError(err, ErrServiceAccess)
		}
		if _, err := q.DeleteConnectorPeerPendingBinding(ctx, pairID); err != nil {
			return result, err
		}
		if _, err := q.DeleteConnectorPeerPairLegClaims(ctx, pairID); err != nil {
			return result, err
		}
		if _, err := q.RetireConnectorPeerAuditBindings(ctx, controlstatedb.RetireConnectorPeerAuditBindingsParams{
			PairID: pairID, Now: pair.RetiredAt,
		}); err != nil {
			return result, err
		}
	}
	if _, err := tx.Exec(ctx, "SET CONSTRAINTS ALL IMMEDIATE"); err != nil {
		return result, err
	}
	if !until.After(clock.current()) {
		return result, ErrServiceAccess
	}
	commit, stop := context.WithDeadline(ctx, clock.started.Add(until.Sub(now)))
	defer stop()
	if err := tx.Commit(commit); err != nil {
		return result, err
	}
	observed := clock.current()
	if !until.After(observed) {
		return result, ErrServiceAccess
	}
	result = ConnectorPeerPairRetirement{PairID: pair.ID, ServiceID: serviceID, ServiceRunID: pair.ServiceRunID,
		PublisherIdentityID: pair.PublisherIdentityID, RunNumber: pair.RunNumber, OwnerRevision: pair.OwnerRevision,
		DeliveryID: p.DeliveryID, IdempotencyKey: pair.OwnerKey,
		Retirement: ConnectorPeerPairRetirementObservation{ObservedAt: observed, RetiredAt: pair.RetiredAt.Time, RetainedUntil: until}}
	return result, nil
}

// connectorPeerPairWrite requires the exact fenced row and preserves database
// errors independently of the denied mutation.
func connectorPeerPairWrite(count int64, err error) error {
	if err != nil {
		return err
	}
	if count != 1 {
		return ErrServiceAccess
	}
	return nil
}

// only an exact expected authority denial selects a negative-only projection.
// a joined denial plus database/cleanup failure is not negative evidence.
func connectorPeerAuthorityDenied(err error) bool {
	return err == ErrServiceAccess || err == ErrVisitorPermission || err == ErrWorkloadDenied ||
		err == ErrPublisherIdentity || err == ErrGuestTrialSpent || err == pgx.ErrNoRows
}

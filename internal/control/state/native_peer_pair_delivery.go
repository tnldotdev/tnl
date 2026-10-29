package state

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"net/netip"
	"time"

	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/policy/visitorscope"
)

// NativePeerPairDelivery is a local publisher binding, not permission to open
// an application stream. its key must stay with the exact run that requested it.
type NativePeerPairDelivery struct {
	PairID, ServiceID, ServiceRunID, PublisherIdentityID string
	RunNumber, DeliveryGeneration                        int64
	Subject                                              VisitorSubject
	DeliveryID                                           [16]byte
	Key                                                  string
	SourceIP                                             netip.Addr
	Relays                                               [2]NativePeerPairRelay
	ObservedAt, ExpiresAt                                time.Time
}

func (NativePeerPairDelivery) String() string   { return "native peer pair delivery" }
func (NativePeerPairDelivery) GoString() string { return "native peer pair delivery" }

// DeliverNativePeerPair reads only the already claimed delivery. the run lock
// serializes assignment changes and pair replacement; no key is created here.
func (d *Database) DeliverNativePeerPair(ctx context.Context, serviceID, runID, pairID string, generation int64, token string, now time.Time) (result NativePeerPairDelivery, retErr error) {
	return d.nativePeerPairDelivery(ctx, serviceID, runID, pairID, generation, token, now, nil)
}

type NativePeerPairPrepared struct {
	DeliveryID         [16]byte
	DeliveryGeneration int64
	BindingExpiresAt   time.Time
}

// ConfirmNativePeerPairPrepared records only publisher-reported installation.
// it shares the delivery operation's exact current authority and source checks,
// and cannot extend either the pair or the installed binding's deadline.
func (d *Database) ConfirmNativePeerPairPrepared(ctx context.Context, serviceID, runID, pairID, token string, prepared NativePeerPairPrepared, now time.Time) error {
	if prepared.DeliveryID == [16]byte{} || !prepared.BindingExpiresAt.After(now) {
		return ErrServiceAccess
	}
	_, err := d.nativePeerPairDelivery(ctx, serviceID, runID, pairID, prepared.DeliveryGeneration, token, now, &prepared)
	return err
}

func (d *Database) nativePeerPairDelivery(ctx context.Context, serviceID, runID, pairID string, generation int64, token string, now time.Time, prepared *NativePeerPairPrepared) (result NativePeerPairDelivery, retErr error) {
	started := time.Now()
	checkedNow := func() time.Time { return now.Add(time.Since(started)) }
	if generation < 1 || pairID == "" || now.IsZero() || d.storageKey == nil {
		return result, ErrServiceAccess
	}
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return result, err
	}
	defer rollback(ctx, tx, "deliver native peer pair", &retErr)()
	if err = lockServiceAdmission(ctx, tx, serviceID); err != nil {
		return result, err
	}
	q := controlstatedb.New(tx)
	run, err := serviceRunAuthorization(ctx, tx, q, serviceID, runID, token, checkedNow())
	if err != nil {
		return result, err
	}
	if _, err = lockVisitorResource(ctx, tx, visitorscope.Scope{Kind: visitorscope.Service, ID: serviceID}, checkedNow()); err != nil {
		return result, err
	}
	pair, err := q.LockNativePeerPairForLegClaim(ctx, pairID)
	if err != nil {
		return result, publisherLookupError(err, ErrServiceAccess)
	}
	if pair.DeliveryGeneration != generation {
		return result, ErrServiceAccess
	}
	binding, err := d.nativePeerPairBinding(ctx, tx, run, pair, checkedNow())
	if err != nil {
		return NativePeerPairDelivery{}, err
	}
	if !binding.claimsCurrent || !binding.recheckAt.After(checkedNow()) || len(pair.DeliveryID) != len(result.DeliveryID) {
		return NativePeerPairDelivery{}, ErrServiceAccess
	}
	result.Subject, result.SourceIP, result.ExpiresAt = binding.subject, binding.source, binding.expiresAt
	copy(result.DeliveryID[:], pair.DeliveryID)
	if result.DeliveryID == [16]byte{} {
		return NativePeerPairDelivery{}, ErrServiceAccess
	}
	if prepared != nil {
		if prepared.DeliveryID != result.DeliveryID || prepared.BindingExpiresAt.After(result.ExpiresAt) || !prepared.BindingExpiresAt.After(checkedNow()) {
			return NativePeerPairDelivery{}, ErrServiceAccess
		}
		until := prepared.BindingExpiresAt
		if pair.PublisherPreparedUntil.Valid && pair.PublisherPreparedUntil.Time.After(until) {
			until = pair.PublisherPreparedUntil.Time
		}
		until = minTime(until, result.ExpiresAt).UTC().Truncate(time.Microsecond)
		reportChanged := !pair.PublisherPreparedUntil.Valid || !until.Equal(pair.PublisherPreparedUntil.Time)
		if reportChanged {
			count, err := q.ConfirmNativePeerPairPrepared(ctx, controlstatedb.ConfirmNativePeerPairPreparedParams{ID: pairID,
				DeliveryGeneration: generation, BindingExpiresAt: timestamptz(prepared.BindingExpiresAt),
				AuthorityExpiresAt: timestamptz(result.ExpiresAt), Now: timestamptz(checkedNow())})
			if err != nil || count != 1 {
				return NativePeerPairDelivery{}, publisherLookupError(err, ErrServiceAccess)
			}
		}
	} else {
		secret, _, err := d.storageKey.Open(pair.StorageKeyID, nativePeerPairKeyContext(pair.ID), pair.KeyCiphertext)
		if err != nil {
			return NativePeerPairDelivery{}, err
		}
		defer clear(secret)
		digest := sha256.Sum256(secret)
		if !bytes.Equal(digest[:], pair.KeyDigest) {
			return NativePeerPairDelivery{}, ErrServiceAccess
		}
		result.Key = base64.RawURLEncoding.EncodeToString(secret)
	}
	result.PairID, result.ServiceID, result.ServiceRunID, result.PublisherIdentityID = pair.ID, serviceID, runID, run.PublisherIdentityID
	result.RunNumber, result.DeliveryGeneration, result.Relays = run.RunNumber, generation, binding.relays
	result.ObservedAt = now
	if !binding.recheckAt.After(checkedNow()) {
		return NativePeerPairDelivery{}, ErrServiceAccess
	}
	if err = tx.Commit(ctx); err != nil {
		return NativePeerPairDelivery{}, err
	}
	if !binding.recheckAt.After(checkedNow()) {
		return NativePeerPairDelivery{}, ErrServiceAccess
	}
	return result, nil
}

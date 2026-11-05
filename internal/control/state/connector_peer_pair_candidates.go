package state

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
)

// ConnectorPeerPairCandidate identifies background preparation work. it contains
// neither a key nor authority to deliver packets or admit an application.
type ConnectorPeerPairCandidate struct {
	PairID             string
	DeliveryGeneration int64
	OwnerAuthority     *ConnectorPeerPairOwnerAuthority
}

type ConnectorPeerPairOwnerAuthority struct {
	ObservedAt, ExpiresAt time.Time
}

type ConnectorPeerPairCandidates struct {
	Items     []ConnectorPeerPairCandidate
	NextAfter string
}

// ListConnectorPeerPairs authenticates the exact run token and bounds each read.
// an installed owner's optional authority observation rechecks its original
// subject and parent independently of delivery. listing renews nothing and never
// discloses a subject, key, or application permission.
func (d *Database) ListConnectorPeerPairs(ctx context.Context, serviceID, runID, after, token string, now time.Time) (result ConnectorPeerPairCandidates, retErr error) {
	clock := newAuthorizationClock(now)
	if now.IsZero() || after != "" && !opaqueid.Valid(after, "cpp_") {
		return result, ErrServiceAccess
	}
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return result, err
	}
	defer rollback(ctx, tx, "list connector peer pairs", &retErr)()
	if err = lockServiceAdmission(ctx, tx, serviceID); err != nil {
		return result, err
	}
	q := controlstatedb.New(tx)
	run, err := serviceRunAuthorization(ctx, tx, q, serviceID, runID, token, clock.current())
	if err != nil {
		return result, err
	}
	// a starting or temporarily unhealthy run can reconcile hints. only the
	// independent delivery operation requires ready claims and a certificate.
	if _, err = q.GetServiceRunPublisherIdentity(ctx, controlstatedb.GetServiceRunPublisherIdentityParams{
		ID: run.ID, ServiceID: serviceID, RunNumber: run.RunNumber, PublisherIdentityID: run.PublisherIdentityID,
		PublisherGrantID: run.PublisherGrantID, PublisherKeyID: run.PublisherKeyID, Now: timestamptz(clock.current()),
	}); err != nil {
		return result, publisherLookupError(err, ErrServiceAccess)
	}
	rows, err := q.ListConnectorPeerPairCandidates(ctx, controlstatedb.ListConnectorPeerPairCandidatesParams{
		ServiceID: serviceID, ServiceRunID: runID, RunNumber: run.RunNumber,
		PublisherIdentityID: run.PublisherIdentityID, Now: timestamptz(now), AfterID: after,
	})
	if err != nil {
		return result, err
	}
	result.Items = make([]ConnectorPeerPairCandidate, 0, min(len(rows), 64))
	until := run.PublisherExpiresAt.Time
	for _, row := range rows[:min(len(rows), 64)] {
		candidate := ConnectorPeerPairCandidate{PairID: row.ID, DeliveryGeneration: row.DeliveryGeneration}
		pair, err := q.LockConnectorPeerPairForLegClaim(ctx, row.ID)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return ConnectorPeerPairCandidates{}, err
		}
		if err == nil && pair.PublisherPreparedUntil.Valid {
			_, _, bound, err := d.connectorPeerSessionAuthority(ctx, tx, run, pair, clock.current())
			if err == nil {
				candidate.OwnerAuthority = &ConnectorPeerPairOwnerAuthority{ObservedAt: now, ExpiresAt: bound}
				until = minTime(until, bound)
			} else if !errors.Is(err, ErrServiceAccess) && !errors.Is(err, ErrVisitorPermission) && !errors.Is(err, ErrWorkloadDenied) {
				return ConnectorPeerPairCandidates{}, err
			}
		}
		result.Items = append(result.Items, candidate)
	}
	if len(rows) > 64 {
		result.NextAfter = result.Items[len(result.Items)-1].PairID
	}
	if !until.After(clock.current()) {
		return ConnectorPeerPairCandidates{}, ErrServiceAccess
	}
	commit, stop := context.WithDeadline(ctx, clock.started.Add(until.Sub(now)))
	defer stop()
	if err = tx.Commit(commit); err != nil {
		return ConnectorPeerPairCandidates{}, err
	}
	if !until.After(clock.current()) {
		return ConnectorPeerPairCandidates{}, ErrServiceAccess
	}
	return result, nil
}

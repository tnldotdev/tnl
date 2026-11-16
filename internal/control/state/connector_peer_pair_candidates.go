package state

import (
	"context"
	"crypto/subtle"
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
	OwnerRevision      int64
	Retired            bool
	Retirement         *ConnectorPeerPairRetirementObservation
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
	digest, err := serviceRunCredentialDigest(runID, token)
	if err != nil {
		return result, err
	}
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return result, err
	}
	defer rollback(ctx, tx, "list connector peer pairs", &retErr)()
	q := controlstatedb.New(tx)
	service, err := lockConnectorPeerRetirementScope(ctx, tx, serviceID)
	if err != nil {
		return result, err
	}
	ownerCurrent := true
	if service.TeamID.Valid {
		if err := tx.QueryRow(ctx, `SELECT deleted_at IS NULL FROM control.teams WHERE id=$1`, service.TeamID.String).Scan(&ownerCurrent); err != nil {
			return result, err
		}
	}
	run, err := q.LockServiceRun(ctx, controlstatedb.LockServiceRunParams{ID: runID, ServiceID: serviceID})
	if err != nil {
		return result, publisherLookupError(err, ErrServiceAccess)
	}
	binding, err := checkedServiceRunBinding(serviceID, runID, run.RunNumber)
	if err != nil || !binding.matches(run) || !run.StartedAt.Valid || subtle.ConstantTimeCompare(digest[:], run.RunTokenDigest) != 1 {
		return result, ErrServiceAccess
	}
	// authorize positive hints before taking any pair lock. a known serving
	// denial permits only retained negative facts, never a fabricated retirement.
	includeCandidates := ownerCurrent && service.Enabled && !service.DeletedAt.Valid
	until := run.PublisherExpiresAt.Time
	if includeCandidates {
		_, err = d.validateServiceRunAuthorization(ctx, tx, q, serviceID, runID, run, digest, clock)
		if err == nil {
			_, err = q.GetServiceRunPublisherIdentity(ctx, controlstatedb.GetServiceRunPublisherIdentityParams{
				ID: run.ID, ServiceID: serviceID, RunNumber: run.RunNumber, PublisherIdentityID: run.PublisherIdentityID,
				PublisherGrantID: run.PublisherGrantID, PublisherKeyID: run.PublisherKeyID, Now: timestamptz(clock.current()),
			})
		}
		if err != nil {
			if !connectorPeerAuthorityDenied(err) {
				return result, err
			}
			includeCandidates = false
		} else {
			permissionUntil, err := serviceRunPublisherPermission(ctx, tx, run, clock.current())
			if err != nil {
				if !connectorPeerAuthorityDenied(err) {
					return result, err
				}
				includeCandidates = false
			} else if permissionUntil.Valid {
				until = minTime(until, permissionUntil.Time)
			}
		}
	}
	retained := func() (bool, error) {
		return q.HasRetainedConnectorPeerPair(ctx, controlstatedb.HasRetainedConnectorPeerPairParams{
			ServiceID: serviceID, ServiceRunID: runID, RunNumber: run.RunNumber,
			PublisherIdentityID: run.PublisherIdentityID, Now: timestamptz(clock.current()),
		})
	}
	if !includeCandidates {
		found, err := retained()
		if err != nil {
			return result, err
		}
		if !found {
			return result, ErrServiceAccess
		}
		until = time.Time{}
	}
	rows, err := q.ListConnectorPeerPairCandidates(ctx, controlstatedb.ListConnectorPeerPairCandidatesParams{
		ServiceID: serviceID, ServiceRunID: runID, RunNumber: run.RunNumber,
		PublisherIdentityID: run.PublisherIdentityID, Now: timestamptz(clock.current()), AfterID: after, IncludeCandidates: includeCandidates,
	})
	if err != nil {
		return result, err
	}
	result.Items = make([]ConnectorPeerPairCandidate, 0, min(len(rows), 64))
	for _, row := range rows[:min(len(rows), 64)] {
		candidate := ConnectorPeerPairCandidate{PairID: row.ID, DeliveryGeneration: row.DeliveryGeneration, OwnerRevision: row.OwnerRevision}
		if row.RetiredAt.Valid {
			observed := clock.current()
			if row.OwnerRevision != 2 {
				return ConnectorPeerPairCandidates{}, ErrServiceAccess
			}
			if !row.RetainedUntil.Time.After(observed) {
				continue
			}
			candidate.Retired = true
			candidate.Retirement = &ConnectorPeerPairRetirementObservation{
				ObservedAt: observed, RetiredAt: row.RetiredAt.Time, RetainedUntil: row.RetainedUntil.Time}
			if !includeCandidates && (until.IsZero() || row.RetainedUntil.Time.Before(until)) {
				until = row.RetainedUntil.Time
			}
			result.Items = append(result.Items, candidate)
			continue
		}
		if !includeCandidates || row.OwnerRevision != 1 {
			return ConnectorPeerPairCandidates{}, ErrServiceAccess
		}
		pair, err := q.LockConnectorPeerPairForLegClaim(ctx, row.ID)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return ConnectorPeerPairCandidates{}, err
		}
		if err == nil && connectorPeerPairUnretired(pair) && pair.PublisherPreparedUntil.Valid {
			_, _, bound, err := d.connectorPeerSessionAuthority(ctx, tx, run, pair, clock.current())
			if err == nil {
				candidate.OwnerAuthority = &ConnectorPeerPairOwnerAuthority{ObservedAt: now, ExpiresAt: minTime(bound, now.Add(5*time.Minute))}
			} else if !connectorPeerAuthorityDenied(err) {
				return ConnectorPeerPairCandidates{}, err
			}
		}
		result.Items = append(result.Items, candidate)
	}
	if len(rows) > 64 && len(result.Items) == 64 {
		result.NextAfter = result.Items[len(result.Items)-1].PairID
	}
	if includeCandidates && !until.After(clock.current()) {
		return ConnectorPeerPairCandidates{}, ErrServiceAccess
	}
	if !includeCandidates {
		found, err := retained()
		if err != nil {
			return ConnectorPeerPairCandidates{}, err
		}
		if !found {
			return ConnectorPeerPairCandidates{}, ErrServiceAccess
		}
	}
	commit := ctx
	if !until.IsZero() {
		var stop context.CancelFunc
		commit, stop = context.WithDeadline(ctx, clock.started.Add(until.Sub(now)))
		defer stop()
	}
	if err = tx.Commit(commit); err != nil {
		return ConnectorPeerPairCandidates{}, err
	}
	if includeCandidates && !until.After(clock.current()) {
		return ConnectorPeerPairCandidates{}, ErrServiceAccess
	}
	// an individual owner may expire while a later candidate waits for a row
	// lock. drop only its optional observation, not the publisher's independently
	// authorized listing or its healthy siblings. no observation renews authority.
	observed := clock.current()
	items := result.Items[:0]
	for _, candidate := range result.Items {
		if candidate.Retirement != nil && !candidate.Retirement.RetainedUntil.After(observed) {
			result.NextAfter = ""
			continue
		}
		if candidate.OwnerAuthority != nil && !candidate.OwnerAuthority.ExpiresAt.After(observed) {
			candidate.OwnerAuthority = nil
		}
		items = append(items, candidate)
	}
	result.Items = items
	return result, nil
}

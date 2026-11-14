package state

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/policy/visitorscope"
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
	return d.listConnectorPeerPairs(ctx, connectorPeerPublisherSource{serviceID: serviceID, runID: runID, token: token}, after, now)
}

func (d *Database) ListPublicURLConnectorPeerPairs(ctx context.Context, auth PublishRunAuthentication, after string, now time.Time) (ConnectorPeerPairCandidates, error) {
	return d.listConnectorPeerPairs(ctx, connectorPeerPublisherSource{publishRun: &auth}, after, now)
}

func (d *Database) listConnectorPeerPairs(ctx context.Context, source connectorPeerPublisherSource, after string, now time.Time) (result ConnectorPeerPairCandidates, retErr error) {
	clock := newAuthorizationClock(now)
	if now.IsZero() || after != "" && !opaqueid.Valid(after, "cpp_") {
		return result, ErrServiceAccess
	}
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return result, err
	}
	defer rollback(ctx, tx, "list connector peer pairs", &retErr)()
	q := controlstatedb.New(tx)
	run, err := d.connectorPeerCandidateRun(ctx, tx, source, clock.current())
	if err != nil {
		return result, err
	}
	selection := run.selection
	selection.Now, selection.AfterID = timestamptz(now), after
	rows, err := q.ListConnectorPeerPairCandidates(ctx, selection)
	if err != nil {
		return result, err
	}
	result.Items = make([]ConnectorPeerPairCandidate, 0, min(len(rows), 64))
	until := run.until
	for _, row := range rows[:min(len(rows), 64)] {
		candidate := ConnectorPeerPairCandidate{PairID: row.ID, DeliveryGeneration: row.DeliveryGeneration}
		pair, err := q.LockConnectorPeerPairForLegClaim(ctx, row.ID)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return ConnectorPeerPairCandidates{}, err
		}
		if err == nil && pair.PublisherPreparedUntil.Valid {
			bound, err := d.connectorPeerCandidateOwner(ctx, tx, run, pair, clock.current())
			if err == nil {
				candidate.OwnerAuthority = &ConnectorPeerPairOwnerAuthority{ObservedAt: now, ExpiresAt: bound}
			} else if !errors.Is(err, ErrServiceAccess) && !errors.Is(err, ErrVisitorPermission) && !errors.Is(err, ErrWorkloadDenied) && !errors.Is(err, ErrPublisherIdentity) {
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
	// an individual owner may expire while a later candidate waits for a row
	// lock. drop only its optional observation, not the publisher's independently
	// authorized listing or its healthy siblings. no observation renews authority.
	observed := clock.current()
	for index := range result.Items {
		candidate := &result.Items[index]
		if candidate.OwnerAuthority != nil && !candidate.OwnerAuthority.ExpiresAt.After(observed) {
			candidate.OwnerAuthority = nil
		}
	}
	return result, nil
}

// retain the actual authenticated run for optional observations. a hint alone
// is not a serving projection and must not depend on healthy/ready connections.
type connectorPeerCandidateRun struct {
	selection controlstatedb.ListConnectorPeerPairCandidatesParams
	service   controlstatedb.ControlServiceRun
	until     time.Time
}

func (d *Database) connectorPeerCandidateRun(ctx context.Context, tx pgx.Tx, source connectorPeerPublisherSource, now time.Time) (result connectorPeerCandidateRun, err error) {
	q := controlstatedb.New(tx)
	if source.publishRun != nil {
		if source.serviceID != "" || source.runID != "" || source.token != "" {
			return result, ErrServiceAccess
		}
		auth := *source.publishRun
		if _, err = lockVisitorResource(ctx, tx, visitorscope.Scope{Kind: visitorscope.PublicURL, ID: auth.PublicURLID}, now); err != nil {
			return result, err
		}
		url, run, err := lockAuthenticatedPublishRun(ctx, q, auth, now)
		if err != nil {
			return result, err
		}
		result.until, err = d.connectorPublicURLPublisherIdentity(ctx, tx, url, run, now)
		if err != nil {
			return result, err
		}
		result.selection = controlstatedb.ListConnectorPeerPairCandidatesParams{
			PublicURLID: run.PublicURLID, PublishRunID: run.ID, PublishRunNumber: run.PublishRunNumber,
			PublisherIdentityID: run.PublisherIdentityID.String,
		}
		return result, nil
	}
	if err = lockServiceAdmission(ctx, tx, source.serviceID); err != nil {
		return result, err
	}
	run, err := serviceRunAuthorization(ctx, tx, q, source.serviceID, source.runID, source.token, now)
	if err != nil {
		return result, err
	}
	if _, err = q.GetServiceRunPublisherIdentity(ctx, controlstatedb.GetServiceRunPublisherIdentityParams{
		ID: run.ID, ServiceID: source.serviceID, RunNumber: run.RunNumber, PublisherIdentityID: run.PublisherIdentityID,
		PublisherGrantID: run.PublisherGrantID, PublisherKeyID: run.PublisherKeyID, Now: timestamptz(now),
	}); err != nil {
		return result, publisherLookupError(err, ErrServiceAccess)
	}
	result.service, result.until = run, run.PublisherExpiresAt.Time
	result.selection = controlstatedb.ListConnectorPeerPairCandidatesParams{ServiceID: run.ServiceID,
		ServiceRunID: run.ID, RunNumber: run.RunNumber, PublisherIdentityID: run.PublisherIdentityID}
	return result, nil
}

func (d *Database) connectorPeerCandidateOwner(ctx context.Context, tx pgx.Tx, run connectorPeerCandidateRun, pair controlstatedb.ControlConnectorPeerPair, now time.Time) (time.Time, error) {
	selected := run.selection
	if selected.PublicURLID == "" {
		_, _, until, err := d.connectorPeerSessionAuthority(ctx, tx, run.service, pair, now)
		return until, err
	}
	publication, err := d.connectorPairPublication(ctx, tx, ConnectorPeerPairRequest{
		PublicURLID: selected.PublicURLID, PublishRunID: selected.PublishRunID, PublishRunNumber: selected.PublishRunNumber,
		PublisherIdentityID: selected.PublisherIdentityID, Action: "renew",
	}, now)
	if err != nil {
		return time.Time{}, err
	}
	_, _, until, err := d.connectorPeerPublicationAuthority(ctx, tx, publication, pair, now)
	return until, err
}

package state

import (
	"context"
	"time"

	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
)

// ConnectorPeerPairCandidate identifies background preparation work. it contains
// neither a key nor authority to deliver packets or admit an application.
type ConnectorPeerPairCandidate struct {
	PairID             string
	DeliveryGeneration int64
}

type ConnectorPeerPairCandidates struct {
	Items     []ConnectorPeerPairCandidate
	NextAfter string
}

// ListConnectorPeerPairs bounds each reconciliation read and authenticates only
// the exact run token. listing does not renew a pair or disclose its subject.
func (d *Database) ListConnectorPeerPairs(ctx context.Context, serviceID, runID, after, token string, now time.Time) (result ConnectorPeerPairCandidates, retErr error) {
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
	run, err := serviceRunAuthorization(ctx, tx, q, serviceID, runID, token, now)
	if err != nil {
		return result, err
	}
	// a starting or temporarily unhealthy run can reconcile hints. only the
	// independent delivery operation requires ready claims and a certificate.
	if _, err = q.GetServiceRunPublisherIdentity(ctx, controlstatedb.GetServiceRunPublisherIdentityParams{
		ID: run.ID, ServiceID: serviceID, RunNumber: run.RunNumber, PublisherIdentityID: run.PublisherIdentityID,
		PublisherGrantID: run.PublisherGrantID, PublisherKeyID: run.PublisherKeyID, Now: timestamptz(now),
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
	for _, row := range rows[:min(len(rows), 64)] {
		result.Items = append(result.Items, ConnectorPeerPairCandidate{PairID: row.ID, DeliveryGeneration: row.DeliveryGeneration})
	}
	if len(rows) > 64 {
		result.NextAfter = result.Items[len(result.Items)-1].PairID
	}
	if err = tx.Commit(ctx); err != nil {
		return ConnectorPeerPairCandidates{}, err
	}
	return result, nil
}

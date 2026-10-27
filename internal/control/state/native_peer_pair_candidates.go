package state

import (
	"context"
	"time"

	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
)

// NativePeerPairCandidate identifies background preparation work. it contains
// neither a key nor authority to deliver packets or admit an application.
type NativePeerPairCandidate struct {
	PairID             string
	DeliveryGeneration int64
}

type NativePeerPairCandidates struct {
	Items     []NativePeerPairCandidate
	NextAfter string
}

// ListNativePeerPairs bounds each reconciliation read and authenticates only
// the exact run token. listing does not renew a pair or disclose its subject.
func (d *Database) ListNativePeerPairs(ctx context.Context, serviceID, runID, after, token string, now time.Time) (result NativePeerPairCandidates, retErr error) {
	if now.IsZero() || after != "" && !opaqueid.Valid(after, "npp_") {
		return result, ErrServiceAccess
	}
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return result, err
	}
	defer rollback(ctx, tx, "list native peer pairs", &retErr)()
	if err = lockServiceAdmission(ctx, tx, serviceID); err != nil {
		return result, err
	}
	q := controlstatedb.New(tx)
	run, err := serviceRunAuthorization(ctx, tx, q, serviceID, runID, token, now)
	if err != nil {
		return result, err
	}
	if run.State != "ready" || !run.Healthy || !run.CertificateExpiresAt.Valid || !run.CertificateExpiresAt.Time.After(now) {
		return result, ErrServiceAccess
	}
	if _, err = q.GetServiceRunPublisherIdentity(ctx, controlstatedb.GetServiceRunPublisherIdentityParams{
		ID: run.ID, ServiceID: serviceID, RunNumber: run.RunNumber, PublisherIdentityID: run.PublisherIdentityID,
		PublisherGrantID: run.PublisherGrantID, PublisherKeyID: run.PublisherKeyID, Now: timestamptz(now),
	}); err != nil {
		return result, publisherLookupError(err, ErrServiceAccess)
	}
	rows, err := q.ListNativePeerPairCandidates(ctx, controlstatedb.ListNativePeerPairCandidatesParams{
		ServiceID: serviceID, ServiceRunID: runID, RunNumber: run.RunNumber,
		PublisherIdentityID: run.PublisherIdentityID, Now: timestamptz(now), AfterID: after,
	})
	if err != nil {
		return result, err
	}
	result.Items = make([]NativePeerPairCandidate, 0, min(len(rows), 64))
	for _, row := range rows[:min(len(rows), 64)] {
		result.Items = append(result.Items, NativePeerPairCandidate{PairID: row.ID, DeliveryGeneration: row.DeliveryGeneration})
	}
	if len(rows) > 64 {
		result.NextAfter = result.Items[len(result.Items)-1].PairID
	}
	if err = tx.Commit(ctx); err != nil {
		return NativePeerPairCandidates{}, err
	}
	return result, nil
}

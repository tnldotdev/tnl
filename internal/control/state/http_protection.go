package state

import (
	"context"
	"errors"
	"net/netip"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/policy/httpprotection"
	"github.com/tnldotdev/tnl/internal/policy/visitorscope"
)

var ErrHTTPProtectionCapacity = errors.New("temporary source block capacity is occupied")
var ErrHTTPProtectionDisabled = errors.New("temporary source blocks are not enabled for this run")

// only public service admission calls this check. connector access retains its
// own authorization and never consumes HTTP mitigation state.
func (d *Database) publicHTTPSourceAllowed(ctx context.Context, q *controlstatedb.Queries, service string, source netip.Addr, now time.Time) error {
	settings, err := d.serviceHTTPSettings(ctx, q, service)
	if err != nil {
		return err
	}
	if settings == nil || settings.Protection == nil || !settings.Protection.BlocksSources() {
		return nil
	}
	block, err := q.ReadHTTPTemporaryBlock(ctx, controlstatedb.ReadHTTPTemporaryBlockParams{
		ResourceKind: string(visitorscope.Service), ResourceID: service, SourceIp: source.Unmap().String(),
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	if now.Before(block.ExpiresAt.Time) {
		return ErrServiceAccess
	}
	return nil
}

func readHTTPTemporaryBlocks(ctx context.Context, q *controlstatedb.Queries, scope visitorscope.Scope, now time.Time) ([]httpprotection.TemporaryBlock, error) {
	rows, err := q.ListHTTPTemporaryBlocks(ctx, controlstatedb.ListHTTPTemporaryBlocksParams{
		ResourceKind: string(scope.Kind), ResourceID: scope.ID, Now: timestamptz(now),
	})
	if err != nil {
		return nil, err
	}
	blocks := make([]httpprotection.TemporaryBlock, 0, len(rows))
	for _, row := range rows {
		blocks = append(blocks, httpprotection.TemporaryBlock{SourceIP: row.SourceIp, ExpiresAt: row.ExpiresAt.Time})
	}
	return blocks, nil
}

func (d *Database) ReportHTTPProtectionRejections(ctx context.Context, scope visitorscope.Scope, run string, number int64, token string, evidence httpprotection.Rejections, now time.Time) (retErr error) {
	if !scope.Valid() || evidence.Validate(now) != nil {
		return ErrVisitorPolicy
	}
	tx, err := d.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return err
	}
	defer rollback(ctx, tx, "report HTTP protection rejections", &retErr)()
	q := controlstatedb.New(tx)
	if scope.Kind == visitorscope.Service {
		if err := lockServiceAdmission(ctx, tx, scope.ID); err != nil {
			return err
		}
	}
	authority, err := d.authorizePublisherVisitorRun(ctx, tx, q, scope, run, number, token, now)
	if err != nil {
		return err
	}
	if !authority.protection.BlocksSources() {
		return ErrHTTPProtectionDisabled
	}
	if err := q.PruneHTTPResourceBlocks(ctx, controlstatedb.PruneHTTPResourceBlocksParams{
		ResourceKind: string(scope.Kind), ResourceID: scope.ID, Before: timestamptz(now.Add(-httpprotection.BlockRetention)),
	}); err != nil {
		return err
	}
	existing, err := q.ReadHTTPTemporaryBlock(ctx, controlstatedb.ReadHTTPTemporaryBlockParams{ResourceKind: string(scope.Kind), ResourceID: scope.ID, SourceIp: evidence.SourceIP})
	if err == nil {
		// reports during a block, including retries, never extend it. a new
		// block needs evidence entirely collected after the previous expiry.
		if existing.ExpiresAt.Time.After(now) || evidence.StartedAt.Before(existing.ExpiresAt.Time) || !evidence.EndedAt.After(existing.EvidenceEndedAt.Time) {
			return tx.Commit(ctx)
		}
	} else if !errors.Is(err, pgx.ErrNoRows) {
		return err
	} else {
		count, err := q.CountHTTPTemporaryBlocks(ctx, controlstatedb.CountHTTPTemporaryBlocksParams{ResourceKind: string(scope.Kind), ResourceID: scope.ID})
		if err != nil {
			return err
		}
		if count >= httpprotection.MaxBlocks {
			return ErrHTTPProtectionCapacity
		}
	}
	ended := evidence.EndedAt
	if ended.After(now) {
		ended = now
	}
	if err := q.StoreHTTPTemporaryBlock(ctx, controlstatedb.StoreHTTPTemporaryBlockParams{
		ResourceKind: string(scope.Kind), ResourceID: scope.ID, SourceIp: evidence.SourceIP,
		ExpiresAt: timestamptz(ended.Add(httpprotection.BlockDuration)), EvidenceEndedAt: timestamptz(evidence.EndedAt),
		EvidenceStartedAt: timestamptz(evidence.StartedAt),
	}); err != nil {
		return err
	}
	if scope.Kind == visitorscope.PublicURL {
		url, err := q.LockPublicURLForRun(ctx, scope.ID)
		if err != nil {
			return err
		}
		runs, err := q.ListOpenPublishRuns(ctx, scope.ID)
		if err != nil {
			return err
		}
		pending := pendingIngressRoutingTableEvents{}
		for _, current := range runs {
			connections, err := validReadyPublisherConnections(ctx, q, current.ID, now)
			if err != nil {
				return err
			}
			if err := pending.addPublisherConnectionChanges(ctx, q, url, current, connections, now); err != nil {
				return err
			}
		}
		if err := pending.publish(ctx, q); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

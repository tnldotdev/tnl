package state

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/policy/httpprotection"
	"github.com/tnldotdev/tnl/internal/policy/visitorscope"
)

var ErrHTTPProtectionCapacity = errors.New("temporary source block capacity is occupied")
var ErrHTTPProtectionDisabled = errors.New("temporary source blocks are not enabled for this run")

func readHTTPTemporaryBlocks(ctx context.Context, q *controlstatedb.Queries, scope visitorscope.Scope, now time.Time) ([]httpprotection.TemporaryBlock, error) {
	rows, err := q.ListHTTPTemporaryBlocks(ctx, controlstatedb.ListHTTPTemporaryBlocksParams{
		ServiceID: scope.ID, Now: timestamptz(now),
	})
	if err != nil {
		return nil, err
	}
	blocks := make([]httpprotection.TemporaryBlock, 0, len(rows))
	for _, row := range rows {
		blocks = append(blocks, httpprotection.TemporaryBlock{SourceDigest: row.SourceDigest, ExpiresAt: row.ExpiresAt.Time})
	}
	return blocks, nil
}

func (d *Database) ReportHTTPProtectionRejections(ctx context.Context, scope visitorscope.Scope, run string, number int64, token string, evidence httpprotection.Rejections, now time.Time) (retErr error) {
	if scope.Kind != visitorscope.Service || !scope.Valid() || evidence.Validate(now) != nil {
		return ErrVisitorPolicy
	}
	tx, err := d.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return err
	}
	defer rollback(ctx, tx, "report HTTP protection rejections", &retErr)()
	q := controlstatedb.New(tx)
	if err := lockServiceAdmission(ctx, tx, scope.ID); err != nil {
		return err
	}
	authority, err := d.authorizePublisherVisitorRun(ctx, tx, q, scope, run, number, token, now)
	if err != nil {
		return err
	}
	if !authority.protection.BlocksSources() {
		return ErrHTTPProtectionDisabled
	}
	if err := q.PruneHTTPResourceBlocks(ctx, controlstatedb.PruneHTTPResourceBlocksParams{
		ServiceID: scope.ID, Before: timestamptz(now.Add(-httpprotection.BlockRetention)),
	}); err != nil {
		return err
	}
	existing, err := q.ReadHTTPTemporaryBlock(ctx, controlstatedb.ReadHTTPTemporaryBlockParams{ServiceID: scope.ID, SourceDigest: evidence.SourceDigest})
	if err == nil {
		// reports during a block, including retries, never extend it. a new
		// block needs evidence entirely collected after the previous expiry.
		if existing.ExpiresAt.Time.After(now) || evidence.StartedAt.Before(existing.ExpiresAt.Time) || !evidence.EndedAt.After(existing.EvidenceEndedAt.Time) {
			return tx.Commit(ctx)
		}
	} else if !errors.Is(err, pgx.ErrNoRows) {
		return err
	} else {
		count, err := q.CountHTTPTemporaryBlocks(ctx, scope.ID)
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
		ServiceID: scope.ID, SourceDigest: evidence.SourceDigest,
		ExpiresAt: timestamptz(ended.Add(httpprotection.BlockDuration)), EvidenceEndedAt: timestamptz(evidence.EndedAt),
		EvidenceStartedAt: timestamptz(evidence.StartedAt),
	}); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

type publisherHTTPAuthority struct {
	protection httpprotection.Settings
}

// callers hold the service owner/admission locks before checking its run.
// settings come from the current saved declaration, never a publisher report.
func (d *Database) authorizePublisherVisitorRun(ctx context.Context, tx pgx.Tx, q *controlstatedb.Queries, scope visitorscope.Scope, run string, number int64, token string, now time.Time) (publisherHTTPAuthority, error) {
	var result publisherHTTPAuthority
	if scope.Kind != visitorscope.Service || !scope.Valid() {
		return result, ErrServiceAccess
	}
	service, err := q.GetService(ctx, scope.ID)
	if err != nil || service.Protocol != "http" || !service.Public {
		return result, errors.Join(ErrServiceAccess, err)
	}
	current, err := d.serviceRunAuthorization(ctx, tx, q, scope.ID, run, token, now)
	if err != nil || current.RunNumber != number {
		return result, errors.Join(ErrServiceAccess, err)
	}
	settings, err := d.serviceHTTPSettings(ctx, q, scope.ID)
	if err != nil {
		return result, err
	}
	if settings != nil && settings.Protection != nil {
		result.protection = *settings.Protection
	}
	return result, nil
}

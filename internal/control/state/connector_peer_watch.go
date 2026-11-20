package state

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/observability"
)

const MaxConnectorPeerWatchBatch = 512

// ConnectorPeerWatchVersion is a hint for an exact service run. -1 means there
// is no bookmark (in a request) or no current run (in a response).
type ConnectorPeerWatchVersion struct {
	RunID          string
	Revision       int64
	PolicyBookmark string
}

// AuthorizeConnectorPeerWatch verifies subscription authority. the version
// reader does not confer it, and using a hint always requires another checked
// operation. the caller owns the lifetime and rechecks of open subscriptions.
func (d *Database) AuthorizeConnectorPeerWatch(ctx context.Context, serviceID, runID string, number int64, token string, now time.Time) (retErr error) {
	if _, err := checkedServiceRunBinding(serviceID, runID, number); err != nil || now.IsZero() {
		return ErrServiceAccess
	}
	// a watch can span multiple publisher identities. label the individual
	// authorization span, not the shared HTTP request.
	ctx, finish := observability.Start(ctx, "publisher.watch.authorize")
	defer func() { finish(retErr) }()
	_, err := retryVisitorPreparation(ctx, now, func(at time.Time) (struct{}, error) {
		return struct{}{}, d.authorizeConnectorPeerWatch(ctx, serviceID, runID, number, token, at)
	})
	return err
}

func (d *Database) authorizeConnectorPeerWatch(ctx context.Context, serviceID, runID string, number int64, token string, now time.Time) (retErr error) {
	tx, err := d.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead})
	if err != nil {
		return err
	}
	defer rollback(ctx, tx, "authorize connector peer watch", &retErr)()
	if err := lockPublisherVisitorPolicy(ctx, tx, serviceID); err != nil {
		return err
	}
	run, err := d.serviceRunObservationAuthorization(ctx, tx, controlstatedb.New(tx), serviceID, runID, token, now)
	if err != nil {
		return err
	}
	if run.RunNumber != number {
		return ErrServiceAccess
	}
	return tx.Commit(ctx)
}

// CompareConnectorPeerWatchVersions batches already authorized subscriptions.
// it does not read permissions, extend deadlines, or hold a connection after
// the comparison returns. only the operation that applies a snapshot can
// advance a publisher's bookmark.
func (d *Database) CompareConnectorPeerWatchVersions(ctx context.Context, watched []ConnectorPeerWatchVersion) ([]ConnectorPeerWatchVersion, error) {
	if len(watched) > MaxConnectorPeerWatchBatch {
		return nil, ErrServiceAccess
	}
	if len(watched) == 0 {
		return nil, nil
	}
	params := controlstatedb.CompareConnectorPeerWatchVersionsParams{
		RunIds: make([]string, len(watched)), Revisions: make([]int64, len(watched)), PolicyBookmarks: make([]string, len(watched)),
	}
	seen := make(map[string]struct{}, len(watched))
	for i, scope := range watched {
		if _, duplicate := seen[scope.RunID]; duplicate || !opaqueid.Valid(scope.RunID, opaqueid.ServiceRunPrefix) || scope.Revision < -1 {
			return nil, ErrServiceAccess
		}
		seen[scope.RunID] = struct{}{}
		params.RunIds[i], params.Revisions[i] = scope.RunID, scope.Revision
		params.PolicyBookmarks[i] = scope.PolicyBookmark
	}
	rows, err := controlstatedb.New(d.pool).CompareConnectorPeerWatchVersions(ctx, params)
	if err != nil {
		return nil, err
	}
	changed := make([]ConnectorPeerWatchVersion, len(rows))
	for i, row := range rows {
		changed[i] = ConnectorPeerWatchVersion{RunID: row.RunID, Revision: row.Revision, PolicyBookmark: row.PolicyBookmark}
	}
	return changed, nil
}

package state

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/observability"
)

const MaxConnectorPeerWatchBatch = 512

var ErrPublisherWatchContended = errors.New("publisher watch authorization database contention")

// ConnectorPeerWatchVersion is a hint for an exact service run. -1 means there
// is no bookmark (in a request) or no current run (in a response).
type ConnectorPeerWatchVersion struct {
	RunID          string
	Revision       int64
	PolicyBookmark string
}

// entries are hints for the database comparison, never publisher input.
// eviction or a control restart just recomputes the bookmark on the next poll.
type watchBookmarkCache struct {
	sync.Mutex
	byRun map[string]watchBookmark
}

type watchBookmark struct {
	version                  ConnectorPeerWatchVersion
	runBucket, serviceBucket int32
	global, run, service     int64
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
	return classifyPublisherWatchError(err)
}

func classifyPublisherWatchError(err error) error {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr != nil && failure.Only(err, pgErr) {
		switch pgErr.Code {
		case "40001", "40P01", "55P03":
			return fmt.Errorf("%w: %w", ErrPublisherWatchContended, err)
		}
	}
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
func (d *Database) CompareConnectorPeerWatchVersions(ctx context.Context, watched []ConnectorPeerWatchVersion) (_ []ConnectorPeerWatchVersion, retErr error) {
	if len(watched) > MaxConnectorPeerWatchBatch {
		return nil, ErrServiceAccess
	}
	if len(watched) == 0 {
		return nil, nil
	}
	seen := make(map[string]ConnectorPeerWatchVersion, len(watched))
	for _, scope := range watched {
		if _, duplicate := seen[scope.RunID]; duplicate || !opaqueid.Valid(scope.RunID, opaqueid.ServiceRunPrefix) || scope.Revision < -1 {
			return nil, ErrServiceAccess
		}
		seen[scope.RunID] = scope
	}
	cache := &d.watchBookmarks
	compare := func(q *controlstatedb.Queries) (changed []ConnectorPeerWatchVersion, dirty []string, versions [257]int64, err error) {
		rows, err := q.ListReadDependencyVersions(ctx, "watch")
		if err != nil {
			return nil, nil, versions, err
		}
		for _, row := range rows {
			versions[row.Bucket+1] = row.Revision
		}
		cache.Lock()
		defer cache.Unlock()
		for id, previous := range seen {
			b, ok := cache.byRun[id]
			if !ok || b.global != versions[0] || b.run != versions[1+b.runBucket] || b.service != versions[1+b.serviceBucket] {
				dirty = append(dirty, id)
			} else if b.version.Revision < 0 || b.version != previous {
				changed = append(changed, b.version)
			}
		}
		return
	}
	changed, dirty, _, err := compare(controlstatedb.New(d.pool))
	if err != nil || len(dirty) == 0 {
		return changed, err
	}
	// pair fresh bookmarks with their exact revisions, including concurrent
	// commits from other controls. the idle path needs only the first read.
	tx, err := d.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return nil, err
	}
	defer rollback(ctx, tx, "read publisher watch changes", &retErr)()
	q := controlstatedb.New(tx)
	changed, dirty, versions, err := compare(q)
	if err != nil {
		return nil, err
	}
	rows, err := q.ReadConnectorPeerWatchVersions(ctx, dirty)
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	cache.Lock()
	defer cache.Unlock()
	if cache.byRun == nil || len(cache.byRun)+len(rows) > 8*MaxConnectorPeerWatchBatch {
		cache.byRun = make(map[string]watchBookmark)
	}
	for _, row := range rows {
		version := ConnectorPeerWatchVersion{RunID: row.RunID, Revision: row.Revision, PolicyBookmark: row.PolicyBookmark}
		cache.byRun[row.RunID] = watchBookmark{version: version, runBucket: row.RunBucket, serviceBucket: row.ServiceBucket,
			global: versions[0], run: versions[1+row.RunBucket], service: versions[1+row.ServiceBucket]}
		if version.Revision < 0 || version != seen[row.RunID] {
			changed = append(changed, version)
		}
	}
	return changed, nil
}

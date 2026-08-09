package routeexport

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"time"

	"github.com/0xcadams/tnl/internal/routes"
	"github.com/0xcadams/tnl/internal/state/statedb"
)

const (
	lifecycleSource = "lifecycle_event"
	usageSource     = "usage_snapshot"
)

type Store struct {
	db      *sql.DB
	queries *statedb.Queries
	wake    chan struct{}
}

func NewStore(db *sql.DB) (*Store, error) {
	if db == nil {
		return nil, errors.New("routeexport: nil state database")
	}
	return &Store{db: db, queries: statedb.New(db), wake: make(chan struct{}, 1)}, nil
}

func (s *Store) RecordLifecycle(
	ctx context.Context,
	queries *statedb.Queries,
	change routes.LifecycleChange,
) error {
	generation, err := databaseInteger(change.Generation)
	if err != nil {
		return err
	}
	exists, err := queries.CountRouteLifecycleTransition(ctx, statedb.CountRouteLifecycleTransitionParams{
		RouteID: change.RouteID, Generation: generation, Transition: string(change.Transition),
	})
	if err != nil {
		return fmt.Errorf("routeexport: check lifecycle transition: %w", err)
	}
	if exists != 0 {
		return nil
	}
	sequence, err := queries.AdvanceRouteLifecycleSequence(ctx, change.RouteID)
	if err != nil {
		return fmt.Errorf("routeexport: advance lifecycle sequence: %w", err)
	}
	eventID, err := newEventID()
	if err != nil {
		return err
	}
	eventRowID, err := queries.InsertRouteLifecycleEvent(ctx, statedb.InsertRouteLifecycleEventParams{
		EventID: eventID, RouteID: change.RouteID, Generation: generation, Sequence: sequence,
		OccurredAtNs: change.OccurredAt.UTC().UnixNano(), Transition: string(change.Transition),
	})
	if err != nil {
		return fmt.Errorf("routeexport: insert lifecycle event: %w", err)
	}
	if err := queries.UpsertRouteExportOutbox(ctx, statedb.UpsertRouteExportOutboxParams{
		SourceKind: lifecycleSource, SourceID: eventRowID, SourceRevision: 1,
		CreatedAtNs: time.Now().UTC().UnixNano(),
	}); err != nil {
		return fmt.Errorf("routeexport: enqueue lifecycle event: %w", err)
	}
	s.wakePublisher()
	return nil
}

type UsageSnapshot struct {
	RouteID           string
	Generation        uint64
	Resolution        string
	BucketStart       time.Time
	Revision          uint64
	SourceThrough     time.Time
	ConnectionsOpened uint64
	ConnectionNS      uint64
	IngressBytes      uint64
	EgressBytes       uint64
	Complete          bool
	Publish           bool
}

func (s *Store) SaveUsage(ctx context.Context, snapshots []UsageSnapshot) error {
	if len(snapshots) == 0 {
		return nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("routeexport: begin usage checkpoint: %w", err)
	}
	defer tx.Rollback()
	queries := s.queries.WithTx(tx)
	for _, snapshot := range snapshots {
		generation, err := databaseInteger(snapshot.Generation)
		if err != nil {
			return err
		}
		revision, err := databaseInteger(snapshot.Revision)
		if err != nil {
			return err
		}
		connections, err := databaseInteger(snapshot.ConnectionsOpened)
		if err != nil {
			return err
		}
		connectionNS, err := databaseInteger(snapshot.ConnectionNS)
		if err != nil {
			return err
		}
		ingressBytes, err := databaseInteger(snapshot.IngressBytes)
		if err != nil {
			return err
		}
		egressBytes, err := databaseInteger(snapshot.EgressBytes)
		if err != nil {
			return err
		}
		complete := int64(0)
		if snapshot.Complete {
			complete = 1
		}
		rowID, err := queries.UpsertRouteUsageBucket(ctx, statedb.UpsertRouteUsageBucketParams{
			RouteID: snapshot.RouteID, Generation: generation, Resolution: snapshot.Resolution,
			BucketStartNs: snapshot.BucketStart.UTC().UnixNano(), Revision: revision,
			SourceThroughNs: snapshot.SourceThrough.UTC().UnixNano(), ConnectionsOpened: connections,
			ConnectionNs: connectionNS, IngressBytes: ingressBytes, EgressBytes: egressBytes, Complete: complete,
		})
		if err != nil {
			return fmt.Errorf("routeexport: save usage bucket: %w", err)
		}
		if snapshot.Publish {
			if revision < 1 {
				return errors.New("routeexport: publishable usage snapshot has no revision")
			}
			if err := queries.UpsertRouteExportOutbox(ctx, statedb.UpsertRouteExportOutboxParams{
				SourceKind: usageSource, SourceID: rowID, SourceRevision: revision,
				CreatedAtNs: time.Now().UTC().UnixNano(),
			}); err != nil {
				return fmt.Errorf("routeexport: enqueue usage snapshot: %w", err)
			}
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("routeexport: commit usage checkpoint: %w", err)
	}
	s.wakePublisher()
	return nil
}

func (s *Store) LoadIncompleteUsage(ctx context.Context) ([]statedb.RouteUsageBucket, error) {
	rows, err := s.queries.ListIncompleteRouteUsageBuckets(ctx)
	if err != nil {
		return nil, fmt.Errorf("routeexport: load usage checkpoints: %w", err)
	}
	return rows, nil
}

func (s *Store) outboxStats(ctx context.Context, now time.Time) (int64, int64, time.Duration, error) {
	lifecycle, err := s.queries.CountRouteExportOutboxByKind(ctx, lifecycleSource)
	if err != nil {
		return 0, 0, 0, fmt.Errorf("routeexport: count lifecycle outbox: %w", err)
	}
	usage, err := s.queries.CountRouteExportOutboxByKind(ctx, usageSource)
	if err != nil {
		return 0, 0, 0, fmt.Errorf("routeexport: count usage outbox: %w", err)
	}
	oldest, err := s.queries.GetOldestRouteExportOutboxTime(ctx)
	if errors.Is(err, sql.ErrNoRows) {
		return lifecycle, usage, 0, nil
	}
	if err != nil {
		return 0, 0, 0, fmt.Errorf("routeexport: read oldest outbox item: %w", err)
	}
	age := now.UTC().Sub(time.Unix(0, oldest).UTC())
	if age < 0 {
		age = 0
	}
	return lifecycle, usage, age, nil
}

func (s *Store) acknowledge(ctx context.Context, kind string, sourceID, revision int64) (bool, error) {
	count, err := s.queries.DeleteRouteExportOutboxRevision(ctx, statedb.DeleteRouteExportOutboxRevisionParams{
		SourceKind: kind, SourceID: sourceID, SourceRevision: revision,
	})
	if err != nil {
		return false, fmt.Errorf("routeexport: acknowledge export: %w", err)
	}
	return count == 1, nil
}

func (s *Store) deleteUsage(ctx context.Context, id int64) error {
	if _, err := s.queries.DeleteAcknowledgedRouteUsageBucket(ctx, id); err != nil {
		return fmt.Errorf("routeexport: delete delivered usage: %w", err)
	}
	return nil
}

func (s *Store) pruneLifecycle(ctx context.Context, now time.Time) error {
	return s.queries.DeleteExpiredRouteLifecycleEvents(ctx, statedb.DeleteExpiredRouteLifecycleEventsParams{
		CutoffNs: now.Add(-365 * 24 * time.Hour).UnixNano(), BatchSize: 5000,
	})
}

func (s *Store) wakePublisher() {
	select {
	case s.wake <- struct{}{}:
	default:
	}
}

func databaseInteger(value uint64) (int64, error) {
	if value > math.MaxInt64 {
		return 0, errors.New("routeexport: counter exceeds SQLite integer range")
	}
	return int64(value), nil
}

func newEventID() (string, error) {
	var material [16]byte
	if _, err := rand.Read(material[:]); err != nil {
		return "", fmt.Errorf("routeexport: generate lifecycle event ID: %w", err)
	}
	return "event_" + hex.EncodeToString(material[:]), nil
}

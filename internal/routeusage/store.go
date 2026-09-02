package routeusage

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"time"

	"github.com/tnldotdev/tnl/internal/routes"
	"github.com/tnldotdev/tnl/internal/state/statedb"
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
		return nil, errors.New("routeusage: nil state database")
	}
	return &Store{db: db, queries: statedb.New(db), wake: make(chan struct{}, 1)}, nil
}

func (s *Store) RecordLifecycle(
	ctx context.Context,
	queries *statedb.Queries,
	change routes.LifecycleChange,
) error {
	version, err := databaseInteger(change.Version)
	if err != nil {
		return err
	}
	exists, err := queries.CountRouteLifecycleTransition(ctx, statedb.CountRouteLifecycleTransitionParams{
		RouteID: change.RouteID, Version: version, Transition: string(change.Transition),
	})
	if err != nil {
		return fmt.Errorf("routeusage: check lifecycle transition: %w", err)
	}
	if exists != 0 {
		return nil
	}
	sequence, err := queries.AdvanceRouteLifecycleSequence(ctx, change.RouteID)
	if err != nil {
		return fmt.Errorf("routeusage: advance lifecycle sequence: %w", err)
	}
	eventID, err := newEventID()
	if err != nil {
		return err
	}
	eventRowID, err := queries.InsertRouteLifecycleEvent(ctx, statedb.InsertRouteLifecycleEventParams{
		EventID: eventID, RouteID: change.RouteID, Version: version, Sequence: sequence,
		OccurredAt: change.OccurredAt.UTC().UnixNano(), Transition: string(change.Transition),
	})
	if err != nil {
		return fmt.Errorf("routeusage: insert lifecycle event: %w", err)
	}
	if err := queries.UpsertRouteUsageOutbox(ctx, statedb.UpsertRouteUsageOutboxParams{
		SourceKind: lifecycleSource, SourceID: eventRowID, SourceRevision: 1,
		EnqueuedAt: time.Now().UTC().UnixNano(),
	}); err != nil {
		return fmt.Errorf("routeusage: enqueue lifecycle event: %w", err)
	}
	s.wakeSender()
	return nil
}

type UsageSnapshot struct {
	RouteID               string
	Version               uint64
	Resolution            string
	BucketStart           time.Time
	Revision              uint64
	ObservedThrough       time.Time
	ConnectionsOpened     uint64
	ConnectionNanoseconds uint64
	IngressBytes          uint64
	EgressBytes           uint64
	Complete              bool
	Publish               bool
}

func (s *Store) SaveUsage(ctx context.Context, snapshots []UsageSnapshot) error {
	if len(snapshots) == 0 {
		return nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("routeusage: begin usage checkpoint: %w", err)
	}
	defer tx.Rollback()
	queries := s.queries.WithTx(tx)
	for _, snapshot := range snapshots {
		version, err := databaseInteger(snapshot.Version)
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
		connectionNanoseconds, err := databaseInteger(snapshot.ConnectionNanoseconds)
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
		rowID, err := queries.UpsertRouteUsageSnapshot(ctx, statedb.UpsertRouteUsageSnapshotParams{
			RouteID: snapshot.RouteID, Version: version, Resolution: snapshot.Resolution,
			BucketStart: snapshot.BucketStart.UTC().UnixNano(), Revision: revision,
			ObservedThrough: snapshot.ObservedThrough.UTC().UnixNano(), ConnectionsOpened: connections,
			ConnectionNanoseconds: connectionNanoseconds, IngressBytes: ingressBytes, EgressBytes: egressBytes, Complete: complete,
		})
		if err != nil {
			return fmt.Errorf("routeusage: save usage bucket: %w", err)
		}
		if snapshot.Publish {
			if revision < 1 {
				return errors.New("routeusage: deliverable usage snapshot has no revision")
			}
			if err := queries.UpsertRouteUsageOutbox(ctx, statedb.UpsertRouteUsageOutboxParams{
				SourceKind: usageSource, SourceID: rowID, SourceRevision: revision,
				EnqueuedAt: time.Now().UTC().UnixNano(),
			}); err != nil {
				return fmt.Errorf("routeusage: enqueue usage snapshot: %w", err)
			}
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("routeusage: commit usage checkpoint: %w", err)
	}
	s.wakeSender()
	return nil
}

func (s *Store) LoadIncompleteUsage(ctx context.Context) ([]statedb.RouteUsageSnapshot, error) {
	rows, err := s.queries.ListIncompleteRouteUsageSnapshots(ctx)
	if err != nil {
		return nil, fmt.Errorf("routeusage: load usage checkpoints: %w", err)
	}
	return rows, nil
}

func (s *Store) outboxStats(ctx context.Context, now time.Time) (int64, int64, time.Duration, error) {
	lifecycle, err := s.queries.CountRouteUsageOutboxByKind(ctx, lifecycleSource)
	if err != nil {
		return 0, 0, 0, fmt.Errorf("routeusage: count lifecycle outbox: %w", err)
	}
	usage, err := s.queries.CountRouteUsageOutboxByKind(ctx, usageSource)
	if err != nil {
		return 0, 0, 0, fmt.Errorf("routeusage: count usage outbox: %w", err)
	}
	oldest, err := s.queries.GetOldestRouteUsageOutboxTime(ctx)
	if errors.Is(err, sql.ErrNoRows) {
		return lifecycle, usage, 0, nil
	}
	if err != nil {
		return 0, 0, 0, fmt.Errorf("routeusage: read oldest outbox item: %w", err)
	}
	age := now.UTC().Sub(time.Unix(0, oldest).UTC())
	if age < 0 {
		age = 0
	}
	return lifecycle, usage, age, nil
}

func (s *Store) acknowledge(ctx context.Context, kind string, sourceID, revision int64) (bool, error) {
	count, err := s.queries.DeleteRouteUsageOutboxRevision(ctx, statedb.DeleteRouteUsageOutboxRevisionParams{
		SourceKind: kind, SourceID: sourceID, SourceRevision: revision,
	})
	if err != nil {
		return false, fmt.Errorf("routeusage: acknowledge report: %w", err)
	}
	return count == 1, nil
}

func (s *Store) deleteUsage(ctx context.Context, id int64) error {
	if _, err := s.queries.DeleteAcknowledgedRouteUsageSnapshot(ctx, id); err != nil {
		return fmt.Errorf("routeusage: delete delivered usage: %w", err)
	}
	return nil
}

func (s *Store) pruneLifecycle(ctx context.Context, now time.Time) error {
	return s.queries.DeleteExpiredRouteLifecycleEvents(ctx, statedb.DeleteExpiredRouteLifecycleEventsParams{
		Cutoff: now.Add(-365 * 24 * time.Hour).UnixNano(), BatchSize: 5000,
	})
}

func (s *Store) wakeSender() {
	select {
	case s.wake <- struct{}{}:
	default:
	}
}

func databaseInteger(value uint64) (int64, error) {
	if value > math.MaxInt64 {
		return 0, errors.New("routeusage: counter exceeds SQLite integer range")
	}
	return int64(value), nil
}

func newEventID() (string, error) {
	var material [16]byte
	if _, err := rand.Read(material[:]); err != nil {
		return "", fmt.Errorf("routeusage: generate lifecycle event ID: %w", err)
	}
	return "event_" + hex.EncodeToString(material[:]), nil
}

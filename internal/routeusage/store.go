package routeusage

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
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
	registrationSource = "registration"
	lifecycleSource    = "lifecycle_event"
	usageSource        = "usage_snapshot"
	visitorSecretKey   = "route-usage-visitor-master-secret"
)

type Store struct {
	db      *sql.DB
	queries *statedb.Queries
	wake    chan struct{}

	visitorMasterSecret [sha256.Size]byte
}

func NewStore(db *sql.DB) (*Store, error) {
	if db == nil {
		return nil, errors.New("routeusage: nil state database")
	}
	visitorMasterSecret, err := ensureVisitorMasterSecret(db)
	if err != nil {
		return nil, err
	}
	return &Store{
		db: db, queries: statedb.New(db), wake: make(chan struct{}, 1), visitorMasterSecret: visitorMasterSecret,
	}, nil
}

func (s *Store) RecordRegistration(
	ctx context.Context,
	queries *statedb.Queries,
	registration routes.RouteRegistration,
) error {
	rowID, err := queries.InsertRouteRegistration(ctx, statedb.InsertRouteRegistrationParams{
		RegistrationID:  registration.RegistrationID,
		RouteID:         registration.RouteID,
		Hostname:        registration.Hostname,
		SigningKeyID:    registration.SigningKeyID,
		AuthorizationID: registration.AuthorizationID,
		CreatedAt:       registration.CreatedAt.UTC().UnixNano(),
		RetryID:         registration.RetryID,
	})
	if err != nil {
		return fmt.Errorf("routeusage: insert route registration: %w", err)
	}
	if err := queries.UpsertRouteUsageOutbox(ctx, statedb.UpsertRouteUsageOutboxParams{
		SourceKind: registrationSource, SourceID: rowID, SourceRevision: 1,
		EnqueuedAt: time.Now().UTC().UnixNano(),
	}); err != nil {
		return fmt.Errorf("routeusage: enqueue route registration: %w", err)
	}
	s.wakeSender()
	return nil
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
	RouteID                      string
	Version                      uint64
	Resolution                   string
	BucketStart                  time.Time
	Revision                     uint64
	ObservedThrough              time.Time
	ConnectionAttempts           uint64
	PolicyDenials                uint64
	CapacityDenials              uint64
	PublisherOpenFailures        uint64
	SuccessfulStreams            uint64
	ConnectionNanoseconds        uint64
	IngressBytes                 uint64
	EgressBytes                  uint64
	PublisherOpenLatency         []byte
	TimeToFirstPublisherByte     []byte
	SuccessfulConnectionDuration []byte
	VisitorNetworkHLL            []byte
	VisitorNetworkEstimate       uint64
	Complete                     bool
	Finalized                    bool
	Publish                      bool
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
		connectionAttempts, err := databaseInteger(snapshot.ConnectionAttempts)
		if err != nil {
			return err
		}
		policyDenials, err := databaseInteger(snapshot.PolicyDenials)
		if err != nil {
			return err
		}
		capacityDenials, err := databaseInteger(snapshot.CapacityDenials)
		if err != nil {
			return err
		}
		publisherOpenFailures, err := databaseInteger(snapshot.PublisherOpenFailures)
		if err != nil {
			return err
		}
		successfulStreams, err := databaseInteger(snapshot.SuccessfulStreams)
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
		for _, checkpoint := range [][]byte{
			snapshot.PublisherOpenLatency,
			snapshot.TimeToFirstPublisherByte,
			snapshot.SuccessfulConnectionDuration,
		} {
			if _, err := unmarshalDurationHistogram(checkpoint); err != nil {
				return err
			}
		}
		visitorCheckpoint := snapshot.VisitorNetworkHLL
		if len(visitorCheckpoint) == 0 {
			visitorCheckpoint = new(visitorSketch).checkpoint()
		}
		visitorSketch, err := visitorSketchFromCheckpoint(visitorCheckpoint)
		if err != nil {
			return err
		}
		visitorEstimate := visitorSketch.estimate()
		if snapshot.VisitorNetworkEstimate != 0 && snapshot.VisitorNetworkEstimate != visitorEstimate {
			return errors.New("routeusage: visitor HLL estimate does not match checkpoint")
		}
		visitorEstimateInteger, err := databaseInteger(visitorEstimate)
		if err != nil {
			return err
		}
		complete := int64(0)
		if snapshot.Complete {
			complete = 1
		}
		finalized := int64(0)
		if snapshot.Finalized || snapshot.Complete {
			finalized = 1
		}
		rowID, err := queries.UpsertRouteUsageSnapshot(ctx, statedb.UpsertRouteUsageSnapshotParams{
			RouteID: snapshot.RouteID, Version: version, Resolution: snapshot.Resolution,
			BucketStart: snapshot.BucketStart.UTC().UnixNano(), Revision: revision,
			ObservedThrough: snapshot.ObservedThrough.UTC().UnixNano(), ConnectionAttempts: connectionAttempts,
			PolicyDenials: policyDenials, CapacityDenials: capacityDenials,
			PublisherOpenFailures: publisherOpenFailures, SuccessfulStreams: successfulStreams,
			ConnectionNanoseconds: connectionNanoseconds, IngressBytes: ingressBytes, EgressBytes: egressBytes,
			PublisherOpenLatency:         snapshot.PublisherOpenLatency,
			TimeToFirstPublisherByte:     snapshot.TimeToFirstPublisherByte,
			SuccessfulConnectionDuration: snapshot.SuccessfulConnectionDuration,
			VisitorNetworkHll:            visitorCheckpoint, VisitorNetworkEstimate: visitorEstimateInteger,
			Complete: complete, Finalized: finalized,
		})
		if err != nil {
			return fmt.Errorf("routeusage: save usage bucket: %w", err)
		}
		if snapshot.Publish {
			if revision < 1 {
				return errors.New("routeusage: deliverable usage snapshot has no revision")
			}
			reportID, err := newUsageReportID()
			if err != nil {
				return err
			}
			count, err := queries.UpsertRouteUsageReport(ctx, statedb.UpsertRouteUsageReportParams{
				SnapshotID: rowID, ReportID: reportID, Revision: revision,
				ObservedThrough:    snapshot.ObservedThrough.UTC().UnixNano(),
				ConnectionAttempts: connectionAttempts, PolicyDenials: policyDenials, CapacityDenials: capacityDenials,
				PublisherOpenFailures: publisherOpenFailures, SuccessfulStreams: successfulStreams,
				ConnectionNanoseconds: connectionNanoseconds, IngressBytes: ingressBytes, EgressBytes: egressBytes,
				PublisherOpenLatency:         snapshot.PublisherOpenLatency,
				TimeToFirstPublisherByte:     snapshot.TimeToFirstPublisherByte,
				SuccessfulConnectionDuration: snapshot.SuccessfulConnectionDuration,
				VisitorNetworkHll:            visitorCheckpoint, VisitorNetworkEstimate: visitorEstimateInteger, Complete: complete,
			})
			if err != nil {
				return fmt.Errorf("routeusage: save deliverable usage report: %w", err)
			}
			if count != 1 {
				return errors.New("routeusage: usage revision does not identify one payload")
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

func (s *Store) outboxStats(ctx context.Context, now time.Time) (int64, int64, int64, time.Duration, error) {
	registration, err := s.queries.CountRouteUsageOutboxByKind(ctx, registrationSource)
	if err != nil {
		return 0, 0, 0, 0, fmt.Errorf("routeusage: count registration outbox: %w", err)
	}
	lifecycle, err := s.queries.CountRouteUsageOutboxByKind(ctx, lifecycleSource)
	if err != nil {
		return 0, 0, 0, 0, fmt.Errorf("routeusage: count lifecycle outbox: %w", err)
	}
	usage, err := s.queries.CountRouteUsageOutboxByKind(ctx, usageSource)
	if err != nil {
		return 0, 0, 0, 0, fmt.Errorf("routeusage: count usage outbox: %w", err)
	}
	oldest, err := s.queries.GetOldestRouteUsageOutboxTime(ctx)
	if errors.Is(err, sql.ErrNoRows) {
		return registration, lifecycle, usage, 0, nil
	}
	if err != nil {
		return 0, 0, 0, 0, fmt.Errorf("routeusage: read oldest outbox item: %w", err)
	}
	age := now.UTC().Sub(time.Unix(0, oldest).UTC())
	if age < 0 {
		age = 0
	}
	return registration, lifecycle, usage, age, nil
}

type outboxRevision struct {
	kind     string
	sourceID int64
	revision int64
}

func (s *Store) markAttempted(ctx context.Context, items []outboxRevision) (bool, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return false, fmt.Errorf("routeusage: begin outbox attempt: %w", err)
	}
	defer tx.Rollback()
	queries := s.queries.WithTx(tx)
	attemptedAt := time.Now().UTC().UnixNano()
	for _, item := range items {
		count, err := queries.MarkRouteUsageOutboxAttempt(ctx, statedb.MarkRouteUsageOutboxAttemptParams{
			AttemptedAt: attemptedAt, SourceKind: item.kind,
			SourceID: item.sourceID, SourceRevision: item.revision,
		})
		if err != nil {
			return false, fmt.Errorf("routeusage: mark outbox attempt: %w", err)
		}
		if count != 1 {
			return false, nil
		}
	}
	if err := tx.Commit(); err != nil {
		return false, fmt.Errorf("routeusage: commit outbox attempt: %w", err)
	}
	return true, nil
}

func (s *Store) acknowledgeLifecycleBatch(ctx context.Context, items []outboxRevision) error {
	return s.acknowledgeBatch(ctx, items, false)
}

func (s *Store) acknowledgeUsageBatch(ctx context.Context, items []outboxRevision) error {
	return s.acknowledgeBatch(ctx, items, true)
}

func (s *Store) acknowledgeBatch(ctx context.Context, items []outboxRevision, deleteFinalized bool) error {
	if len(items) == 0 {
		return nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("routeusage: begin batch acknowledgment: %w", err)
	}
	defer tx.Rollback()
	queries := s.queries.WithTx(tx)
	for _, item := range items {
		count, err := queries.DeleteRouteUsageOutboxRevision(ctx, statedb.DeleteRouteUsageOutboxRevisionParams{
			SourceKind: item.kind, SourceID: item.sourceID, SourceRevision: item.revision,
		})
		if err != nil {
			return fmt.Errorf("routeusage: acknowledge batch item: %w", err)
		}
		if deleteFinalized && count == 1 {
			if _, err := queries.DeleteAcknowledgedRouteUsageSnapshot(ctx, item.sourceID); err != nil {
				return fmt.Errorf("routeusage: delete finalized usage snapshot: %w", err)
			}
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("routeusage: commit batch acknowledgment: %w", err)
	}
	return nil
}

func (s *Store) acknowledgeRegistration(ctx context.Context, sourceID, revision int64) (bool, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return false, fmt.Errorf("routeusage: begin registration acknowledgment: %w", err)
	}
	defer tx.Rollback()
	queries := s.queries.WithTx(tx)
	count, err := queries.AcknowledgeRouteRegistrationRevision(ctx, statedb.AcknowledgeRouteRegistrationRevisionParams{
		SourceRevision: revision,
		AcknowledgedAt: time.Now().UTC().UnixNano(),
		SourceID:       sourceID,
	})
	if err != nil {
		return false, fmt.Errorf("routeusage: acknowledge route registration: %w", err)
	}
	if count != 1 {
		return false, nil
	}
	count, err = queries.DeleteRouteUsageOutboxRevision(ctx, statedb.DeleteRouteUsageOutboxRevisionParams{
		SourceKind: registrationSource, SourceID: sourceID, SourceRevision: revision,
	})
	if err != nil {
		return false, fmt.Errorf("routeusage: acknowledge registration outbox: %w", err)
	}
	if count != 1 {
		return false, nil
	}
	if err := tx.Commit(); err != nil {
		return false, fmt.Errorf("routeusage: commit registration acknowledgment: %w", err)
	}
	return true, nil
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
	return newOpaqueID("event_", "lifecycle event")
}

func newUsageReportID() (string, error) {
	return newOpaqueID("usage_report_", "usage report")
}

func newOpaqueID(prefix, description string) (string, error) {
	var material [16]byte
	if _, err := rand.Read(material[:]); err != nil {
		return "", fmt.Errorf("routeusage: generate %s ID: %w", description, err)
	}
	return prefix + hex.EncodeToString(material[:]), nil
}

func ensureVisitorMasterSecret(db *sql.DB) ([sha256.Size]byte, error) {
	var generated [sha256.Size]byte
	if _, err := rand.Read(generated[:]); err != nil {
		return generated, fmt.Errorf("routeusage: generate visitor master secret: %w", err)
	}
	tx, err := db.Begin()
	if err != nil {
		return generated, fmt.Errorf("routeusage: begin visitor master secret initialization: %w", err)
	}
	defer tx.Rollback()
	queries := statedb.New(tx)
	if _, err := queries.InsertServerValue(context.Background(), statedb.InsertServerValueParams{
		Key: visitorSecretKey, Value: generated[:],
	}); err != nil {
		return generated, fmt.Errorf("routeusage: persist visitor master secret: %w", err)
	}
	data, err := queries.GetServerValue(context.Background(), visitorSecretKey)
	if err != nil {
		return generated, fmt.Errorf("routeusage: read visitor master secret: %w", err)
	}
	if len(data) != len(generated) {
		return generated, errors.New("routeusage: persisted visitor master secret is invalid")
	}
	copy(generated[:], data)
	if err := tx.Commit(); err != nil {
		return generated, fmt.Errorf("routeusage: commit visitor master secret initialization: %w", err)
	}
	return generated, nil
}

package controlstate

import (
	"context"
	"errors"
	"fmt"
	"math"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/controlstate/controlstatedb"
	"github.com/tnldotdev/tnl/internal/opaqueid"
	"github.com/tnldotdev/tnl/internal/publicurlusage"
)

var (
	ErrPublicURLUsageDeliveryWorkStale = errors.New("controlstate: public URL usage delivery work is stale")
	ErrPublicURLUsageDeliveryInvalid   = errors.New("controlstate: public URL usage delivery work is invalid")
)

// FinalizePublicURLUsageBuckets closes aggregate buckets through a cutoff and
// creates delivery work for each finalized revision.
func (d *Database) FinalizePublicURLUsageBuckets(
	ctx context.Context,
	through time.Time,
	now time.Time,
) (result int, retErr error) {
	if through.After(now) {
		return 0, errors.New("controlstate: public URL usage finalization cutoff is in the future")
	}
	if err := d.requireOpen(); err != nil {
		return 0, err
	}
	tx, err := d.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return 0, fmt.Errorf("controlstate: finalize public URL usage buckets: begin transaction: %w", err)
	}
	defer rollback(ctx, tx, "finalize public URL usage buckets", &retErr)()
	queries := controlstatedb.New(tx)
	buckets, err := queries.FinalizePublicURLUsageBuckets(ctx, controlstatedb.FinalizePublicURLUsageBucketsParams{
		FinalizedAt: timestamptz(now), Through: timestamptz(through),
	})
	if err != nil {
		return 0, fmt.Errorf("controlstate: finalize public URL usage buckets: update buckets: %w", err)
	}
	for _, bucket := range buckets {
		deliveryKey, err := opaqueid.New("usage_report_")
		if err != nil {
			return 0, fmt.Errorf("controlstate: finalize public URL usage buckets: create delivery key: %w", err)
		}
		_, err = queries.InsertPublicURLUsageDelivery(ctx, controlstatedb.InsertPublicURLUsageDeliveryParams{
			BucketID: bucket.BucketID, SourceRevision: bucket.BucketRevision,
			DeliveryKey: deliveryKey,
			AvailableAt: timestamptz(now), CreatedAt: timestamptz(now),
		})
		if err != nil {
			return 0, fmt.Errorf("controlstate: finalize public URL usage buckets: insert delivery: %w", err)
		}
		result++
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, fmt.Errorf("controlstate: finalize public URL usage buckets: commit: %w", err)
	}
	return result, nil
}

// PublicURLUsageDeliveryWork is one immutable finalized bucket held under a
// PostgreSQL work lease.
type PublicURLUsageDeliveryWork struct {
	DeliveryID                uint64
	DeliveryKey               string
	SourceRevision            uint64
	PublicURLID               string
	PublishRunNumber          uint64
	TeamID                    string
	ActingIdentityID          string
	BucketStart               time.Time
	BucketEnd                 time.Time
	ObservedThrough           time.Time
	ConnectionAttempts        uint64
	PolicyDenials             uint64
	CapacityDenials           uint64
	VisitorStreamOpenFailures uint64
	SuccessfulStreams         uint64
	ConnectionNanoseconds     uint64
	IngressBytes              uint64
	EgressBytes               uint64
	Checkpoint                publicurlusage.Checkpoint
	Complete                  bool
	Attempts                  uint64
	WorkerID                  string
	WorkEpoch                 uint64
	WorkExpiresAt             time.Time
}

// ClaimPublicURLUsageDeliveries claims up to batchSize finalized buckets.
func (d *Database) ClaimPublicURLUsageDeliveries(
	ctx context.Context,
	workerID string,
	batchSize int,
	now time.Time,
	leaseDuration time.Duration,
) (result []PublicURLUsageDeliveryWork, retErr error) {
	if !validStateText(workerID) || batchSize <= 0 || batchSize > 32 || leaseDuration <= 0 {
		return nil, ErrPublicURLUsageDeliveryInvalid
	}
	if err := d.requireOpen(); err != nil {
		return nil, err
	}
	tx, err := d.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return nil, fmt.Errorf("controlstate: claim public URL usage deliveries: begin transaction: %w", err)
	}
	defer rollback(ctx, tx, "claim public URL usage deliveries", &retErr)()
	queries := controlstatedb.New(tx)
	deliveries, err := queries.ClaimPublicURLUsageDeliveries(ctx, controlstatedb.ClaimPublicURLUsageDeliveriesParams{
		WorkOwner: text(workerID), WorkExpiresAt: timestamptz(now.Add(leaseDuration)),
		ClaimedAt: timestamptz(now), BatchSize: int32(batchSize),
	})
	if err != nil {
		return nil, fmt.Errorf("controlstate: claim public URL usage deliveries: claim: %w", err)
	}
	result = make([]PublicURLUsageDeliveryWork, 0, len(deliveries))
	for _, delivery := range deliveries {
		bucket, err := queries.GetPublicURLUsageBucketByID(ctx, delivery.BucketID)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrPublicURLUsageDeliveryInvalid
		}
		if err != nil {
			return nil, fmt.Errorf("controlstate: claim public URL usage deliveries: read bucket: %w", err)
		}
		work, err := publicURLUsageDeliveryWork(delivery, bucket)
		if err != nil {
			return nil, err
		}
		result = append(result, work)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("controlstate: claim public URL usage deliveries: commit: %w", err)
	}
	return result, nil
}

func (d *Database) CompletePublicURLUsageDelivery(
	ctx context.Context,
	work PublicURLUsageDeliveryWork,
	now time.Time,
) error {
	if err := validatePublicURLUsageDeliveryWork(work); err != nil {
		return err
	}
	if err := d.requireOpen(); err != nil {
		return err
	}
	if _, err := controlstatedb.New(d.pool).CompletePublicURLUsageDelivery(ctx, controlstatedb.CompletePublicURLUsageDeliveryParams{
		CompletedAt: timestamptz(now), DeliveryID: int64(work.DeliveryID),
		WorkOwner: text(work.WorkerID), WorkEpoch: positive(work.WorkEpoch),
	}); errors.Is(err, pgx.ErrNoRows) {
		return ErrPublicURLUsageDeliveryWorkStale
	} else if err != nil {
		return fmt.Errorf("controlstate: complete public URL usage delivery: %w", err)
	}
	return nil
}

func (d *Database) RetryPublicURLUsageDelivery(
	ctx context.Context,
	work PublicURLUsageDeliveryWork,
	availableAt time.Time,
	lastError string,
	now time.Time,
) error {
	if err := validatePublicURLUsageDeliveryWork(work); err != nil || !availableAt.After(now) ||
		lastError == "" || len(lastError) > 2048 {
		return ErrPublicURLUsageDeliveryInvalid
	}
	if err := d.requireOpen(); err != nil {
		return err
	}
	if _, err := controlstatedb.New(d.pool).RetryPublicURLUsageDelivery(ctx, controlstatedb.RetryPublicURLUsageDeliveryParams{
		AvailableAt: timestamptz(availableAt), LastError: text(lastError), DeliveryID: int64(work.DeliveryID),
		WorkOwner: text(work.WorkerID), WorkEpoch: positive(work.WorkEpoch), CompletedAt: timestamptz(now),
	}); errors.Is(err, pgx.ErrNoRows) {
		return ErrPublicURLUsageDeliveryWorkStale
	} else if err != nil {
		return fmt.Errorf("controlstate: retry public URL usage delivery: %w", err)
	}
	return nil
}

func (d *Database) RejectPublicURLUsageDelivery(
	ctx context.Context,
	work PublicURLUsageDeliveryWork,
	reason string,
	now time.Time,
) error {
	if err := validatePublicURLUsageDeliveryWork(work); err != nil || reason == "" || len(reason) > 2048 || now.IsZero() {
		return ErrPublicURLUsageDeliveryInvalid
	}
	if err := d.requireOpen(); err != nil {
		return err
	}
	if _, err := controlstatedb.New(d.pool).RejectPublicURLUsageDelivery(ctx, controlstatedb.RejectPublicURLUsageDeliveryParams{
		LastError: text(reason), DeliveryID: int64(work.DeliveryID),
		WorkOwner: text(work.WorkerID), WorkEpoch: positive(work.WorkEpoch), CompletedAt: timestamptz(now),
	}); errors.Is(err, pgx.ErrNoRows) {
		return ErrPublicURLUsageDeliveryWorkStale
	} else if err != nil {
		return fmt.Errorf("controlstate: reject public URL usage delivery: %w", err)
	}
	return nil
}

func publicURLUsageDeliveryWork(
	delivery controlstatedb.ControlPublicUrlUsageDelivery,
	bucket controlstatedb.ControlPublicUrlUsageBucket,
) (PublicURLUsageDeliveryWork, error) {
	checkpoint, err := aggregateIngressUsageHistogramData(bucket.HistogramData)
	if err != nil {
		return PublicURLUsageDeliveryWork{}, err
	}
	if delivery.DeliveryID <= 0 || !opaqueid.Valid(delivery.DeliveryKey, "usage_report_") ||
		delivery.SourceRevision <= 0 || delivery.SourceRevision != bucket.BucketRevision || bucket.PublishRunNumber <= 0 ||
		!validStateText(bucket.TeamID) || !validStateText(bucket.ActingIdentityID) ||
		!bucket.BucketStart.Valid || !bucket.BucketEnd.Valid || !bucket.ObservedThrough.Valid ||
		!delivery.WorkOwner.Valid || delivery.WorkEpoch <= 0 || !delivery.WorkExpiresAt.Valid || delivery.Attempts <= 0 {
		return PublicURLUsageDeliveryWork{}, ErrPublicURLUsageDeliveryInvalid
	}
	values := []int64{
		bucket.ConnectionAttempts, bucket.PolicyDenials, bucket.CapacityDenials, bucket.VisitorStreamOpenFailures,
		bucket.SuccessfulStreams, bucket.ConnectionNanoseconds, bucket.IngressBytes, bucket.EgressBytes,
	}
	for _, value := range values {
		if value < 0 {
			return PublicURLUsageDeliveryWork{}, ErrPublicURLUsageDeliveryInvalid
		}
	}
	return PublicURLUsageDeliveryWork{
		DeliveryID: uint64(delivery.DeliveryID), DeliveryKey: delivery.DeliveryKey,
		SourceRevision: uint64(delivery.SourceRevision), PublicURLID: bucket.PublicURLID,
		PublishRunNumber: uint64(bucket.PublishRunNumber), TeamID: bucket.TeamID, ActingIdentityID: bucket.ActingIdentityID,
		BucketStart: bucket.BucketStart.Time,
		BucketEnd:   bucket.BucketEnd.Time, ObservedThrough: bucket.ObservedThrough.Time,
		ConnectionAttempts: uint64(bucket.ConnectionAttempts), PolicyDenials: uint64(bucket.PolicyDenials),
		CapacityDenials: uint64(bucket.CapacityDenials), VisitorStreamOpenFailures: uint64(bucket.VisitorStreamOpenFailures),
		SuccessfulStreams: uint64(bucket.SuccessfulStreams), ConnectionNanoseconds: uint64(bucket.ConnectionNanoseconds),
		IngressBytes: uint64(bucket.IngressBytes), EgressBytes: uint64(bucket.EgressBytes),
		Checkpoint: checkpoint, Complete: bucket.Complete, Attempts: uint64(delivery.Attempts),
		WorkerID: delivery.WorkOwner.String, WorkEpoch: uint64(delivery.WorkEpoch), WorkExpiresAt: delivery.WorkExpiresAt.Time,
	}, nil
}

func validatePublicURLUsageDeliveryWork(work PublicURLUsageDeliveryWork) error {
	if work.DeliveryID == 0 || work.DeliveryID > math.MaxInt64 || !opaqueid.Valid(work.DeliveryKey, "usage_report_") ||
		!validStateText(work.WorkerID) || work.WorkEpoch == 0 || work.WorkEpoch > math.MaxInt64 || work.WorkExpiresAt.IsZero() {
		return ErrPublicURLUsageDeliveryInvalid
	}
	return nil
}

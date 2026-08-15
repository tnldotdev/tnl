package controlstate

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"slices"
	"sort"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/tnldotdev/tnl/internal/controlstate/controlstatedb"
	"github.com/tnldotdev/tnl/internal/opaqueid"
	"github.com/tnldotdev/tnl/internal/routeusage"
)

const (
	maximumIngressUsageReports       = 256
	maximumIngressUsageHistogramData = 1 << 20
	usageHistogramEnvelopeVersion    = 1
)

var (
	ErrIngressUsageReportInvalid   = errors.New("controlstate: ingress usage report is invalid")
	ErrIngressUsageReportStale     = errors.New("controlstate: ingress usage report revision is stale")
	ErrIngressUsageReportConflict  = errors.New("controlstate: ingress usage report conflicts with stored state")
	ErrIngressUsageRouteNotFound   = errors.New("controlstate: ingress usage route version was not found")
	ErrRouteUsageBucketFinalized   = errors.New("controlstate: route usage bucket is finalized")
	ErrRouteUsageDeliveryWorkStale = errors.New("controlstate: route usage delivery work is stale")
	ErrRouteUsageDeliveryInvalid   = errors.New("controlstate: route usage delivery work is invalid")
)

// IngressUsageReport contains cumulative usage for one ingress process, route
// version, and time bucket.
type IngressUsageReport struct {
	RouteID                   string
	RouteVersion              uint64
	BucketStart               time.Time
	BucketEnd                 time.Time
	ObservedThrough           time.Time
	ReportRevision            uint64
	ConnectionAttempts        uint64
	PolicyDenials             uint64
	CapacityDenials           uint64
	VisitorStreamOpenFailures uint64
	SuccessfulStreams         uint64
	ConnectionNanoseconds     uint64
	IngressBytes              uint64
	EgressBytes               uint64
	HistogramData             []byte
	Final                     bool
}

// IngressUsageBatch advances one ingress process run only after every report
// through the optional watermark has been committed.
type IngressUsageBatch struct {
	Reports         []IngressUsageReport
	ObservedThrough *time.Time
	Complete        bool
}

// ReportIngressUsage deduplicates cumulative reports and applies only numeric
// deltas to aggregate route usage buckets.
func (d *Database) ReportIngressUsage(
	ctx context.Context,
	identity IngressLeaseIdentity,
	batch IngressUsageBatch,
	receivedAt time.Time,
) (retErr error) {
	if err := validateIngressUsageBatch(batch); err != nil {
		return err
	}
	if err := d.requireOpen(); err != nil {
		return err
	}
	tx, err := d.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return fmt.Errorf("controlstate: report ingress usage: begin transaction: %w", err)
	}
	defer rollback(ctx, tx, "report ingress usage", &retErr)()
	queries := controlstatedb.New(tx)
	lease, err := lockCurrentIngressLease(ctx, queries, identity, receivedAt)
	if err != nil {
		return err
	}
	leaseRevision, _ := positiveInt64(identity.IngressLeaseRevision)
	run, err := queries.EnsureIngressUsageRun(ctx, controlstatedb.EnsureIngressUsageRunParams{
		IngressID: identity.IngressID, IngressRunID: identity.IngressRunID,
		IngressLeaseRevision: leaseRevision, StartedAt: lease.RegisteredAt,
		LeaseExpiresAt: lease.LeaseExpiresAt, ObservedThrough: lease.RegisteredAt,
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrIngressLeaseStale
	}
	if err != nil {
		return fmt.Errorf("controlstate: report ingress usage: ensure process run: %w", err)
	}

	if batch.ObservedThrough != nil && batch.ObservedThrough.Before(run.ObservedThrough.Time) {
		return ErrIngressUsageReportStale
	}
	if batch.ObservedThrough != nil && (batch.ObservedThrough.Before(run.StartedAt.Time) ||
		batch.ObservedThrough.After(lease.LeaseExpiresAt.Time)) {
		return ErrIngressUsageReportInvalid
	}
	ordered := slices.Clone(batch.Reports)
	sort.Slice(ordered, func(left, right int) bool {
		return compareIngressUsageReports(ordered[left], ordered[right]) < 0
	})
	for _, report := range ordered {
		if run.CoverageComplete && !batch.Complete {
			return ErrIngressUsageReportStale
		}
		if batch.ObservedThrough != nil && report.ObservedThrough.After(*batch.ObservedThrough) {
			return ErrIngressUsageReportInvalid
		}
		if report.ObservedThrough.After(lease.LeaseExpiresAt.Time) {
			return ErrIngressUsageReportInvalid
		}
		if err := applyIngressUsageReport(ctx, queries, identity, report, receivedAt); err != nil {
			return err
		}
	}
	var observedThrough pgtype.Timestamptz
	if batch.ObservedThrough != nil {
		observedThrough = timestamptz(*batch.ObservedThrough)
	}
	if _, err := queries.MarkIngressUsageRunReported(ctx, controlstatedb.MarkIngressUsageRunReportedParams{
		ReportedAt: timestamptz(receivedAt), ObservedThrough: observedThrough, Complete: batch.Complete,
		IngressID: identity.IngressID, IngressRunID: identity.IngressRunID,
		IngressLeaseRevision: leaseRevision,
	}); errors.Is(err, pgx.ErrNoRows) {
		return ErrIngressUsageReportStale
	} else if err != nil {
		return fmt.Errorf("controlstate: report ingress usage: update process run: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("controlstate: report ingress usage: commit: %w", err)
	}
	return nil
}

func applyIngressUsageReport(
	ctx context.Context,
	queries *controlstatedb.Queries,
	identity IngressLeaseIdentity,
	report IngressUsageReport,
	receivedAt time.Time,
) error {
	routeVersion, _ := positiveInt64(report.RouteVersion)
	reportRevision, _ := positiveInt64(report.ReportRevision)
	if _, err := queries.LockRouteForUsage(ctx, report.RouteID); errors.Is(err, pgx.ErrNoRows) {
		return ErrIngressUsageRouteNotFound
	} else if err != nil {
		return fmt.Errorf("controlstate: report ingress usage: lock route: %w", err)
	}
	if _, err := queries.LockRouteSessionForUsage(ctx, controlstatedb.LockRouteSessionForUsageParams{
		RouteID: report.RouteID, RouteVersion: routeVersion,
	}); errors.Is(err, pgx.ErrNoRows) {
		return ErrIngressUsageRouteNotFound
	} else if err != nil {
		return fmt.Errorf("controlstate: report ingress usage: lock route version: %w", err)
	}
	key := controlstatedb.GetLatestIngressUsageReportParams{
		IngressID: identity.IngressID, IngressRunID: identity.IngressRunID,
		RouteID: report.RouteID, RouteVersion: routeVersion, BucketStart: timestamptz(report.BucketStart),
	}
	previous, err := queries.GetLatestIngressUsageReport(ctx, key)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("controlstate: report ingress usage: read latest report: %w", err)
	}
	if err == nil && reportRevision <= previous.ReportRevision {
		stored, err := queries.GetIngressUsageReport(ctx, controlstatedb.GetIngressUsageReportParams{
			IngressID: key.IngressID, IngressRunID: key.IngressRunID, RouteID: key.RouteID,
			RouteVersion: key.RouteVersion, BucketStart: key.BucketStart, ReportRevision: reportRevision,
		})
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrIngressUsageReportStale
		}
		if err != nil {
			return fmt.Errorf("controlstate: report ingress usage: read replayed report: %w", err)
		}
		if !ingressUsageReportMatches(stored, report) {
			return ErrIngressUsageReportConflict
		}
		return nil
	}
	if err == nil && (previous.Final || !previous.BucketEnd.Valid || !previous.BucketEnd.Time.Equal(report.BucketEnd)) {
		return ErrIngressUsageReportConflict
	}

	delta, err := ingressUsageDelta(previous, report, errors.Is(err, pgx.ErrNoRows))
	if err != nil {
		return err
	}
	bucket, bucketErr := queries.GetRouteUsageBucketForUpdate(ctx, controlstatedb.GetRouteUsageBucketForUpdateParams{
		RouteID: report.RouteID, RouteVersion: routeVersion, BucketStart: timestamptz(report.BucketStart),
	})
	if bucketErr != nil && !errors.Is(bucketErr, pgx.ErrNoRows) {
		return fmt.Errorf("controlstate: report ingress usage: lock aggregate bucket: %w", bucketErr)
	}
	if bucketErr == nil && bucket.Finalized {
		return ErrRouteUsageBucketFinalized
	}
	mergedHistogramData, err := mergeIngressUsageHistogramData(
		bucket.HistogramData, bucketErr == nil, identity, report.HistogramData,
	)
	if err != nil {
		return err
	}
	if _, err := queries.InsertIngressUsageReport(ctx, ingressUsageReportParams(identity, report, receivedAt)); errors.Is(err, pgx.ErrNoRows) {
		return ErrIngressUsageReportConflict
	} else if err != nil {
		return fmt.Errorf("controlstate: report ingress usage: insert report: %w", err)
	}
	if _, err := queries.ApplyIngressUsageDelta(ctx, controlstatedb.ApplyIngressUsageDeltaParams{
		BucketStart: timestamptz(report.BucketStart), BucketEnd: timestamptz(report.BucketEnd),
		ObservedThrough: timestamptz(report.ObservedThrough), ConnectionAttempts: delta.connectionAttempts,
		PolicyDenials: delta.policyDenials, CapacityDenials: delta.capacityDenials,
		VisitorStreamOpenFailures: delta.visitorStreamOpenFailures, SuccessfulStreams: delta.successfulStreams,
		ConnectionNanoseconds: delta.connectionNanoseconds, IngressBytes: delta.ingressBytes,
		EgressBytes: delta.egressBytes, HistogramData: mergedHistogramData, UpdatedAt: timestamptz(receivedAt),
		RouteID: report.RouteID, RouteVersion: routeVersion,
	}); errors.Is(err, pgx.ErrNoRows) {
		return ErrRouteUsageBucketFinalized
	} else if err != nil {
		return fmt.Errorf("controlstate: report ingress usage: apply aggregate delta: %w", err)
	}
	if _, err := queries.ApplyRouteSessionPolicyDenials(ctx, controlstatedb.ApplyRouteSessionPolicyDenialsParams{
		PolicyDenials: delta.policyDenials, RouteID: report.RouteID, RouteVersion: routeVersion,
	}); errors.Is(err, pgx.ErrNoRows) {
		return errors.New("controlstate: route-session policy denial counter is exhausted")
	} else if err != nil {
		return fmt.Errorf("controlstate: report ingress usage: apply route-session policy denials: %w", err)
	}
	return nil
}

type ingressUsageCounters struct {
	connectionAttempts, policyDenials, capacityDenials, visitorStreamOpenFailures int64
	successfulStreams, connectionNanoseconds, ingressBytes, egressBytes           int64
}

func ingressUsageDelta(
	previous controlstatedb.ControlIngressUsageReport,
	report IngressUsageReport,
	first bool,
) (ingressUsageCounters, error) {
	current, ok := ingressUsageCountersFromReport(report)
	if !ok {
		return ingressUsageCounters{}, ErrIngressUsageReportInvalid
	}
	if first {
		return current, nil
	}
	stored := ingressUsageCounters{
		connectionAttempts: previous.ConnectionAttempts, policyDenials: previous.PolicyDenials,
		capacityDenials: previous.CapacityDenials, visitorStreamOpenFailures: previous.VisitorStreamOpenFailures,
		successfulStreams: previous.SuccessfulStreams, connectionNanoseconds: previous.ConnectionNanoseconds,
		ingressBytes: previous.IngressBytes, egressBytes: previous.EgressBytes,
	}
	if current.connectionAttempts < stored.connectionAttempts || current.policyDenials < stored.policyDenials ||
		current.capacityDenials < stored.capacityDenials ||
		current.visitorStreamOpenFailures < stored.visitorStreamOpenFailures ||
		current.successfulStreams < stored.successfulStreams ||
		current.connectionNanoseconds < stored.connectionNanoseconds ||
		current.ingressBytes < stored.ingressBytes || current.egressBytes < stored.egressBytes {
		return ingressUsageCounters{}, ErrIngressUsageReportConflict
	}
	return ingressUsageCounters{
		connectionAttempts:        current.connectionAttempts - stored.connectionAttempts,
		policyDenials:             current.policyDenials - stored.policyDenials,
		capacityDenials:           current.capacityDenials - stored.capacityDenials,
		visitorStreamOpenFailures: current.visitorStreamOpenFailures - stored.visitorStreamOpenFailures,
		successfulStreams:         current.successfulStreams - stored.successfulStreams,
		connectionNanoseconds:     current.connectionNanoseconds - stored.connectionNanoseconds,
		ingressBytes:              current.ingressBytes - stored.ingressBytes,
		egressBytes:               current.egressBytes - stored.egressBytes,
	}, nil
}

func ingressUsageCountersFromReport(report IngressUsageReport) (ingressUsageCounters, bool) {
	values := []uint64{
		report.ConnectionAttempts, report.PolicyDenials, report.CapacityDenials,
		report.VisitorStreamOpenFailures, report.SuccessfulStreams, report.ConnectionNanoseconds,
		report.IngressBytes, report.EgressBytes,
	}
	for _, value := range values {
		if value > math.MaxInt64 {
			return ingressUsageCounters{}, false
		}
	}
	return ingressUsageCounters{
		connectionAttempts: int64(report.ConnectionAttempts), policyDenials: int64(report.PolicyDenials),
		capacityDenials: int64(report.CapacityDenials), visitorStreamOpenFailures: int64(report.VisitorStreamOpenFailures),
		successfulStreams: int64(report.SuccessfulStreams), connectionNanoseconds: int64(report.ConnectionNanoseconds),
		ingressBytes: int64(report.IngressBytes), egressBytes: int64(report.EgressBytes),
	}, true
}

type ingressUsageHistogramEnvelope struct {
	Version int               `json:"version"`
	Runs    map[string][]byte `json:"runs"`
}

func mergeIngressUsageHistogramData(
	stored []byte,
	hasStored bool,
	identity IngressLeaseIdentity,
	report []byte,
) ([]byte, error) {
	envelope := ingressUsageHistogramEnvelope{Version: usageHistogramEnvelopeVersion, Runs: make(map[string][]byte)}
	if hasStored {
		decoder := json.NewDecoder(bytes.NewReader(stored))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&envelope); err != nil || envelope.Version != usageHistogramEnvelopeVersion || envelope.Runs == nil {
			return nil, errors.New("controlstate: stored ingress usage histogram data is invalid")
		}
	}
	envelope.Runs[identity.IngressID+"\x00"+identity.IngressRunID] = slices.Clone(report)
	encoded, err := json.Marshal(envelope)
	if err != nil {
		return nil, fmt.Errorf("controlstate: encode ingress usage histogram data: %w", err)
	}
	return encoded, nil
}

func aggregateIngressUsageHistogramData(data []byte) (routeusage.Checkpoint, error) {
	var envelope ingressUsageHistogramEnvelope
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&envelope); err != nil || envelope.Version != usageHistogramEnvelopeVersion || envelope.Runs == nil {
		return routeusage.Checkpoint{}, errors.New("controlstate: ingress usage histogram data is invalid")
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return routeusage.Checkpoint{}, errors.New("controlstate: ingress usage histogram data has trailing content")
	}
	var result routeusage.Checkpoint
	for _, data := range envelope.Runs {
		checkpoint, err := routeusage.ParseCheckpoint(data)
		if err != nil {
			return routeusage.Checkpoint{}, fmt.Errorf("controlstate: parse ingress usage checkpoint: %w", err)
		}
		if err := result.Merge(checkpoint); err != nil {
			return routeusage.Checkpoint{}, fmt.Errorf("controlstate: merge ingress usage checkpoint: %w", err)
		}
	}
	return result, nil
}

func validateIngressUsageBatch(batch IngressUsageBatch) error {
	if len(batch.Reports) > maximumIngressUsageReports || batch.Complete && batch.ObservedThrough == nil ||
		len(batch.Reports) == 0 && batch.ObservedThrough == nil {
		return ErrIngressUsageReportInvalid
	}
	if batch.ObservedThrough != nil && batch.ObservedThrough.IsZero() {
		return ErrIngressUsageReportInvalid
	}
	for _, report := range batch.Reports {
		if !validStateText(report.RouteID) || report.BucketStart.IsZero() || !report.BucketEnd.After(report.BucketStart) ||
			report.ObservedThrough.Before(report.BucketStart) || report.ObservedThrough.After(report.BucketEnd) ||
			len(report.HistogramData) > maximumIngressUsageHistogramData || batch.Complete && !report.Final {
			return ErrIngressUsageReportInvalid
		}
		if _, ok := positiveInt64(report.RouteVersion); !ok {
			return ErrIngressUsageReportInvalid
		}
		if _, ok := positiveInt64(report.ReportRevision); !ok {
			return ErrIngressUsageReportInvalid
		}
		if _, ok := ingressUsageCountersFromReport(report); !ok {
			return ErrIngressUsageReportInvalid
		}
		if _, err := routeusage.ParseCheckpoint(report.HistogramData); err != nil {
			return ErrIngressUsageReportInvalid
		}
	}
	return nil
}

func ingressUsageReportParams(
	identity IngressLeaseIdentity,
	report IngressUsageReport,
	receivedAt time.Time,
) controlstatedb.InsertIngressUsageReportParams {
	counters, _ := ingressUsageCountersFromReport(report)
	return controlstatedb.InsertIngressUsageReportParams{
		IngressID: identity.IngressID, IngressRunID: identity.IngressRunID,
		RouteID: report.RouteID, RouteVersion: positive(report.RouteVersion),
		BucketStart: timestamptz(report.BucketStart), BucketEnd: timestamptz(report.BucketEnd),
		ObservedThrough: timestamptz(report.ObservedThrough), ReportRevision: positive(report.ReportRevision),
		ConnectionAttempts: counters.connectionAttempts,
		PolicyDenials:      counters.policyDenials, CapacityDenials: counters.capacityDenials,
		VisitorStreamOpenFailures: counters.visitorStreamOpenFailures, SuccessfulStreams: counters.successfulStreams,
		ConnectionNanoseconds: counters.connectionNanoseconds, IngressBytes: counters.ingressBytes,
		EgressBytes: counters.egressBytes, HistogramData: slices.Clone(report.HistogramData),
		Final: report.Final, ReceivedAt: timestamptz(receivedAt),
	}
}

func ingressUsageReportMatches(stored controlstatedb.ControlIngressUsageReport, report IngressUsageReport) bool {
	counters, ok := ingressUsageCountersFromReport(report)
	return ok && stored.RouteID == report.RouteID && matchesPositiveInt64(stored.RouteVersion, report.RouteVersion) &&
		stored.BucketStart.Valid && stored.BucketStart.Time.Equal(report.BucketStart) &&
		stored.BucketEnd.Valid && stored.BucketEnd.Time.Equal(report.BucketEnd) &&
		stored.ObservedThrough.Valid && stored.ObservedThrough.Time.Equal(report.ObservedThrough) &&
		matchesPositiveInt64(stored.ReportRevision, report.ReportRevision) &&
		stored.ConnectionAttempts == counters.connectionAttempts && stored.PolicyDenials == counters.policyDenials &&
		stored.CapacityDenials == counters.capacityDenials && stored.VisitorStreamOpenFailures == counters.visitorStreamOpenFailures &&
		stored.SuccessfulStreams == counters.successfulStreams && stored.ConnectionNanoseconds == counters.connectionNanoseconds &&
		stored.IngressBytes == counters.ingressBytes && stored.EgressBytes == counters.egressBytes &&
		bytes.Equal(stored.HistogramData, report.HistogramData) && stored.Final == report.Final
}

func compareIngressUsageReports(left, right IngressUsageReport) int {
	if left.RouteID != right.RouteID {
		if left.RouteID < right.RouteID {
			return -1
		}
		return 1
	}
	if left.RouteVersion != right.RouteVersion {
		if left.RouteVersion < right.RouteVersion {
			return -1
		}
		return 1
	}
	if value := left.BucketStart.Compare(right.BucketStart); value != 0 {
		return value
	}
	if left.ReportRevision < right.ReportRevision {
		return -1
	}
	if left.ReportRevision > right.ReportRevision {
		return 1
	}
	return 0
}

// MarkExpiredIngressUsageRunsIncomplete records only the uncovered tail of
// process runs that ended without a final report.
func (d *Database) MarkExpiredIngressUsageRunsIncomplete(ctx context.Context, now time.Time) (int, error) {
	if err := d.requireOpen(); err != nil {
		return 0, err
	}
	runs, err := controlstatedb.New(d.pool).MarkExpiredIngressUsageRunsIncomplete(ctx, timestamptz(now))
	if err != nil {
		return 0, fmt.Errorf("controlstate: mark expired ingress usage runs incomplete: %w", err)
	}
	return len(runs), nil
}

// FinalizeRouteUsageBuckets closes aggregate buckets through a cutoff and
// creates one stored delivery record for each finalized revision.
func (d *Database) FinalizeRouteUsageBuckets(
	ctx context.Context,
	through time.Time,
	now time.Time,
) (result int, retErr error) {
	if through.After(now) {
		return 0, errors.New("controlstate: route usage finalization cutoff is in the future")
	}
	if err := d.requireOpen(); err != nil {
		return 0, err
	}
	tx, err := d.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return 0, fmt.Errorf("controlstate: finalize route usage buckets: begin transaction: %w", err)
	}
	defer rollback(ctx, tx, "finalize route usage buckets", &retErr)()
	queries := controlstatedb.New(tx)
	buckets, err := queries.FinalizeRouteUsageBuckets(ctx, controlstatedb.FinalizeRouteUsageBucketsParams{
		FinalizedAt: timestamptz(now), Through: timestamptz(through),
	})
	if err != nil {
		return 0, fmt.Errorf("controlstate: finalize route usage buckets: update buckets: %w", err)
	}
	for _, bucket := range buckets {
		deliveryKey, err := opaqueid.New("usage_report_")
		if err != nil {
			return 0, fmt.Errorf("controlstate: finalize route usage buckets: create delivery key: %w", err)
		}
		_, err = queries.InsertRouteUsageDelivery(ctx, controlstatedb.InsertRouteUsageDeliveryParams{
			BucketID: bucket.BucketID, SourceRevision: bucket.BucketRevision,
			DeliveryKey: deliveryKey,
			AvailableAt: timestamptz(now), CreatedAt: timestamptz(now),
		})
		if err != nil {
			return 0, fmt.Errorf("controlstate: finalize route usage buckets: insert delivery: %w", err)
		}
		result++
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, fmt.Errorf("controlstate: finalize route usage buckets: commit: %w", err)
	}
	return result, nil
}

// RouteUsageDeliveryWork is one immutable finalized bucket held under a
// PostgreSQL work lease.
type RouteUsageDeliveryWork struct {
	DeliveryID                uint64
	DeliveryKey               string
	SourceRevision            uint64
	RouteID                   string
	RouteVersion              uint64
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
	Checkpoint                routeusage.Checkpoint
	Complete                  bool
	Attempts                  uint64
	WorkerID                  string
	WorkEpoch                 uint64
	WorkExpiresAt             time.Time
}

// ClaimRouteUsageDeliveries claims up to batchSize finalized buckets.
func (d *Database) ClaimRouteUsageDeliveries(
	ctx context.Context,
	workerID string,
	batchSize int,
	now time.Time,
	leaseDuration time.Duration,
) (result []RouteUsageDeliveryWork, retErr error) {
	if !validStateText(workerID) || batchSize <= 0 || batchSize > 32 || leaseDuration <= 0 {
		return nil, ErrRouteUsageDeliveryInvalid
	}
	if err := d.requireOpen(); err != nil {
		return nil, err
	}
	tx, err := d.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return nil, fmt.Errorf("controlstate: claim route usage deliveries: begin transaction: %w", err)
	}
	defer rollback(ctx, tx, "claim route usage deliveries", &retErr)()
	queries := controlstatedb.New(tx)
	deliveries, err := queries.ClaimRouteUsageDeliveries(ctx, controlstatedb.ClaimRouteUsageDeliveriesParams{
		WorkOwner: text(workerID), WorkExpiresAt: timestamptz(now.Add(leaseDuration)),
		ClaimedAt: timestamptz(now), BatchSize: int32(batchSize),
	})
	if err != nil {
		return nil, fmt.Errorf("controlstate: claim route usage deliveries: claim: %w", err)
	}
	result = make([]RouteUsageDeliveryWork, 0, len(deliveries))
	for _, delivery := range deliveries {
		bucket, err := queries.GetRouteUsageBucketByID(ctx, delivery.BucketID)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrRouteUsageDeliveryInvalid
		}
		if err != nil {
			return nil, fmt.Errorf("controlstate: claim route usage deliveries: read bucket: %w", err)
		}
		work, err := routeUsageDeliveryWork(delivery, bucket)
		if err != nil {
			return nil, err
		}
		result = append(result, work)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("controlstate: claim route usage deliveries: commit: %w", err)
	}
	return result, nil
}

func (d *Database) CompleteRouteUsageDelivery(
	ctx context.Context,
	work RouteUsageDeliveryWork,
	now time.Time,
) error {
	if err := validateRouteUsageDeliveryWork(work); err != nil {
		return err
	}
	if err := d.requireOpen(); err != nil {
		return err
	}
	if _, err := controlstatedb.New(d.pool).CompleteRouteUsageDelivery(ctx, controlstatedb.CompleteRouteUsageDeliveryParams{
		CompletedAt: timestamptz(now), DeliveryID: int64(work.DeliveryID),
		WorkOwner: text(work.WorkerID), WorkEpoch: positive(work.WorkEpoch),
	}); errors.Is(err, pgx.ErrNoRows) {
		return ErrRouteUsageDeliveryWorkStale
	} else if err != nil {
		return fmt.Errorf("controlstate: complete route usage delivery: %w", err)
	}
	return nil
}

func (d *Database) RetryRouteUsageDelivery(
	ctx context.Context,
	work RouteUsageDeliveryWork,
	availableAt time.Time,
	lastError string,
	now time.Time,
) error {
	if err := validateRouteUsageDeliveryWork(work); err != nil || !availableAt.After(now) ||
		lastError == "" || len(lastError) > 2048 {
		return ErrRouteUsageDeliveryInvalid
	}
	if err := d.requireOpen(); err != nil {
		return err
	}
	if _, err := controlstatedb.New(d.pool).RetryRouteUsageDelivery(ctx, controlstatedb.RetryRouteUsageDeliveryParams{
		AvailableAt: timestamptz(availableAt), LastError: text(lastError), DeliveryID: int64(work.DeliveryID),
		WorkOwner: text(work.WorkerID), WorkEpoch: positive(work.WorkEpoch), CompletedAt: timestamptz(now),
	}); errors.Is(err, pgx.ErrNoRows) {
		return ErrRouteUsageDeliveryWorkStale
	} else if err != nil {
		return fmt.Errorf("controlstate: retry route usage delivery: %w", err)
	}
	return nil
}

func routeUsageDeliveryWork(
	delivery controlstatedb.ControlRouteUsageDelivery,
	bucket controlstatedb.ControlRouteUsageBucket,
) (RouteUsageDeliveryWork, error) {
	checkpoint, err := aggregateIngressUsageHistogramData(bucket.HistogramData)
	if err != nil {
		return RouteUsageDeliveryWork{}, err
	}
	if delivery.DeliveryID <= 0 || !opaqueid.Valid(delivery.DeliveryKey, "usage_report_") ||
		delivery.SourceRevision <= 0 || delivery.SourceRevision != bucket.BucketRevision || bucket.RouteVersion <= 0 ||
		!validStateText(bucket.TeamID) || !validStateText(bucket.ActingIdentityID) ||
		!bucket.BucketStart.Valid || !bucket.BucketEnd.Valid || !bucket.ObservedThrough.Valid ||
		!delivery.WorkOwner.Valid || delivery.WorkEpoch <= 0 || !delivery.WorkExpiresAt.Valid || delivery.Attempts <= 0 {
		return RouteUsageDeliveryWork{}, ErrRouteUsageDeliveryInvalid
	}
	values := []int64{
		bucket.ConnectionAttempts, bucket.PolicyDenials, bucket.CapacityDenials, bucket.VisitorStreamOpenFailures,
		bucket.SuccessfulStreams, bucket.ConnectionNanoseconds, bucket.IngressBytes, bucket.EgressBytes,
	}
	for _, value := range values {
		if value < 0 {
			return RouteUsageDeliveryWork{}, ErrRouteUsageDeliveryInvalid
		}
	}
	return RouteUsageDeliveryWork{
		DeliveryID: uint64(delivery.DeliveryID), DeliveryKey: delivery.DeliveryKey,
		SourceRevision: uint64(delivery.SourceRevision), RouteID: bucket.RouteID,
		RouteVersion: uint64(bucket.RouteVersion), TeamID: bucket.TeamID, ActingIdentityID: bucket.ActingIdentityID,
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

func validateRouteUsageDeliveryWork(work RouteUsageDeliveryWork) error {
	if work.DeliveryID == 0 || work.DeliveryID > math.MaxInt64 || !opaqueid.Valid(work.DeliveryKey, "usage_report_") ||
		!validStateText(work.WorkerID) || work.WorkEpoch == 0 || work.WorkEpoch > math.MaxInt64 || work.WorkExpiresAt.IsZero() {
		return ErrRouteUsageDeliveryInvalid
	}
	return nil
}

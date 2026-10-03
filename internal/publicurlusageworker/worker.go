// Package publicurlusageworker finishes and sends stored public URL usage reports.
package publicurlusageworker

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/tnldotdev/tnl/internal/controlstate"
	"github.com/tnldotdev/tnl/internal/observability"
	"github.com/tnldotdev/tnl/internal/publicurlusage"
	"github.com/tnldotdev/tnl/internal/workerloop"
	"github.com/tnldotdev/tnl/pkg/api/publicurlusagev1"
)

const (
	maximumBatchItems       = 32
	maximumRequestBytes     = 256 << 10
	maximumResponseBytes    = 64 << 10
	defaultLeaseDuration    = 2 * time.Minute
	defaultOperationTimeout = 10 * time.Second
	defaultPollInterval     = time.Second
	defaultRetryInterval    = time.Second
)

var errBatchTooLarge = errors.New("publicurlusageworker: request exceeds size limit")

// Store is the stored public URL usage state used by a Worker.
type Store interface {
	MarkExpiredIngressUsageRunsIncomplete(context.Context, time.Time) (int, error)
	FinalizePublicURLUsageBuckets(context.Context, time.Time, time.Time) (int, error)
	ClaimPublicURLUsageDeliveries(context.Context, string, int, time.Time, time.Duration) ([]controlstate.PublicURLUsageDeliveryWork, error)
	CompletePublicURLUsageDelivery(context.Context, controlstate.PublicURLUsageDeliveryWork, time.Time) error
	RetryPublicURLUsageDelivery(context.Context, controlstate.PublicURLUsageDeliveryWork, time.Time, string, time.Time) error
	RejectPublicURLUsageDelivery(context.Context, controlstate.PublicURLUsageDeliveryWork, string, time.Time) error
}

type publicURLUsageAPI interface {
	IngestPublicURLUsageBucketReportsWithBody(context.Context, string, io.Reader, ...publicurlusagev1.RequestEditorFn) (*http.Response, error)
}

type Config struct {
	WorkerID         string
	Endpoint         string
	Token            string
	HTTPClient       *http.Client
	Logger           *slog.Logger
	Observer         UsageObserver
	LeaseDuration    time.Duration
	OperationTimeout time.Duration
	PollInterval     time.Duration
	RetryInterval    time.Duration
}

type UsageObserver interface {
	ObserveUsageWork(phase string, outcome observability.UsageWorkOutcome)
	AddUsageItems(result string, count int)
	ObserveUsageReceiver(outcome observability.UsageReceiverOutcome, elapsed time.Duration)
}

type Worker struct {
	store  Store
	config Config
	now    func() time.Time
	api    publicURLUsageAPI
}

func New(store Store, config Config) (*Worker, error) {
	if store == nil || strings.TrimSpace(config.WorkerID) != config.WorkerID || config.WorkerID == "" ||
		(config.Endpoint == "") != (config.Token == "") {
		return nil, errors.New("publicurlusageworker: invalid configuration")
	}
	if config.Logger == nil {
		config.Logger = slog.Default()
	}
	if config.LeaseDuration <= 0 {
		config.LeaseDuration = defaultLeaseDuration
	}
	if config.OperationTimeout <= 0 {
		config.OperationTimeout = defaultOperationTimeout
	}
	if config.PollInterval <= 0 {
		config.PollInterval = defaultPollInterval
	}
	if config.RetryInterval <= 0 {
		config.RetryInterval = defaultRetryInterval
	}
	if config.OperationTimeout >= config.LeaseDuration {
		return nil, errors.New("publicurlusageworker: operation timeout must be shorter than the work lease")
	}
	worker := &Worker{store: store, config: config, now: func() time.Time { return time.Now().UTC() }}
	if config.Endpoint == "" {
		return worker, nil
	}
	httpClient := http.Client{Timeout: config.OperationTimeout}
	if config.HTTPClient != nil {
		httpClient = *config.HTTPClient
		httpClient.Timeout = config.OperationTimeout
	}
	httpClient.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	client, err := publicurlusagev1.NewClient(
		config.Endpoint,
		publicurlusagev1.WithHTTPClient(&httpClient),
		publicurlusagev1.WithRequestEditorFn(func(_ context.Context, request *http.Request) error {
			request.Header.Set("Authorization", "Bearer "+config.Token)
			return nil
		}),
	)
	if err != nil {
		return nil, fmt.Errorf("publicurlusageworker: configure client: %w", err)
	}
	worker.api = client
	return worker, nil
}

func (w *Worker) Run(ctx context.Context) error {
	return workerloop.Run(ctx, workerloop.Config{
		OperationTimeout: w.config.OperationTimeout,
		IdleInterval:     w.config.PollInterval,
		Process:          w.process,
		OnError: func(err error) {
			if ctx.Err() == nil {
				w.config.Logger.Error("public URL usage worker iteration failed", "error", err)
			}
		},
	})
}

func (w *Worker) process(ctx context.Context) (bool, error) {
	now := w.now()
	incomplete, err := w.store.MarkExpiredIngressUsageRunsIncomplete(ctx, now)
	w.observeWork("incomplete_runs", err)
	if err != nil {
		return false, err
	}
	w.addItems("incomplete", incomplete)
	finalized, err := w.store.FinalizePublicURLUsageBuckets(ctx, now.Truncate(time.Minute), now)
	w.observeWork("finalize", err)
	if err != nil {
		return false, err
	}
	w.addItems("finalized", finalized)
	if w.api == nil {
		return false, nil
	}
	work, err := w.store.ClaimPublicURLUsageDeliveries(ctx, w.config.WorkerID, maximumBatchItems, now, w.config.LeaseDuration)
	w.observeClaim(len(work) != 0, err)
	if err != nil || len(work) == 0 {
		return false, err
	}
	return true, w.deliver(ctx, work)
}

func (w *Worker) deliver(ctx context.Context, work []controlstate.PublicURLUsageDeliveryWork) error {
	results, err := w.send(ctx, work)
	w.observeWork("deliver", err)
	completedAt := w.now()
	if errors.Is(err, errBatchTooLarge) {
		// split an oversized batch without dropping its work leases. a single
		// oversized report cannot be delivered and is rejected permanently.
		if len(work) > 1 {
			middle := len(work) / 2
			return errors.Join(w.deliver(ctx, work[:middle]), w.deliver(ctx, work[middle:]))
		}
		rejectErr := w.store.RejectPublicURLUsageDelivery(ctx, work[0], err.Error(), completedAt)
		w.observeWork("reject", rejectErr)
		if rejectErr == nil {
			w.addItems("rejected", 1)
		}
		return errors.Join(err, rejectErr)
	}
	if err != nil {
		// a transport or response failure leaves every item eligible for retry.
		return errors.Join(err, w.retry(ctx, work, completedAt, err.Error()))
	}
	var result error
	for index, item := range work {
		response := results[item.DeliveryKey]
		if response.Accepted {
			completeErr := w.store.CompletePublicURLUsageDelivery(ctx, item, completedAt)
			w.observeWork("complete", completeErr)
			if completeErr == nil {
				w.addItems("accepted", 1)
			}
			result = errors.Join(result, completeErr)
			continue
		}
		rejection := fmt.Errorf("publicurlusageworker: receiver rejected %s with %s", item.DeliveryKey, *response.Code)
		if *response.Code == publicurlusagev1.BatchProblemCodeInvalidArgument {
			// reject only this invalid item; retryable items release their leases
			// and become available for a later claim.
			rejectErr := w.store.RejectPublicURLUsageDelivery(ctx, item, string(*response.Code), completedAt)
			w.observeWork("reject", rejectErr)
			if rejectErr == nil {
				w.addItems("rejected", 1)
			}
			result = errors.Join(result, rejection, rejectErr)
		} else {
			result = errors.Join(result, rejection, w.retry(ctx, work[index:index+1], completedAt, string(*response.Code)))
		}
	}
	return result
}

func (w *Worker) send(
	ctx context.Context,
	work []controlstate.PublicURLUsageDeliveryWork,
) (results map[string]publicurlusagev1.BatchResult, retErr error) {
	items := make([]publicurlusagev1.PublicURLUsageBucketReport, len(work))
	ids := make(map[string]struct{}, len(work))
	for index, item := range work {
		items[index] = usageBucketReport(item)
		ids[item.DeliveryKey] = struct{}{}
	}
	body, err := json.Marshal(publicurlusagev1.PublicURLUsageBucketReportBatch{Items: items})
	if err != nil {
		return nil, fmt.Errorf("publicurlusageworker: encode batch: %w", err)
	}
	if len(body) > maximumRequestBytes {
		return nil, errBatchTooLarge
	}
	started := time.Now()
	outcome := observability.UsageReceiverInvalidResponse
	defer func() {
		if w.config.Observer != nil {
			w.config.Observer.ObserveUsageReceiver(outcome, time.Since(started))
		}
	}()
	response, err := w.api.IngestPublicURLUsageBucketReportsWithBody(ctx, "application/json", bytes.NewReader(body))
	if err != nil {
		outcome = observability.UsageReceiverTransportError
		return nil, fmt.Errorf("publicurlusageworker: send batch: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		outcome = observability.UsageReceiverHTTPError
		if response.StatusCode == http.StatusRequestEntityTooLarge {
			return nil, fmt.Errorf("%w: receiver returned HTTP %d", errBatchTooLarge, response.StatusCode)
		}
		return nil, fmt.Errorf("publicurlusageworker: receiver returned HTTP %d", response.StatusCode)
	}
	reader := io.LimitReader(response.Body, maximumResponseBytes+1)
	responseBody, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("publicurlusageworker: read response: %w", err)
	}
	if len(responseBody) > maximumResponseBytes {
		return nil, errors.New("publicurlusageworker: response exceeds size limit")
	}
	var batch publicurlusagev1.PublicURLUsageBucketReportBatchResponse
	decoder := json.NewDecoder(bytes.NewReader(responseBody))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&batch); err != nil {
		return nil, fmt.Errorf("publicurlusageworker: decode response: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return nil, errors.New("publicurlusageworker: response contains trailing data")
	}
	if len(batch.Results) != len(work) {
		return nil, errors.New("publicurlusageworker: response result count does not match request")
	}
	results = make(map[string]publicurlusagev1.BatchResult, len(batch.Results))
	for _, result := range batch.Results {
		if _, expected := ids[result.ItemId]; !expected {
			return nil, errors.New("publicurlusageworker: response contains an unknown item ID")
		}
		if _, duplicate := results[result.ItemId]; duplicate {
			return nil, errors.New("publicurlusageworker: response contains a duplicate item ID")
		}
		if result.Accepted != (result.Code == nil) || result.Code != nil && !result.Code.Valid() {
			return nil, errors.New("publicurlusageworker: response contains an invalid item result")
		}
		results[result.ItemId] = result
	}
	outcome = observability.UsageReceiverSuccess
	return results, nil
}

func (w *Worker) retry(
	ctx context.Context,
	work []controlstate.PublicURLUsageDeliveryWork,
	now time.Time,
	message string,
) error {
	if message == "" {
		message = "public URL usage delivery failed"
	}
	if len(message) > 2048 {
		message = message[:2048]
	}
	var result error
	for _, item := range work {
		delay := w.config.RetryInterval
		for attempt := uint64(1); attempt < item.Attempts && delay < time.Minute; attempt++ {
			delay = min(delay*2, time.Minute)
		}
		retryErr := w.store.RetryPublicURLUsageDelivery(ctx, item, now.Add(delay), message, now)
		w.observeWork("retry", retryErr)
		if retryErr == nil {
			w.addItems("retried", 1)
		}
		result = errors.Join(result, retryErr)
	}
	return result
}

func (w *Worker) observeWork(phase string, err error) {
	if w.config.Observer == nil {
		return
	}
	outcome := observability.UsageWorkSuccess
	if err != nil {
		outcome = observability.UsageWorkError
	}
	w.config.Observer.ObserveUsageWork(phase, outcome)
}

func (w *Worker) observeClaim(found bool, err error) {
	if w.config.Observer == nil {
		return
	}
	outcome := observability.UsageWorkSuccess
	if err != nil {
		outcome = observability.UsageWorkError
	} else if !found {
		outcome = observability.UsageWorkEmpty
	}
	w.config.Observer.ObserveUsageWork("claim", outcome)
}

func (w *Worker) addItems(result string, count int) {
	if w.config.Observer != nil {
		w.config.Observer.AddUsageItems(result, count)
	}
}

func usageBucketReport(work controlstate.PublicURLUsageDeliveryWork) publicurlusagev1.PublicURLUsageBucketReport {
	checkpoint := work.Checkpoint
	return publicurlusagev1.PublicURLUsageBucketReport{
		ItemId: work.DeliveryKey, PublicUrlId: work.PublicURLID, PublishRunNumber: strconv.FormatUint(work.PublishRunNumber, 10),
		TeamId: work.TeamID, ActingIdentityId: work.ActingIdentityID,
		Resolution: publicurlusagev1.Minute, BucketStart: wireTimestamp(work.BucketStart),
		ReportRevision: strconv.FormatUint(work.SourceRevision, 10), ObservedThrough: wireTimestamp(work.ObservedThrough),
		ConnectionAttempts: strconv.FormatUint(work.ConnectionAttempts, 10),
		PolicyDenials:      strconv.FormatUint(work.PolicyDenials, 10), CapacityDenials: strconv.FormatUint(work.CapacityDenials, 10),
		VisitorStreamOpenFailures: strconv.FormatUint(work.VisitorStreamOpenFailures, 10),
		SuccessfulStreams:         strconv.FormatUint(work.SuccessfulStreams, 10),
		ConnectionNanoseconds:     strconv.FormatUint(work.ConnectionNanoseconds, 10),
		IngressBytes:              strconv.FormatUint(work.IngressBytes, 10), EgressBytes: strconv.FormatUint(work.EgressBytes, 10),
		VisitorStreamOpenLatency:     durationHistogram(checkpoint.VisitorStreamOpenLatency),
		TimeToFirstPublisherByte:     durationHistogram(checkpoint.TimeToFirstPublisherByte),
		SuccessfulConnectionDuration: durationHistogram(checkpoint.SuccessfulConnectionDuration),
		VisitorNetworkEstimate:       strconv.FormatUint(checkpoint.VisitorNetworks.Estimate(), 10),
		VisitorNetworkHll:            checkpoint.VisitorNetworks.MarshalBinary(), Complete: work.Complete,
	}
}

func durationHistogram(histogram publicurlusage.DurationHistogram) *publicurlusagev1.DurationHistogram {
	if histogram.Count() == 0 {
		return nil
	}
	counts := histogram.CumulativeCounts()
	result := &publicurlusagev1.DurationHistogram{
		Count:            strconv.FormatUint(histogram.Count(), 10),
		SumNanoseconds:   strconv.FormatUint(histogram.SumNanoseconds(), 10),
		CumulativeCounts: make([]string, len(counts)),
	}
	for index, count := range counts {
		result.CumulativeCounts[index] = strconv.FormatUint(count, 10)
	}
	return result
}

func wireTimestamp(value time.Time) time.Time { return value.UTC().Truncate(time.Millisecond) }

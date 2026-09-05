// Package routeusageworker finalizes and delivers durable route usage.
package routeusageworker

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
	"github.com/tnldotdev/tnl/internal/routeusage"
	"github.com/tnldotdev/tnl/pkg/api/routeusagev1"
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

// Store is the durable route usage state consumed by a Worker.
type Store interface {
	MarkExpiredIngressUsageRunsIncomplete(context.Context, time.Time) (int, error)
	FinalizeRouteUsageBuckets(context.Context, time.Time, time.Time) (int, error)
	ClaimRouteUsageDeliveries(context.Context, string, int, time.Time, time.Duration) ([]controlstate.RouteUsageDeliveryWork, error)
	CompleteRouteUsageDelivery(context.Context, controlstate.RouteUsageDeliveryWork, time.Time) error
	RetryRouteUsageDelivery(context.Context, controlstate.RouteUsageDeliveryWork, time.Time, string, time.Time) error
}

type routeUsageAPI interface {
	IngestRouteUsageBucketReportsWithBody(context.Context, string, io.Reader, ...routeusagev1.RequestEditorFn) (*http.Response, error)
}

type Config struct {
	WorkerID         string
	Endpoint         string
	Token            string
	HTTPClient       *http.Client
	Logger           *slog.Logger
	LeaseDuration    time.Duration
	OperationTimeout time.Duration
	PollInterval     time.Duration
	RetryInterval    time.Duration
}

type Worker struct {
	store  Store
	config Config
	now    func() time.Time
	api    routeUsageAPI
}

func New(store Store, config Config) (*Worker, error) {
	if store == nil || strings.TrimSpace(config.WorkerID) != config.WorkerID || config.WorkerID == "" ||
		(config.Endpoint == "") != (config.Token == "") {
		return nil, errors.New("routeusageworker: invalid configuration")
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
		return nil, errors.New("routeusageworker: operation timeout must be shorter than the work lease")
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
	client, err := routeusagev1.NewClient(
		config.Endpoint,
		routeusagev1.WithHTTPClient(&httpClient),
		routeusagev1.WithRequestEditorFn(func(_ context.Context, request *http.Request) error {
			request.Header.Set("Authorization", "Bearer "+config.Token)
			return nil
		}),
	)
	if err != nil {
		return nil, fmt.Errorf("routeusageworker: configure client: %w", err)
	}
	worker.api = client
	return worker, nil
}

func (w *Worker) Run(ctx context.Context) error {
	timer := time.NewTimer(0)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-timer.C:
		}
		operationCtx, cancel := context.WithTimeout(ctx, w.config.OperationTimeout)
		found, err := w.process(operationCtx)
		cancel()
		if err != nil && ctx.Err() == nil {
			w.config.Logger.Error("route usage worker iteration failed", "error", err)
		}
		delay := time.Duration(0)
		if !found || err != nil {
			delay = w.config.PollInterval
		}
		timer.Reset(delay)
	}
}

func (w *Worker) process(ctx context.Context) (bool, error) {
	now := w.now()
	if _, err := w.store.MarkExpiredIngressUsageRunsIncomplete(ctx, now); err != nil {
		return false, err
	}
	if _, err := w.store.FinalizeRouteUsageBuckets(ctx, now.Truncate(time.Minute), now); err != nil {
		return false, err
	}
	if w.api == nil {
		return false, nil
	}
	work, err := w.store.ClaimRouteUsageDeliveries(ctx, w.config.WorkerID, maximumBatchItems, now, w.config.LeaseDuration)
	if err != nil || len(work) == 0 {
		return false, err
	}
	results, err := w.send(ctx, work)
	completedAt := w.now()
	if err != nil {
		return true, errors.Join(err, w.retry(ctx, work, completedAt, err.Error()))
	}
	var result error
	for index, item := range work {
		response := results[item.DeliveryKey]
		if response.Accepted {
			result = errors.Join(result, w.store.CompleteRouteUsageDelivery(ctx, item, completedAt))
			continue
		}
		rejection := fmt.Errorf("routeusageworker: receiver rejected %s with %s", item.DeliveryKey, *response.Code)
		result = errors.Join(result, rejection, w.retry(ctx, work[index:index+1], completedAt, string(*response.Code)))
	}
	return true, result
}

func (w *Worker) send(
	ctx context.Context,
	work []controlstate.RouteUsageDeliveryWork,
) (map[string]routeusagev1.BatchResult, error) {
	items := make([]routeusagev1.RouteUsageBucketReport, len(work))
	ids := make(map[string]struct{}, len(work))
	for index, item := range work {
		items[index] = usageBucketReport(item)
		ids[item.DeliveryKey] = struct{}{}
	}
	body, err := json.Marshal(routeusagev1.RouteUsageBucketReportBatch{Items: items})
	if err != nil {
		return nil, fmt.Errorf("routeusageworker: encode batch: %w", err)
	}
	if len(body) > maximumRequestBytes {
		return nil, errors.New("routeusageworker: request exceeds size limit")
	}
	response, err := w.api.IngestRouteUsageBucketReportsWithBody(ctx, "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("routeusageworker: send batch: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("routeusageworker: receiver returned HTTP %d", response.StatusCode)
	}
	reader := io.LimitReader(response.Body, maximumResponseBytes+1)
	responseBody, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("routeusageworker: read response: %w", err)
	}
	if len(responseBody) > maximumResponseBytes {
		return nil, errors.New("routeusageworker: response exceeds size limit")
	}
	var batch routeusagev1.RouteUsageBucketReportBatchResponse
	decoder := json.NewDecoder(bytes.NewReader(responseBody))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&batch); err != nil {
		return nil, fmt.Errorf("routeusageworker: decode response: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return nil, errors.New("routeusageworker: response contains trailing data")
	}
	if len(batch.Results) != len(work) {
		return nil, errors.New("routeusageworker: response result count does not match request")
	}
	results := make(map[string]routeusagev1.BatchResult, len(batch.Results))
	for _, result := range batch.Results {
		if _, expected := ids[result.ItemId]; !expected {
			return nil, errors.New("routeusageworker: response contains an unknown item ID")
		}
		if _, duplicate := results[result.ItemId]; duplicate {
			return nil, errors.New("routeusageworker: response contains a duplicate item ID")
		}
		if result.Accepted != (result.Code == nil) || result.Code != nil && !result.Code.Valid() {
			return nil, errors.New("routeusageworker: response contains an invalid item result")
		}
		results[result.ItemId] = result
	}
	return results, nil
}

func (w *Worker) retry(
	ctx context.Context,
	work []controlstate.RouteUsageDeliveryWork,
	now time.Time,
	message string,
) error {
	if message == "" {
		message = "route usage delivery failed"
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
		result = errors.Join(result, w.store.RetryRouteUsageDelivery(ctx, item, now.Add(delay), message, now))
	}
	return result
}

func usageBucketReport(work controlstate.RouteUsageDeliveryWork) routeusagev1.RouteUsageBucketReport {
	checkpoint := work.Checkpoint
	return routeusagev1.RouteUsageBucketReport{
		ItemId: work.DeliveryKey, RouteId: work.RouteID, RouteVersion: strconv.FormatUint(work.RouteVersion, 10),
		TeamId: work.TeamID, ActingIdentityId: work.ActingIdentityID,
		Resolution: routeusagev1.Minute, BucketStart: wireTimestamp(work.BucketStart),
		Revision: strconv.FormatUint(work.SourceRevision, 10), ObservedThrough: wireTimestamp(work.ObservedThrough),
		ConnectionAttempts: strconv.FormatUint(work.ConnectionAttempts, 10),
		PolicyDenials:      strconv.FormatUint(work.PolicyDenials, 10), CapacityDenials: strconv.FormatUint(work.CapacityDenials, 10),
		PublisherOpenFailures: strconv.FormatUint(work.PublisherOpenFailures, 10),
		SuccessfulStreams:     strconv.FormatUint(work.SuccessfulStreams, 10),
		ConnectionNanoseconds: strconv.FormatUint(work.ConnectionNanoseconds, 10),
		IngressBytes:          strconv.FormatUint(work.IngressBytes, 10), EgressBytes: strconv.FormatUint(work.EgressBytes, 10),
		PublisherOpenLatency:         durationHistogram(checkpoint.PublisherOpenLatency),
		TimeToFirstPublisherByte:     durationHistogram(checkpoint.TimeToFirstPublisherByte),
		SuccessfulConnectionDuration: durationHistogram(checkpoint.SuccessfulConnectionDuration),
		VisitorNetworkEstimate:       strconv.FormatUint(checkpoint.VisitorNetworks.Estimate(), 10),
		VisitorNetworkHll:            checkpoint.VisitorNetworks.MarshalBinary(), Complete: work.Complete,
	}
}

func durationHistogram(histogram routeusage.DurationHistogram) *routeusagev1.DurationHistogram {
	if histogram.Count() == 0 {
		return nil
	}
	counts := histogram.CumulativeCounts()
	result := &routeusagev1.DurationHistogram{
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

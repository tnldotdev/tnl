package routeusage

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/tnldotdev/tnl/internal/state/statedb"
	"github.com/tnldotdev/tnl/pkg/protocol/routeusagev1"
)

const (
	requestTimeout       = 10 * time.Second
	maximumBatchItems    = 32
	maximumRequestBytes  = 256 * 1024
	maximumResponseBytes = 64 * 1024
)

type Sender struct {
	store    *Store
	baseURL  *url.URL
	token    string
	client   *http.Client
	observer Observer
}

func NewSender(store *Store, rawURL, token string, observer Observer) (*Sender, error) {
	baseURL, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("routeusage: parse route usage URL: %w", err)
	}
	return &Sender{
		store: store, baseURL: baseURL, token: token, observer: observer,
		client: &http.Client{
			Timeout:       requestTimeout,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}, nil
}

func (p *Sender) Run(ctx context.Context, report func(error)) {
	backoff := time.Second
	prune := time.NewTicker(time.Hour)
	defer prune.Stop()
	poll := time.NewTicker(time.Second)
	defer poll.Stop()
	for {
		delivered, err := p.SendOne(ctx)
		if err == nil && delivered {
			backoff = time.Second
			continue
		}
		if err != nil && report != nil && !errors.Is(err, context.Canceled) {
			report(err)
		}
		var delay <-chan time.Time
		var pollReady <-chan time.Time
		var pruneReady <-chan time.Time
		var wake <-chan struct{}
		var timer *time.Timer
		if err != nil {
			jitter := time.Duration(rand.Int64N(int64(backoff / 2)))
			timer = time.NewTimer(backoff + jitter)
			delay = timer.C
			backoff = min(backoff*2, 30*time.Second)
		} else {
			pollReady = poll.C
			pruneReady = prune.C
			wake = p.store.wake
		}
		select {
		case <-ctx.Done():
			if timer != nil {
				timer.Stop()
			}
			return
		case <-wake:
		case <-delay:
		case <-pollReady:
		case now := <-pruneReady:
			if pruneErr := p.store.pruneLifecycle(ctx, now.UTC()); pruneErr != nil && report != nil {
				report(pruneErr)
			}
		}
	}
}

func (p *Sender) SendOne(ctx context.Context) (bool, error) {
	item, err := p.store.queries.GetNextRouteUsageOutboxItem(ctx)
	if errors.Is(err, sql.ErrNoRows) {
		p.updateOutbox(ctx)
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("routeusage: read outbox: %w", err)
	}
	var kind string
	switch item.SourceKind {
	case registrationSource:
		kind = "registration"
		err = p.sendRegistration(ctx, item)
	case lifecycleSource:
		kind = "lifecycle"
		err = p.sendLifecycleBatch(ctx)
	case usageSource:
		kind = "usage"
		err = p.sendUsageBatch(ctx)
	default:
		return false, fmt.Errorf("routeusage: unknown outbox source %q", item.SourceKind)
	}
	p.observe(ctx, kind, err)
	return true, err
}

func (p *Sender) observe(ctx context.Context, kind string, deliveryErr error) {
	if p.observer == nil {
		return
	}
	result := "success"
	if deliveryErr != nil {
		result = "error"
	}
	p.observer.ObserveRouteUsageDelivery(kind, result)
	p.updateOutbox(ctx)
}

func (p *Sender) updateOutbox(ctx context.Context) {
	if p.observer == nil {
		return
	}
	registration, lifecycle, usage, age, err := p.store.outboxStats(ctx, time.Now())
	if err != nil {
		return
	}
	p.observer.SetRouteUsageOutbox("registration", registration)
	p.observer.SetRouteUsageOutbox("lifecycle", lifecycle)
	p.observer.SetRouteUsageOutbox("usage", usage)
	p.observer.SetRouteUsageOldestAge(age)
}

func (p *Sender) sendRegistration(ctx context.Context, item statedb.RouteUsageOutboxItem) error {
	marked, err := p.store.markAttempted(ctx, []outboxRevision{{
		kind: registrationSource, sourceID: item.SourceID, revision: item.SourceRevision,
	}})
	if err != nil || !marked {
		return err
	}
	registration, err := p.store.queries.GetRouteRegistrationReport(ctx, item.SourceID)
	if err != nil {
		return fmt.Errorf("routeusage: read route registration: %w", err)
	}
	payload := routeusagev1.RouteRegistration{
		RegistrationId:  registration.RegistrationID,
		RouteId:         registration.RouteID,
		Hostname:        registration.Hostname,
		SigningKeyId:    registration.SigningKeyID,
		AuthorizationId: registration.AuthorizationID,
		CreatedAt:       wireTimestamp(time.Unix(0, registration.CreatedAt)),
		RetryId:         registration.RetryID,
	}
	if err := p.post(ctx, "/v1/routes", payload); err != nil {
		return err
	}
	acknowledged, err := p.store.acknowledgeRegistration(ctx, item.SourceID, item.SourceRevision)
	if err != nil {
		return err
	}
	if !acknowledged {
		return errors.New("routeusage: registration revision changed before acknowledgment")
	}
	return nil
}

func (p *Sender) sendLifecycleBatch(ctx context.Context) error {
	rows, err := p.store.queries.ListRouteLifecycleOutboxBatch(ctx, maximumBatchItems)
	if err != nil {
		return fmt.Errorf("routeusage: read lifecycle batch: %w", err)
	}
	items := make([]routeusagev1.RouteLifecycleEvent, len(rows))
	for index, event := range rows {
		items[index] = routeusagev1.RouteLifecycleEvent{
			ItemId: event.EventID, RouteId: event.RouteID, Version: strconv.FormatInt(event.Version, 10),
			Sequence: strconv.FormatInt(event.Sequence, 10), OccurredAt: wireTimestamp(time.Unix(0, event.OccurredAt)),
			Transition: routeusagev1.RouteLifecycleEventTransition(event.Transition),
		}
	}
	count, body, err := encodeBatch(items)
	if err != nil {
		return err
	}
	rows = rows[:count]
	references := make([]outboxRevision, count)
	itemIDs := make([]string, count)
	byID := make(map[string]outboxRevision, count)
	for index, row := range rows {
		reference := outboxRevision{kind: lifecycleSource, sourceID: row.SourceID, revision: row.SourceRevision}
		references[index], itemIDs[index], byID[row.EventID] = reference, row.EventID, reference
	}
	marked, err := p.store.markAttempted(ctx, references)
	if err != nil || !marked {
		return err
	}
	accepted, rejected, err := p.postBatch(ctx, "/v1/routes/lifecycle-events", body, itemIDs)
	if err != nil {
		return err
	}
	acknowledged := make([]outboxRevision, 0, len(accepted))
	for _, itemID := range accepted {
		acknowledged = append(acknowledged, byID[itemID])
	}
	if err := p.store.acknowledgeLifecycleBatch(ctx, acknowledged); err != nil {
		return err
	}
	if rejected {
		return errors.New("routeusage: receiver rejected lifecycle batch items")
	}
	return nil
}

func (p *Sender) sendUsageBatch(ctx context.Context) error {
	rows, err := p.store.queries.ListRouteUsageOutboxBatch(ctx, maximumBatchItems)
	if err != nil {
		return fmt.Errorf("routeusage: read usage batch: %w", err)
	}
	items := make([]routeusagev1.RouteUsageSnapshot, len(rows))
	for index, bucket := range rows {
		publisherOpenLatency, err := protocolHistogram(bucket.PublisherOpenLatency)
		if err != nil {
			return err
		}
		timeToFirstPublisherByte, err := protocolHistogram(bucket.TimeToFirstPublisherByte)
		if err != nil {
			return err
		}
		successfulConnectionDuration, err := protocolHistogram(bucket.SuccessfulConnectionDuration)
		if err != nil {
			return err
		}
		items[index] = routeusagev1.RouteUsageSnapshot{
			ItemId: bucket.ReportID, RouteId: bucket.RouteID,
			Version: strconv.FormatInt(bucket.Version, 10), Resolution: routeusagev1.RouteUsageSnapshotResolution(bucket.Resolution),
			BucketStart: wireTimestamp(time.Unix(0, bucket.BucketStart)), Revision: strconv.FormatInt(bucket.SourceRevision, 10),
			ObservedThrough: wireTimestamp(time.Unix(0, bucket.ObservedThrough)), ConnectionAttempts: strconv.FormatInt(bucket.ConnectionAttempts, 10),
			PolicyDenials: strconv.FormatInt(bucket.PolicyDenials, 10), CapacityDenials: strconv.FormatInt(bucket.CapacityDenials, 10),
			PublisherOpenFailures: strconv.FormatInt(bucket.PublisherOpenFailures, 10), SuccessfulStreams: strconv.FormatInt(bucket.SuccessfulStreams, 10),
			ConnectionNanoseconds: strconv.FormatInt(bucket.ConnectionNanoseconds, 10), IngressBytes: strconv.FormatInt(bucket.IngressBytes, 10),
			EgressBytes: strconv.FormatInt(bucket.EgressBytes, 10), PublisherOpenLatency: publisherOpenLatency,
			TimeToFirstPublisherByte: timeToFirstPublisherByte, SuccessfulConnectionDuration: successfulConnectionDuration,
			VisitorNetworkEstimate: strconv.FormatInt(bucket.VisitorNetworkEstimate, 10), VisitorNetworkHll: bucket.VisitorNetworkHll,
			Complete: bucket.Complete != 0,
		}
	}
	count, body, err := encodeBatch(items)
	if err != nil {
		return err
	}
	rows = rows[:count]
	references := make([]outboxRevision, count)
	itemIDs := make([]string, count)
	byID := make(map[string]outboxRevision, count)
	for index, row := range rows {
		reference := outboxRevision{kind: usageSource, sourceID: row.SourceID, revision: row.SourceRevision}
		references[index], itemIDs[index], byID[row.ReportID] = reference, row.ReportID, reference
	}
	marked, err := p.store.markAttempted(ctx, references)
	if err != nil || !marked {
		return err
	}
	accepted, rejected, err := p.postBatch(ctx, "/v1/routes/usage-snapshots", body, itemIDs)
	if err != nil {
		return err
	}
	acknowledged := make([]outboxRevision, 0, len(accepted))
	for _, itemID := range accepted {
		acknowledged = append(acknowledged, byID[itemID])
	}
	if err := p.store.acknowledgeUsageBatch(ctx, acknowledged); err != nil {
		return err
	}
	if rejected {
		return errors.New("routeusage: receiver rejected usage batch items")
	}
	return nil
}

func wireTimestamp(value time.Time) time.Time {
	return value.UTC().Truncate(time.Millisecond)
}

func protocolHistogram(data []byte) (*routeusagev1.DurationHistogram, error) {
	histogram, err := unmarshalDurationHistogram(data)
	if err != nil {
		return nil, fmt.Errorf("routeusage: decode duration histogram: %w", err)
	}
	if histogram.count() == 0 {
		return nil, nil
	}
	counts := make([]routeusagev1.UnsignedInteger, len(histogram.counts))
	for index, count := range histogram.counts {
		counts[index] = strconv.FormatUint(count, 10)
	}
	return &routeusagev1.DurationHistogram{
		Count: strconv.FormatUint(histogram.count(), 10), SumNanoseconds: strconv.FormatUint(histogram.sumNanoseconds, 10),
		CumulativeCounts: counts,
	}, nil
}

func encodeBatch[T any](items []T) (int, []byte, error) {
	if len(items) > maximumBatchItems {
		items = items[:maximumBatchItems]
	}
	for len(items) > 0 {
		body, err := json.Marshal(struct {
			Items []T `json:"items"`
		}{Items: items})
		if err != nil {
			return 0, nil, fmt.Errorf("routeusage: encode batch request: %w", err)
		}
		if len(body) <= maximumRequestBytes {
			return len(items), body, nil
		}
		items = items[:len(items)-1]
	}
	return 0, nil, errors.New("routeusage: batch item exceeds request size limit")
}

func (p *Sender) postBatch(ctx context.Context, path string, body []byte, itemIDs []string) ([]string, bool, error) {
	target := *p.baseURL
	target.Path = strings.TrimSuffix(target.Path, "/") + path
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, target.String(), bytes.NewReader(body))
	if err != nil {
		return nil, false, fmt.Errorf("routeusage: create batch request: %w", err)
	}
	request.Header.Set("Authorization", "Bearer "+p.token)
	request.Header.Set("Content-Type", "application/json")
	response, err := p.client.Do(request)
	if err != nil {
		return nil, false, fmt.Errorf("routeusage: deliver batch request: %w", err)
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, maximumResponseBytes+1))
	if err != nil {
		return nil, false, fmt.Errorf("routeusage: read batch response: %w", err)
	}
	if len(data) > maximumResponseBytes {
		return nil, false, errors.New("routeusage: receiver response exceeds size limit")
	}
	if response.StatusCode != http.StatusOK {
		return nil, false, fmt.Errorf("routeusage: receiver returned %s", response.Status)
	}
	var payload struct {
		Results []routeusagev1.BatchResult `json:"results"`
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&payload); err != nil {
		return nil, false, fmt.Errorf("routeusage: decode batch response: %w", err)
	}
	if err := requireJSONEnd(decoder); err != nil {
		return nil, false, err
	}
	requested := make(map[string]struct{}, len(itemIDs))
	for _, itemID := range itemIDs {
		requested[itemID] = struct{}{}
	}
	if len(payload.Results) != len(requested) {
		return nil, false, errors.New("routeusage: batch response result count does not match request")
	}
	seen := make(map[string]struct{}, len(payload.Results))
	accepted := make([]string, 0, len(payload.Results))
	rejected := false
	for _, result := range payload.Results {
		if _, ok := requested[result.ItemId]; !ok {
			return nil, false, fmt.Errorf("routeusage: batch response contains unknown item %q", result.ItemId)
		}
		if _, duplicate := seen[result.ItemId]; duplicate {
			return nil, false, fmt.Errorf("routeusage: batch response contains duplicate item %q", result.ItemId)
		}
		seen[result.ItemId] = struct{}{}
		if result.Accepted {
			if result.Code != nil {
				return nil, false, fmt.Errorf("routeusage: accepted batch item %q has a problem code", result.ItemId)
			}
			accepted = append(accepted, result.ItemId)
			continue
		}
		if result.Code == nil || !result.Code.Valid() {
			return nil, false, fmt.Errorf("routeusage: rejected batch item %q has no valid problem code", result.ItemId)
		}
		rejected = true
	}
	return accepted, rejected, nil
}

func requireJSONEnd(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("routeusage: batch response contains multiple JSON values")
		}
		return fmt.Errorf("routeusage: decode trailing batch response: %w", err)
	}
	return nil
}

func (p *Sender) post(ctx context.Context, path string, payload any) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("routeusage: encode request: %w", err)
	}
	target := *p.baseURL
	target.Path = strings.TrimSuffix(target.Path, "/") + path
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, target.String(), bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("routeusage: create request: %w", err)
	}
	request.Header.Set("Authorization", "Bearer "+p.token)
	request.Header.Set("Content-Type", "application/json")
	response, err := p.client.Do(request)
	if err != nil {
		return fmt.Errorf("routeusage: deliver request: %w", err)
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
	if response.StatusCode != http.StatusNoContent {
		return fmt.Errorf("routeusage: receiver returned %s", response.Status)
	}
	return nil
}

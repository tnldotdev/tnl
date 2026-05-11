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

const requestTimeout = 10 * time.Second

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
		var timer *time.Timer
		if err != nil {
			jitter := time.Duration(rand.Int64N(int64(backoff / 2)))
			timer = time.NewTimer(backoff + jitter)
			delay = timer.C
			backoff = min(backoff*2, 30*time.Second)
		} else {
			pollReady = poll.C
		}
		select {
		case <-ctx.Done():
			if timer != nil {
				timer.Stop()
			}
			return
		case <-p.store.wake:
			if timer != nil {
				timer.Stop()
			}
		case <-delay:
		case <-pollReady:
		case now := <-prune.C:
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
	count, err := p.store.queries.MarkRouteUsageOutboxAttempt(ctx, statedb.MarkRouteUsageOutboxAttemptParams{
		AttemptedAt: time.Now().UTC().UnixNano(), SourceKind: item.SourceKind,
		SourceID: item.SourceID, SourceRevision: item.SourceRevision,
	})
	if err != nil {
		return false, fmt.Errorf("routeusage: mark outbox attempt: %w", err)
	}
	if count != 1 {
		return true, nil
	}

	var kind string
	switch item.SourceKind {
	case registrationSource:
		kind = "registration"
		err = p.sendRegistration(ctx, item)
	case lifecycleSource:
		kind = "lifecycle"
		err = p.sendLifecycle(ctx, item)
	case usageSource:
		kind = "usage"
		err = p.sendUsage(ctx, item)
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

func (p *Sender) sendLifecycle(ctx context.Context, item statedb.RouteUsageOutboxItem) error {
	event, err := p.store.queries.GetRouteLifecycleReport(ctx, item.SourceID)
	if err != nil {
		return fmt.Errorf("routeusage: read lifecycle event: %w", err)
	}
	payload := routeusagev1.RouteLifecycleEvent{
		EventId: event.EventID, Version: strconv.FormatInt(event.Version, 10),
		Sequence: strconv.FormatInt(event.Sequence, 10), OccurredAt: wireTimestamp(time.Unix(0, event.OccurredAt)),
		Transition: routeusagev1.RouteLifecycleEventTransition(event.Transition),
	}
	if err := p.postRoute(ctx, event.RouteID, "lifecycle-events", payload); err != nil {
		return err
	}
	_, err = p.store.acknowledge(ctx, lifecycleSource, event.ID, item.SourceRevision)
	return err
}

func (p *Sender) sendUsage(ctx context.Context, item statedb.RouteUsageOutboxItem) error {
	bucket, err := p.store.queries.GetRouteUsageReport(ctx, statedb.GetRouteUsageReportParams{
		SourceID: item.SourceID, SourceRevision: item.SourceRevision,
	})
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("routeusage: read usage snapshot: %w", err)
	}
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
	payload := routeusagev1.RouteUsageSnapshot{
		Version: strconv.FormatInt(bucket.Version, 10), Resolution: routeusagev1.RouteUsageSnapshotResolution(bucket.Resolution),
		BucketStart: wireTimestamp(time.Unix(0, bucket.BucketStart)), Revision: strconv.FormatInt(item.SourceRevision, 10),
		ObservedThrough: wireTimestamp(time.Unix(0, bucket.ObservedThrough)), ConnectionAttempts: strconv.FormatInt(bucket.ConnectionAttempts, 10),
		PolicyDenials: strconv.FormatInt(bucket.PolicyDenials, 10), CapacityDenials: strconv.FormatInt(bucket.CapacityDenials, 10),
		PublisherOpenFailures: strconv.FormatInt(bucket.PublisherOpenFailures, 10), SuccessfulStreams: strconv.FormatInt(bucket.SuccessfulStreams, 10),
		ConnectionNanoseconds: strconv.FormatInt(bucket.ConnectionNanoseconds, 10), IngressBytes: strconv.FormatInt(bucket.IngressBytes, 10),
		EgressBytes: strconv.FormatInt(bucket.EgressBytes, 10), PublisherOpenLatency: publisherOpenLatency,
		TimeToFirstPublisherByte: timeToFirstPublisherByte, SuccessfulConnectionDuration: successfulConnectionDuration,
		VisitorNetworkEstimate: strconv.FormatInt(bucket.VisitorNetworkEstimate, 10), VisitorNetworkHll: bucket.VisitorNetworkHll,
		Complete: bucket.Complete != 0,
	}
	if err := p.postRoute(ctx, bucket.RouteID, "usage-snapshots", payload); err != nil {
		return err
	}
	acknowledged, err := p.store.acknowledge(ctx, usageSource, bucket.ID, item.SourceRevision)
	if err != nil || !acknowledged {
		return err
	}
	if bucket.Complete != 0 {
		return p.store.deleteUsage(ctx, bucket.ID)
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

func (p *Sender) postRoute(ctx context.Context, routeID, endpoint string, payload any) error {
	return p.post(ctx, "/v1/routes/"+url.PathEscape(routeID)+"/"+endpoint, payload)
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

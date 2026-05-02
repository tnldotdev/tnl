package routeexport

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
	"github.com/tnldotdev/tnl/pkg/protocol/routeexportv1"
)

const requestTimeout = 10 * time.Second

type Publisher struct {
	store    *Store
	baseURL  *url.URL
	token    string
	client   *http.Client
	observer Observer
}

func NewPublisher(store *Store, rawURL, token string, observer Observer) (*Publisher, error) {
	baseURL, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("routeexport: parse export URL: %w", err)
	}
	return &Publisher{
		store: store, baseURL: baseURL, token: token, observer: observer,
		client: &http.Client{
			Timeout:       requestTimeout,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}, nil
}

func (p *Publisher) Run(ctx context.Context, report func(error)) {
	backoff := time.Second
	prune := time.NewTicker(time.Hour)
	defer prune.Stop()
	poll := time.NewTicker(time.Second)
	defer poll.Stop()
	for {
		delivered, err := p.PublishOne(ctx)
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

func (p *Publisher) PublishOne(ctx context.Context) (bool, error) {
	lifecycle, err := p.store.queries.GetNextLifecycleExport(ctx)
	if err == nil {
		err = p.publishLifecycle(ctx, lifecycle)
		p.observe(ctx, "lifecycle", err)
		return true, err
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return false, fmt.Errorf("routeexport: read lifecycle outbox: %w", err)
	}
	usage, err := p.store.queries.GetNextUsageExport(ctx)
	if err == nil {
		err = p.publishUsage(ctx, usage)
		p.observe(ctx, "usage", err)
		return true, err
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return false, fmt.Errorf("routeexport: read usage outbox: %w", err)
	}
	p.updateOutbox(ctx)
	return false, nil
}

func (p *Publisher) observe(ctx context.Context, kind string, deliveryErr error) {
	if p.observer == nil {
		return
	}
	result := "success"
	if deliveryErr != nil {
		result = "error"
	}
	p.observer.ObserveRouteExportDelivery(kind, result)
	p.updateOutbox(ctx)
}

func (p *Publisher) updateOutbox(ctx context.Context) {
	if p.observer == nil {
		return
	}
	lifecycle, usage, age, err := p.store.outboxStats(ctx, time.Now())
	if err != nil {
		return
	}
	p.observer.SetRouteExportOutbox("lifecycle", lifecycle)
	p.observer.SetRouteExportOutbox("usage", usage)
	p.observer.SetRouteExportOldestAge(age)
}

func (p *Publisher) publishLifecycle(ctx context.Context, row statedb.GetNextLifecycleExportRow) error {
	event := row.RouteLifecycleEvent
	payload := routeexportv1.RouteLifecycleEvent{
		EventId: event.EventID, Generation: strconv.FormatInt(event.Generation, 10),
		Sequence: strconv.FormatInt(event.Sequence, 10), OccurredAt: time.Unix(0, event.OccurredAtNs).UTC(),
		Transition: routeexportv1.RouteLifecycleEventTransition(event.Transition),
	}
	if err := p.post(ctx, event.RouteID, "lifecycle-events", payload); err != nil {
		return err
	}
	_, err := p.store.acknowledge(ctx, lifecycleSource, event.ID, row.SourceRevision)
	return err
}

func (p *Publisher) publishUsage(ctx context.Context, row statedb.GetNextUsageExportRow) error {
	bucket := row.RouteUsageBucket
	payload := routeexportv1.RouteUsageSnapshot{
		Generation: strconv.FormatInt(bucket.Generation, 10), Resolution: routeexportv1.RouteUsageSnapshotResolution(bucket.Resolution),
		BucketStart: time.Unix(0, bucket.BucketStartNs).UTC(), Revision: strconv.FormatInt(row.SourceRevision, 10),
		SourceThrough: time.Unix(0, bucket.SourceThroughNs).UTC(), ConnectionsOpened: strconv.FormatInt(bucket.ConnectionsOpened, 10),
		ConnectionNanoseconds: strconv.FormatInt(bucket.ConnectionNs, 10), IngressBytes: strconv.FormatInt(bucket.IngressBytes, 10),
		EgressBytes: strconv.FormatInt(bucket.EgressBytes, 10), Complete: bucket.Complete != 0,
	}
	if err := p.post(ctx, bucket.RouteID, "usage-snapshots", payload); err != nil {
		return err
	}
	acknowledged, err := p.store.acknowledge(ctx, usageSource, bucket.ID, row.SourceRevision)
	if err != nil || !acknowledged {
		return err
	}
	if bucket.Complete != 0 {
		return p.store.deleteUsage(ctx, bucket.ID)
	}
	return nil
}

func (p *Publisher) post(ctx context.Context, routeID, endpoint string, payload any) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("routeexport: encode request: %w", err)
	}
	target := *p.baseURL
	target.Path = strings.TrimSuffix(target.Path, "/") + "/v1/routes/" + url.PathEscape(routeID) + "/" + endpoint
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, target.String(), bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("routeexport: create request: %w", err)
	}
	request.Header.Set("Authorization", "Bearer "+p.token)
	request.Header.Set("Content-Type", "application/json")
	response, err := p.client.Do(request)
	if err != nil {
		return fmt.Errorf("routeexport: deliver request: %w", err)
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
	if response.StatusCode != http.StatusNoContent {
		return fmt.Errorf("routeexport: receiver returned %s", response.Status)
	}
	return nil
}

package telemetry

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/tnldotdev/tnl/internal/buildinfo"
	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	api "github.com/tnldotdev/tnl/pkg/api/integrations/telemetry/v1"
)

const RequestTimeout = 500 * time.Millisecond
const ReceiverURL = "https://tnl.dev/api/telemetry"

type Config struct {
	Root       string
	Protection clientstate.ProtectionMode
	Client     *http.Client
	Metadata   *api.Client
	Endpoint   string
	Interval   time.Duration
}

type queuedEvent struct {
	id    string
	data  json.RawMessage
	epoch int64
}

// collector owns one queue writer/sender and one preference watcher. observations
// never wait for disk or network; close cancels and joins both workers.
type Collector struct {
	state        *clientstate.Database
	client       *http.Client
	endpoint     string
	metadata     api.Client
	ctx          context.Context
	cancel       context.CancelFunc
	preference   atomic.Pointer[clientstate.TelemetryPreference]
	closed       atomic.Bool
	queue        chan queuedEvent
	flush        chan chan struct{}
	done         chan struct{}
	once         sync.Once
	flightMu     sync.Mutex
	flightCancel context.CancelFunc
	scopesMu     sync.Mutex
	scopes       map[*Scope]struct{}
}

func New(parent context.Context, cfg Config) (*Collector, error) {
	if cfg.Root == "" || cfg.Interval < 0 {
		return nil, api.ErrInvalid
	}
	metadata := api.Client{Version: buildinfo.Version, Os: api.ClientOs(runtime.GOOS), Arch: api.ClientArch(runtime.GOARCH), Ci: os.Getenv("CI") != ""}
	if !metadata.Os.Valid() {
		metadata.Os = api.ClientOsOther
	}
	if !metadata.Arch.Valid() {
		metadata.Arch = api.ClientArchOther
	}
	if cfg.Metadata != nil {
		metadata = *cfg.Metadata
	}
	encoded, err := json.Marshal(metadata)
	if err != nil || api.ValidateClient(encoded) != nil {
		return nil, api.ErrInvalid
	}
	setup, stop := context.WithTimeout(parent, RequestTimeout)
	defer stop()
	state, err := clientstate.OpenWithOptions(setup, cfg.Root, clientstate.OpenOptions{Protection: cfg.Protection, NoWait: true})
	if err != nil {
		return nil, err
	}
	preference, err := state.TelemetryPreference(setup)
	if err != nil {
		_ = state.Close()
		return nil, err
	}
	if cfg.Client == nil {
		cfg.Client = &http.Client{Timeout: RequestTimeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	}
	if cfg.Endpoint == "" {
		cfg.Endpoint = ReceiverURL
	}
	if cfg.Interval <= 0 {
		cfg.Interval = 5 * time.Second
	}
	ctx, cancel := context.WithCancel(parent)
	c := &Collector{state: state, client: cfg.Client, endpoint: cfg.Endpoint, metadata: metadata, ctx: ctx, cancel: cancel, queue: make(chan queuedEvent, 64), flush: make(chan chan struct{}, 1), done: make(chan struct{}), scopes: make(map[*Scope]struct{})}
	c.preference.Store(&preference)
	var workers sync.WaitGroup
	workers.Go(func() { c.run(cfg.Interval) })
	workers.Go(c.watchPreference)
	go func() { workers.Wait(); _ = state.Close(); close(c.done) }()
	return c, nil
}

func (c *Collector) Report(event api.Event) {
	if c == nil || c.closed.Load() {
		return
	}
	p := c.preference.Load()
	if p == nil || !p.Enabled {
		return
	}
	c.enqueue(event, p.Epoch)
}

// encode once, including the metadata and preference epoch from collection.
func (c *Collector) enqueue(event api.Event, epoch int64) {
	queued, ok := c.encode(event, epoch)
	if !ok {
		return
	}
	select {
	case c.queue <- queued:
	default:
	}
}

func (c *Collector) encode(event api.Event, epoch int64) (queuedEvent, bool) {
	data, err := json.Marshal(api.CollectedEvent{Client: c.metadata, Event: event})
	if err != nil || len(data) > api.MaximumEventBytes {
		return queuedEvent{}, false
	}
	var header struct {
		Event struct {
			ID string `json:"event_id"`
		} `json:"event"`
	}
	if json.Unmarshal(data, &header) != nil {
		return queuedEvent{}, false
	}
	return queuedEvent{id: header.Event.ID, data: data, epoch: epoch}, true
}

func (c *Collector) Flush() {
	if c == nil || c.closed.Load() {
		return
	}
	select {
	case c.flush <- nil:
	default:
	}
}

func (c *Collector) Close(ctx context.Context) {
	if c == nil {
		return
	}
	c.once.Do(func() {
		c.closed.Store(true)
		ack := make(chan struct{})
		select {
		case c.flush <- ack:
			select {
			case <-ack:
			case <-ctx.Done():
			case <-c.done:
			}
		case <-ctx.Done():
		case <-c.done:
		}
		c.cancel()
		c.stopRequest()
		<-c.done
	})
}

func (c *Collector) stopRequest() {
	c.flightMu.Lock()
	defer c.flightMu.Unlock()
	if c.flightCancel != nil {
		c.flightCancel()
	}
}

func (c *Collector) watchPreference() {
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	for c.ctx.Err() == nil {
		select {
		case <-c.ctx.Done():
			return
		case <-ticker.C:
		}
		c.refreshPreference()
	}
}

func (c *Collector) refreshPreference() {
	call, stop := context.WithTimeout(c.ctx, RequestTimeout)
	next, err := c.state.TelemetryPreference(call)
	stop()
	if err != nil {
		next = clientstate.TelemetryPreference{Epoch: c.preference.Load().Epoch}
	}
	previous := c.preference.Swap(&next)
	if *previous != next {
		c.stopRequest()
	}
}

func (c *Collector) run(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	scopeTicker := time.NewTicker(time.Minute)
	defer scopeTicker.Stop()
	for c.ctx.Err() == nil {
		select {
		case <-c.ctx.Done():
			return
		case event := <-c.queue:
			c.store(event)
		case ack := <-c.flush:
			c.flushScopes()
			c.drain()
			c.send()
			if ack != nil {
				close(ack)
			}
		case <-ticker.C:
			c.drain()
			c.send()
		case <-scopeTicker.C:
			c.flushScopes()
			c.drain()
			c.send()
		}
	}
}

func (c *Collector) flushScopes() {
	c.scopesMu.Lock()
	scopes := make([]*Scope, 0, len(c.scopes))
	for scope := range c.scopes {
		scopes = append(scopes, scope)
	}
	c.scopesMu.Unlock()
	for _, scope := range scopes {
		scope.flushTo(func(event api.Event, epoch int64) {
			if queued, ok := c.encode(event, epoch); ok {
				c.store(queued)
			}
		})
	}
}

func (c *Collector) drain() {
	for range cap(c.queue) {
		if c.ctx.Err() != nil {
			return
		}
		select {
		case event := <-c.queue:
			c.store(event)
		default:
			return
		}
	}
}

func (c *Collector) store(event queuedEvent) {
	if api.ValidateCollectedEvent(event.data) != nil {
		return
	}
	call, stop := context.WithTimeout(c.ctx, RequestTimeout)
	defer stop()
	_ = c.state.QueueTelemetryEvent(call, event.id, event.data, event.epoch)
}

func (c *Collector) send() {
	call, cancel := context.WithTimeout(c.ctx, RequestTimeout)
	defer cancel()
	p, err := c.state.TelemetryPreference(call)
	if err != nil || !p.Enabled {
		return
	}
	_ = c.state.PruneTelemetryOutbox(call)
	rows, err := c.state.PendingTelemetryEvents(call, 25)
	if err != nil || len(rows) == 0 {
		return
	}
	id, err := c.state.InstallationID(call)
	if err != nil {
		return
	}
	batch := api.Batch{SchemaVersion: 1, InstallationId: id}
	var selected, invalid []clientstate.TelemetryOutboxEvent
	bytesUsed := 1024
	for _, row := range rows {
		var event api.CollectedEvent
		if api.ValidateCollectedEvent(row.JSON) != nil || json.Unmarshal(row.JSON, &event) != nil {
			invalid = append(invalid, row)
			continue
		}
		if bytesUsed+len(row.JSON) > api.MaximumBatchBytes {
			continue
		}
		selected = append(selected, row)
		batch.Events = append(batch.Events, event)
		bytesUsed += len(row.JSON)
	}
	_ = c.state.DeleteTelemetryEvents(call, invalid)
	if len(selected) == 0 {
		return
	}
	body, err := json.Marshal(batch)
	if err != nil || api.ValidateBatch(body) != nil {
		return
	}
	fresh, err := c.state.TelemetryPreference(call)
	if err != nil || fresh != p {
		return
	}
	request, err := http.NewRequestWithContext(call, http.MethodPost, c.endpoint, bytes.NewReader(body))
	if err != nil {
		return
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("User-Agent", "tnl")
	c.flightMu.Lock()
	current := c.preference.Load()
	if *current != p {
		c.flightMu.Unlock()
		return
	}
	c.flightCancel = cancel
	c.flightMu.Unlock()
	defer func() { c.flightMu.Lock(); c.flightCancel = nil; c.flightMu.Unlock() }()
	response, err := c.client.Do(request)
	if err != nil {
		return
	}
	_ = response.Body.Close()
	if response.StatusCode == http.StatusNoContent || response.StatusCode >= 400 && response.StatusCode < 500 && response.StatusCode != http.StatusTooManyRequests {
		_ = c.state.DeleteTelemetryEvents(call, selected)
	}
}

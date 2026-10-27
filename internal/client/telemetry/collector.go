package telemetry

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/tnldotdev/tnl/internal/buildinfo"
	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	api "github.com/tnldotdev/tnl/pkg/api/integrations/telemetry/v1"
)

const ReceiverURL = "https://tnl.dev/api/telemetry"
const RequestTimeout = 500 * time.Millisecond
const SetupTimeout = 10 * time.Second
const maximumScopes = 256

type Config struct {
	Root          string
	Protection    clientstate.ProtectionMode
	Disabled      bool
	Client        *http.Client
	Metadata      *api.Client
	Endpoint      string
	FlushInterval time.Duration
}

type queuedObservation struct {
	epoch int64
	make  func(string) (api.Event, error)
}

// Collector owns its state handle and joined workers. Report and scope
// observations use bounded memory only; forwarding never performs queue I/O.
type Collector struct {
	ctx          context.Context
	cancel       context.CancelFunc
	state        *clientstate.Database
	client       *http.Client
	endpoint     string
	metadataJSON json.RawMessage
	interval     time.Duration
	preference   atomic.Pointer[clientstate.TelemetryPreference]
	closed       atomic.Bool
	events       chan queuedObservation
	wake         chan struct{}
	flush        chan chan struct{}
	done         chan struct{}
	closeOnce    sync.Once
	flightMu     sync.Mutex
	flightCancel context.CancelFunc
	scopeMu      sync.Mutex
	scopes       map[*Scope]struct{}
}

func DefaultMetadata() api.Client {
	osName, arch := api.ClientOs(runtime.GOOS), api.ClientArch(runtime.GOARCH)
	if !osName.Valid() {
		osName = api.ClientOsOther
	}
	if !arch.Valid() {
		arch = api.ClientArchOther
	}
	return api.Client{Version: buildinfo.Version, Os: osName, Arch: arch, Ci: os.Getenv("CI") != ""}
}

func New(parent context.Context, config Config) (*Collector, error) {
	if config.Disabled {
		return nil, nil
	}
	if config.Root == "" || config.FlushInterval < 0 {
		return nil, errors.New("telemetry collection settings are invalid")
	}
	metadata := DefaultMetadata()
	if config.Metadata != nil {
		metadata = *config.Metadata
	}
	encoded, err := json.Marshal(metadata)
	if err != nil || api.ValidateClient(encoded) != nil {
		return nil, api.ErrInvalid
	}
	setup, stop := context.WithTimeout(parent, SetupTimeout)
	defer stop()
	database, err := clientstate.OpenWithOptions(setup, config.Root, clientstate.OpenOptions{Protection: config.Protection})
	if err != nil {
		return nil, err
	}
	preference, err := database.TelemetryPreference(setup)
	if err != nil {
		_ = database.Close()
		return nil, err
	}
	if config.Client == nil {
		config.Client = &http.Client{Timeout: RequestTimeout, CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		}}
	}
	if config.Endpoint == "" {
		config.Endpoint = ReceiverURL
	}
	if config.FlushInterval == 0 {
		config.FlushInterval = 5 * time.Second
	}
	ctx, cancel := context.WithCancel(parent)
	c := &Collector{ctx: ctx, cancel: cancel, state: database, client: config.Client,
		endpoint: config.Endpoint, metadataJSON: encoded, interval: config.FlushInterval,
		events: make(chan queuedObservation, 64), wake: make(chan struct{}, 1), flush: make(chan chan struct{}, 1),
		done: make(chan struct{}), scopes: make(map[*Scope]struct{})}
	c.preference.Store(&preference)
	var workers sync.WaitGroup
	workers.Go(c.run)
	workers.Go(c.watchPreference)
	go func() {
		workers.Wait()
		_ = database.Close()
		close(c.done)
	}()
	return c, nil
}

func (c *Collector) Report(observation Observation) {
	if c == nil || c.closed.Load() {
		return
	}
	preference := c.preference.Load()
	if preference == nil || !preference.Enabled {
		return
	}
	select {
	case c.events <- queuedObservation{epoch: preference.Epoch, make: observation.wire}:
	default:
	}
}

func (c *Collector) Flush() {
	if c == nil || c.closed.Load() {
		return
	}
	select {
	case c.wake <- struct{}{}:
	default:
	}
}

func (c *Collector) Close(ctx context.Context) {
	if c == nil {
		return
	}
	c.closeOnce.Do(func() {
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

func (c *Collector) watchPreference() {
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-c.ctx.Done():
			return
		case <-ticker.C:
		}
		call, cancel := context.WithTimeout(c.ctx, 100*time.Millisecond)
		next, err := c.state.TelemetryPreference(call)
		cancel()
		if err != nil {
			current := c.preference.Load()
			next = clientstate.TelemetryPreference{Epoch: current.Epoch}
		}
		previous := c.preference.Swap(&next)
		if previous == nil || *previous != next {
			c.stopRequest()
			c.resetScopes(next)
		}
	}
}

func (c *Collector) stopRequest() {
	c.flightMu.Lock()
	defer c.flightMu.Unlock()
	if c.flightCancel != nil {
		c.flightCancel()
	}
}

func (c *Collector) run() {
	ticker := time.NewTicker(c.interval)
	defer ticker.Stop()
	for c.ctx.Err() == nil {
		select {
		case <-c.ctx.Done():
			return
		case event := <-c.events:
			c.store(event)
		case <-c.wake:
			c.drain()
			c.captureScopes(false)
			c.send()
		case ack := <-c.flush:
			c.drain()
			c.captureScopes(true)
			c.send()
			close(ack)
		case <-ticker.C:
			c.drain()
			c.captureScopes(false)
			c.send()
		}
	}
}

func (c *Collector) drain() {
	for range cap(c.events) {
		select {
		case event := <-c.events:
			c.store(event)
		default:
			return
		}
	}
}

func (c *Collector) store(observation queuedObservation) {
	preference := c.preference.Load()
	if c.ctx.Err() != nil || preference == nil || !preference.Enabled || preference.Epoch != observation.epoch {
		return
	}
	id, err := opaqueid.New(opaqueid.TelemetryEventPrefix)
	if err != nil {
		return
	}
	event, err := observation.make(id)
	if err != nil {
		return
	}
	encoded, err := json.Marshal(event)
	if err != nil || api.ValidateEvent(encoded) != nil {
		return
	}
	call, cancel := context.WithTimeout(c.ctx, RequestTimeout)
	defer cancel()
	_ = c.state.QueueTelemetryEvent(call, id, encoded, c.metadataJSON, observation.epoch)
}

func (c *Collector) send() {
	call, cancel := context.WithTimeout(c.ctx, RequestTimeout)
	defer cancel()
	preference, err := c.state.TelemetryPreference(call)
	if err != nil || !preference.Enabled {
		return
	}
	_ = c.state.PruneTelemetryOutbox(call)
	pending, err := c.state.PendingTelemetryEvents(call, 25)
	if err != nil || len(pending) == 0 {
		return
	}
	installation, err := c.state.InstallationID(call)
	if err != nil {
		return
	}
	batch := api.Batch{SchemaVersion: api.V1, InstallationId: installation}
	var selected, invalid []clientstate.TelemetryOutboxEvent
	bytesUsed := 1024
	for _, row := range pending {
		var event api.Event
		var metadata api.Client
		if api.ValidateEvent(row.JSON) != nil || api.ValidateClient(row.ClientJSON) != nil ||
			json.Unmarshal(row.JSON, &event) != nil || json.Unmarshal(row.ClientJSON, &metadata) != nil {
			invalid = append(invalid, row)
			continue
		}
		if len(selected) == 0 {
			batch.Client = metadata
		}
		if metadata != batch.Client || bytesUsed+len(row.JSON) > api.MaximumBatchBytes {
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
	if err != nil || fresh != preference {
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
	if current == nil || !current.Enabled || current.Epoch != preference.Epoch {
		c.flightMu.Unlock()
		return
	}
	c.flightCancel = cancel
	c.flightMu.Unlock()
	defer func() {
		c.flightMu.Lock()
		c.flightCancel = nil
		c.flightMu.Unlock()
	}()
	response, err := c.client.Do(request)
	if err != nil {
		return
	}
	_ = response.Body.Close()
	if response.StatusCode == http.StatusNoContent || response.StatusCode >= 400 && response.StatusCode < 500 && response.StatusCode != http.StatusTooManyRequests {
		_ = c.state.DeleteTelemetryEvents(call, selected)
	}
}

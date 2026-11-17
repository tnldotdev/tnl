package invocation

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	clientserver "github.com/tnldotdev/tnl/internal/client/server"
	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	clienttelemetry "github.com/tnldotdev/tnl/internal/client/telemetry"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	publisherservice "github.com/tnldotdev/tnl/internal/publisher/service"
	"github.com/tnldotdev/tnl/internal/security/credentials"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
	api "github.com/tnldotdev/tnl/pkg/api/integrations/telemetry/v1"
)

type readyTelemetryCapture struct {
	mu        sync.Mutex
	events    []api.Event
	wire      [][]byte
	requests  chan api.Batch
	active    atomic.Int32
	before    func(api.Batch)
	transport func(*http.Request) error
}

func (c *readyTelemetryCapture) send(r *http.Request) (*http.Response, error) {
	c.active.Add(1)
	defer c.active.Add(-1)
	body, err := io.ReadAll(io.LimitReader(r.Body, api.MaximumBatchBytes+1))
	if err != nil || len(body) > api.MaximumBatchBytes || api.ValidateBatch(body) != nil {
		return nil, errors.New("ready telemetry fixture received an invalid batch")
	}
	var batch api.Batch
	if err := json.Unmarshal(body, &batch); err != nil {
		return nil, err
	}
	if r.Method != http.MethodPost || r.URL.String() != clienttelemetry.ReceiverURL ||
		r.Header.Get("Content-Type") != "application/json" || r.Header.Get("User-Agent") != "tnl" ||
		r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "" {
		return nil, errors.New("ready telemetry changed its safe receiver request")
	}
	if until, ok := r.Context().Deadline(); !ok || time.Until(until) > clienttelemetry.RequestTimeout {
		return nil, errors.New("ready telemetry request lost its delivery deadline")
	}
	if c.before != nil {
		c.before(batch)
	}
	c.mu.Lock()
	c.wire = append(c.wire, bytes.Clone(body))
	for _, collected := range batch.Events {
		c.events = append(c.events, collected.Event)
	}
	c.mu.Unlock()
	select {
	case c.requests <- batch:
	default:
		return nil, errors.New("ready telemetry fixture exceeded its bounded request capture")
	}
	if c.transport != nil {
		if err := c.transport(r); err != nil {
			return nil, err
		}
	}
	return &http.Response{StatusCode: http.StatusNoContent, Header: http.Header{}, Body: http.NoBody, Request: r}, nil
}

func (c *readyTelemetryCapture) ready(t *testing.T) []api.ReadyEvent {
	t.Helper()
	c.mu.Lock()
	defer c.mu.Unlock()
	var ready []api.ReadyEvent
	for _, event := range c.events {
		name, err := event.Discriminator()
		if err != nil {
			t.Fatal("delivered event lost its discriminator", err)
		}
		if name == string(api.TunnelReady) {
			value, err := event.AsReadyEvent()
			if err != nil {
				t.Fatal(err)
			}
			ready = append(ready, value)
		}
	}
	return ready
}

func (c *readyTelemetryCapture) assertSafe(t *testing.T, private ...string) {
	t.Helper()
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, body := range c.wire {
		for _, value := range private {
			if value != "" && bytes.Contains(body, []byte(value)) {
				t.Error("ready telemetry included private publication context")
			}
		}
	}
}

func newReadyTelemetryCollector(t *testing.T, root string, capture *readyTelemetryCapture) *clienttelemetry.Collector {
	t.Helper()
	if root == "" {
		root = filepath.Join(t.TempDir(), "telemetry")
		state, err := clientstate.OpenWithOptions(t.Context(), root, clientstate.OpenOptions{Protection: clientstate.ProtectionFile})
		if err != nil {
			t.Fatal(err)
		}
		if err := state.Close(); err != nil {
			t.Fatal(err)
		}
	}
	capture.requests = make(chan api.Batch, 32)
	metadata := api.Client{Version: "ready-restoration", Os: api.ClientOsDarwin, Arch: api.ClientArchArm64}
	collector, err := clienttelemetry.New(context.WithoutCancel(t.Context()), clienttelemetry.Config{
		Root: root, Protection: clientstate.ProtectionFile, Interval: time.Hour, Metadata: &metadata,
		Client: &http.Client{Transport: publicationHTTPTransport(capture.send)},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { closeReadyTelemetryCollector(t, collector, capture) })
	return collector
}

func closeReadyTelemetryCollector(t *testing.T, collector *clienttelemetry.Collector, capture *readyTelemetryCapture) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	collector.Close(ctx)
	if capture.active.Load() != 0 {
		t.Error("telemetry collector returned before its delivery callback joined")
	}
}

func readyTelemetryAwait[T any](t *testing.T, event <-chan T) T {
	t.Helper()
	select {
	case value := <-event:
		return value
	case <-time.After(5 * time.Second):
		t.Fatal("ready telemetry owner did not reach its bounded observation")
		var zero T
		return zero
	}
}

// a harmless command event fences a real scope flush and HTTP delivery. no test
// callback records a publication-ready event on the real publication's behalf.
func readyTelemetryBarrier(t *testing.T, collector *clienttelemetry.Collector, capture *readyTelemetryCapture) {
	t.Helper()
	marker := clienttelemetry.Command(api.CommandOutcome{Command: api.CommandOutcomeCommandStatus, Outcome: api.Succeeded})
	command, err := marker.AsCommandEvent()
	if err != nil {
		t.Fatal(err)
	}
	collector.Report(marker)
	collector.Flush()
	for {
		batch := readyTelemetryAwait(t, capture.requests)
		for _, item := range batch.Events {
			if name, _ := item.Event.Discriminator(); name == "command.outcome" {
				event, err := item.Event.AsCommandEvent()
				if err != nil {
					t.Fatal(err)
				}
				if event.EventId == command.EventId {
					return
				}
			}
		}
	}
}

type readyTelemetryControl struct {
	*cliFallbackObservationControl
	server      string
	discoveries atomic.Int32
}

func (c *readyTelemetryControl) ControlURL() string { return c.server }

func (c *readyTelemetryControl) Discovery(context.Context) (controlv1.ControlDiscovery, error) {
	c.discoveries.Add(1)
	return controlv1.ControlDiscovery{BrowserLoginAvailable: new(false)}, nil
}

func (c *readyTelemetryControl) ReadPublisherVisitorPolicy(ctx context.Context, request controlv1.PublisherVisitorPolicyRequest, token string) (controlv1.VisitorPolicyUpdate, error) {
	update, err := c.cliFallbackObservationControl.ReadPublisherVisitorPolicy(ctx, request, token)
	update.Policy.Port = 443
	update.Policy.Issuer = c.server
	update.Policy.PublicEndpoint = &controlv1.VisitorPublicEndpoint{Hostname: c.saved.Endpoint.Hostname, Port: 443, EndpointRevision: c.saved.EndpointRevision}
	return update, err
}

func (c *readyTelemetryControl) CreateServiceRunPreview(_ context.Context, service, run string, number int64, token credentials.ServiceRunToken) (controlv1.Preview, error) {
	if service != c.prep.ServiceId || run != c.prep.ServiceRunId || number != c.prep.RunNumber || token.String() != c.prep.RunToken {
		return controlv1.Preview{}, publisherservice.ErrPrivateStream
	}
	return controlv1.Preview{Id: "pv_0123456789abcdefghijkl", SchemaVersion: 1, ServiceIds: []string{service}}, nil
}

func TestReadyTelemetryRestorationFollowsActualPublicationObservation(t *testing.T) {
	for _, server := range []string{clientserver.DefaultURL, "https://private-control.example"} {
		kind := api.SelfHosted
		if server == clientserver.DefaultURL {
			kind = api.Hosted
		}
		for _, mode := range []string{"success", "rejected", "rejected_during_cancellation"} {
			t.Run(string(kind)+"/"+mode, func(t *testing.T) {
				database, _, saved, cfg, base, remoteClosed := cliFallbackObservationFixture(t)
				saved.Protocol, saved.Endpoint.Port = controlv1.ServiceProtocolHTTP, 443
				base.saved = saved
				control := &readyTelemetryControl{cliFallbackObservationControl: base, server: server}
				cfg.Control, cfg.Metadata.Protocol = control, controlv1.ServiceProtocolHTTP
				cfg.Demo, cfg.Target = true, ""
				cfg.Handler = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
				var err error
				cfg.State, err = database.Server(t.Context(), server)
				if err != nil {
					t.Fatal(err)
				}
				project := t.TempDir()
				journal, err := database.BeginTunnel(t.Context(), clientstate.BeginTunnelOptions{
					Command: clientstate.TunnelCommandPublish, Server: server, Target: "http://127.0.0.1:3000",
					Project: project, ServiceID: saved.Id, ServiceProtocol: saved.Protocol,
				})
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = journal.Finish(context.WithoutCancel(t.Context()), nil) })
				entered, release := make(chan struct{}), make(chan struct{})
				unblock := sync.OnceFunc(func() { close(release) })
				defer unblock()
				reportErr := errors.New("private readiness presentation error")
				var accepted atomic.Bool
				var observed, statuses atomic.Int32
				repeated := make(chan struct{})
				var repeatedOnce sync.Once
				capture := &readyTelemetryCapture{before: func(batch api.Batch) {
					for _, event := range batch.Events {
						if name, _ := event.Event.Discriminator(); name == string(api.TunnelReady) && !accepted.Load() {
							t.Error("actual Ready telemetry overtook a successful publication observation")
						}
					}
				}}
				collector := newReadyTelemetryCollector(t, database.Root(), capture)
				cfg.Telemetry = collector
				cfg.ObserveReadiness = func(status publisherservice.RunStatus) {
					if accepted.Load() && status.Ready && statuses.Add(1) >= 2 {
						repeatedOnce.Do(func() { close(repeated) })
					}
				}
				output := &Presentation{Ready: func(address string, number uint64) error {
					if address != "https://"+saved.Endpoint.Hostname || number != uint64(base.prep.RunNumber) || observed.Add(1) != 1 {
						t.Error("actual publication observation changed its run or repeated its first Ready callback")
					}
					close(entered)
					<-release
					if mode != "success" {
						return reportErr
					}
					accepted.Store(true)
					return nil
				}}
				ctx, cancel := context.WithCancel(t.Context())
				published, joined := make(chan error, 1), make(chan struct{})
				go func() {
					defer close(joined)
					published <- RunServiceCLI(ctx, journal, saved, cfg, output, publisherservice.Publish)
				}()
				defer func() { unblock(); cancel(); readyTelemetryAwait(t, joined) }()
				readyTelemetryAwait(t, entered)
				readyTelemetryBarrier(t, collector, capture)
				if count := len(capture.ready(t)); count != 0 {
					t.Error("held publication observation already delivered success telemetry", count)
				}
				if mode == "rejected_during_cancellation" {
					cancel()
					select {
					case <-joined:
						t.Error("publication returned without joining its entered Ready observation")
					default:
					}
				}
				unblock()
				if mode == "success" {
					readyTelemetryAwait(t, repeated)
					readyTelemetryBarrier(t, collector, capture)
				}
				cancel()
				result := readyTelemetryAwait(t, published)
				if control.discoveries.Load() != 1 {
					t.Error("ready telemetry publication did not capture discovery exactly once")
				}
				if mode == "success" && result != nil || mode != "success" && !errors.Is(result, reportErr) {
					t.Error("actual publication lost its readiness observation result", result)
				}
				for range 2 {
					readyTelemetryAwait(t, remoteClosed)
				}
				closeReadyTelemetryCollector(t, collector, capture)
				events := capture.ready(t)
				want := 0
				if mode == "success" {
					want = 1
				}
				if observed.Load() != 1 || len(events) != want {
					t.Error("actual publication lost or duplicated delivered Ready telemetry", observed.Load(), len(events), want)
				}
				for _, event := range events {
					if event.Name != api.TunnelReady || event.EventVersion != 1 || !opaqueid.Valid(string(event.EventId), opaqueid.TelemetryEventPrefix) ||
						event.Payload.ServerKind != kind || event.Payload.PublishMode != api.Demo {
						t.Error("actual publication Ready payload lost current server kind or demo mode", event)
					}
				}
				capture.assertSafe(t, server, saved.Endpoint.Hostname, saved.Id, base.prep.ServiceRunId, base.prep.RunToken,
					"http://127.0.0.1:3000", project, "fixture-assignment-credential", "fixture-publisher-token", reportErr.Error())
			})
		}
	}
}

// the current native publication configuration has no framework input. keep the
// unchanged Vite payload/delivery assertion at the real telemetry scope owner,
// without injecting a Ready event into the publication-wiring test above.
func TestReadyTelemetryRestorationScopeDeliversViteOnceAndJoinsCancellation(t *testing.T) {
	for _, kind := range []api.PublicationReadyServerKind{api.Hosted, api.SelfHosted} {
		for _, canceled := range []bool{false, true} {
			mode := "delivered"
			if canceled {
				mode = "canceled"
			}
			t.Run(string(kind)+"/"+mode, func(t *testing.T) {
				entered, returned := make(chan struct{}), make(chan struct{})
				var once, returnedOnce sync.Once
				capture := &readyTelemetryCapture{}
				capture.transport = func(request *http.Request) error {
					once.Do(func() { close(entered) })
					if canceled {
						<-request.Context().Done()
						returnedOnce.Do(func() { close(returned) })
						return request.Context().Err()
					}
					return nil
				}
				collector := newReadyTelemetryCollector(t, "", capture)
				scope := collector.BeginScope("publisher")
				t.Cleanup(scope.Close)
				framework := api.PublicationReadyFrameworkVite
				scope.Ready(api.PublicationReady{ServerKind: kind, PublishMode: api.Demo, Framework: &framework})
				framework = api.PublicationReadyFrameworkNext
				scope.Ready(api.PublicationReady{ServerKind: kind, PublishMode: api.Demo, Framework: &framework})
				readyTelemetryAwait(t, entered)
				if canceled {
					closed, cancel := context.WithCancel(context.Background())
					cancel()
					collector.Close(closed)
					scope.Close()
					readyTelemetryAwait(t, returned)
					if capture.active.Load() != 0 {
						t.Error("scope delivery callback escaped collector cancellation/join")
					}
				} else {
					scope.Close()
					closeReadyTelemetryCollector(t, collector, capture)
				}
				events := capture.ready(t)
				if len(events) == 0 || !canceled && len(events) != 1 {
					t.Fatal("scope did not retain exactly one Ready event across repeated observations", len(events))
				}
				for _, event := range events {
					if event.EventId != events[0].EventId || event.Name != api.TunnelReady || event.EventVersion != 1 || event.Payload.ServerKind != kind ||
						event.Payload.PublishMode != api.Demo || event.Payload.Framework == nil || *event.Payload.Framework != api.PublicationReadyFrameworkVite {
						t.Error("real scope delivery lost the immutable current Vite payload or reused its scope for another event", event)
					}
					encoded, err := json.Marshal(event.Payload)
					if err != nil || strings.Contains(string(encoded), "next") {
						t.Error("later framework mutation reached the retained Ready event", err)
					}
				}
				capture.assertSafe(t, "private-control.example", "fixture-assignment-credential", "fixture-publisher-token")
			})
		}
	}
}

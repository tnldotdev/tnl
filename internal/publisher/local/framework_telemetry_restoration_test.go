package local

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	clienttelemetry "github.com/tnldotdev/tnl/internal/client/telemetry"
	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	publisherapp "github.com/tnldotdev/tnl/internal/publisher/app"
	publisherprotocol "github.com/tnldotdev/tnl/internal/publisher/localapi/protocol"
	publisherservice "github.com/tnldotdev/tnl/internal/publisher/service"
	"github.com/tnldotdev/tnl/internal/testutil"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
	api "github.com/tnldotdev/tnl/pkg/api/integrations/telemetry/v1"
)

type viteCompositionTelemetry struct {
	mu       sync.Mutex
	events   []api.ReadyEvent
	wire     [][]byte
	private  []string
	requests chan api.Batch
	active   atomic.Int32
	accepted atomic.Bool
}

func (c *viteCompositionTelemetry) ready() []api.ReadyEvent {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]api.ReadyEvent(nil), c.events...)
}

func (c *viteCompositionTelemetry) receive(t *testing.T, w http.ResponseWriter, r *http.Request) {
	c.active.Add(1)
	defer c.active.Add(-1)
	body, err := io.ReadAll(io.LimitReader(r.Body, api.MaximumBatchBytes+1))
	var batch api.Batch
	if err != nil || api.ValidateBatch(body) != nil || json.Unmarshal(body, &batch) != nil ||
		r.Method != http.MethodPost || r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "" ||
		r.Header.Get("Content-Type") != "application/json" || r.Header.Get("User-Agent") != "tnl" {
		t.Error("composed framework telemetry changed its valid anonymous receiver request", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	c.mu.Lock()
	c.wire = append(c.wire, bytes.Clone(body))
	for _, collected := range batch.Events {
		if name, _ := collected.Event.Discriminator(); name == string(api.TunnelReady) {
			event, err := collected.Event.AsReadyEvent()
			if err != nil {
				t.Error("actual framework publication delivered malformed Ready telemetry", err)
				continue
			}
			if !c.accepted.Load() {
				t.Error("actual Ready telemetry overtook successful worker observation")
			}
			c.events = append(c.events, event)
		}
	}
	c.mu.Unlock()
	select {
	case c.requests <- batch:
	default:
		t.Error("composed framework telemetry exceeded its bounded capture")
	}
	w.WriteHeader(http.StatusNoContent)
}

func newViteCompositionCollector(t *testing.T, capture *viteCompositionTelemetry) *clienttelemetry.Collector {
	t.Helper()
	capture.requests = make(chan api.Batch, 32)
	receiver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { capture.receive(t, w, r) }))
	t.Cleanup(receiver.Close)
	root := filepath.Join(t.TempDir(), "telemetry")
	state, err := clientstate.OpenWithOptions(t.Context(), root, clientstate.OpenOptions{Protection: clientstate.ProtectionFile})
	if err != nil {
		t.Fatal(err)
	}
	enabled, err := state.TelemetryEnabled(t.Context())
	if err != nil || !enabled {
		t.Fatal("fresh framework client state did not default telemetry on", err)
	}
	if err := state.Close(); err != nil {
		t.Fatal(err)
	}
	collector, err := clienttelemetry.New(context.WithoutCancel(t.Context()), clienttelemetry.Config{
		Root: root, Protection: clientstate.ProtectionFile, Endpoint: receiver.URL,
		Client: &http.Client{Timeout: clienttelemetry.RequestTimeout}, Interval: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { closeViteCompositionCollector(t, collector, capture) })
	return collector
}

func closeViteCompositionCollector(t *testing.T, collector *clienttelemetry.Collector, capture *viteCompositionTelemetry) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	collector.Close(ctx)
	if capture.active.Load() != 0 {
		t.Error("collector close returned before its framework delivery joined")
	}
}

func viteCompositionBarrier(t *testing.T, collector *clienttelemetry.Collector, capture *viteCompositionTelemetry) {
	t.Helper()
	// this command marks queue delivery, never publication readiness.
	marker := clienttelemetry.Command(api.CommandOutcome{Command: api.CommandOutcomeCommandStatus, Outcome: api.Succeeded})
	command, err := marker.AsCommandEvent()
	if err != nil {
		t.Fatal(err)
	}
	collector.Report(marker)
	collector.Flush()
	deadline := time.NewTimer(2 * time.Second)
	defer deadline.Stop()
	for {
		select {
		case batch := <-capture.requests:
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
		case <-deadline.C:
			t.Fatal("central collector did not complete its framework delivery barrier")
		}
	}
}

func viteCompositionCall(t *testing.T, endpoint publisherprotocol.Endpoint, path string, input, output any) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	if err := publisherprotocol.Call(ctx, endpoint, http.MethodPost, path, input, output); err != nil {
		t.Fatal("framework app local API operation failed: "+path, err)
	}
}

// this declares a vite app through the native API with a normal bound listener.
// it composes the real worker/publisher, but does not launch a vite process.
func TestConfiguredViteRegistrationDeliversReadyFrameworkOnce(t *testing.T) {
	if !testutil.IsolatedPublishingTest(t) {
		return
	}
	capture := &viteCompositionTelemetry{}
	collector := newViteCompositionCollector(t, capture)
	a, f, publications := restoredConfiguredWorkers(t, config.Services{"enabled": {Public: new(true)}, "disabled": {Public: new(true)}}, nil, nil)
	a.Telemetry = collector
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	t.Cleanup(target.Close)
	entered, release := make(chan struct{}), make(chan struct{})
	unblock := sync.OnceFunc(func() { close(release) })
	defer unblock()
	var enabledCalls, disabledCalls atomic.Int32
	var enteredOnce sync.Once
	attach := a.AttachPublication
	a.AttachPublication = func(ctx context.Context, service publisherapp.Service, cfg *publisherservice.RunConfig) error {
		if service.Framework != string(publisherprotocol.FrameworkVite) || cfg.Ready == nil || cfg.Prepared == nil {
			return errors.New("public Vite registration did not reach the configured publication")
		}
		prepared := cfg.Prepared
		cfg.Prepared = func(preparation controlv1.ServiceRunPreparation) error {
			capture.mu.Lock()
			capture.private = append(capture.private, preparation.ServiceRunId, preparation.RunToken, preparation.IdempotencyKey,
				preparation.Hostname, preparation.ServiceId, preparation.TeamId, preparation.PublisherIdentityId, preparation.PublisherGrantId, preparation.PublisherKeyId)
			capture.mu.Unlock()
			return prepared(preparation)
		}
		observe := cfg.Ready
		cfg.Ready = func() error {
			if service.Name == "enabled" {
				enabledCalls.Add(1)
				enteredOnce.Do(func() { close(entered) })
				select {
				case <-release:
				case <-ctx.Done():
					return context.Cause(ctx)
				}
			} else {
				disabledCalls.Add(1)
			}
			err := observe()
			if err == nil && service.Name == "enabled" {
				capture.accepted.Store(true)
			}
			return err
		}
		return attach(ctx, service, cfg)
	}
	type application struct {
		endpoint     publisherprotocol.Endpoint
		assignment   publisherprotocol.Assignment
		registration publisherprotocol.Registration
		stop         func() error
	}
	var apps []*application
	private := []string{a.project.Root, a.state.Root(), target.URL, target.Listener.Addr().String(),
		f.URL, f.Namespace, f.OwnerToken, a.capabilities.Owner().Capability, "127.0.0.1", "localhost"}
	for _, name := range []string{"disabled", "enabled"} {
		app := &application{}
		viteCompositionCall(t, a.capabilities.Owner(), "/v1/capabilities", publisherprotocol.CapabilityRequest{Scope: "app", Service: &name}, &app.endpoint)
		viteCompositionCall(t, app.endpoint, "/v1/prepare", publisherprotocol.Prepare{Version: 1,
			Directory: a.project.Root, Service: name, Owner: strings.Repeat("a", 32), PID: os.Getpid(),
			Framework: publisherprotocol.FrameworkVite, TelemetryDisabled: name == "disabled"}, &app.assignment)
		app.registration = publisherprotocol.Registration{Version: 1, RegistrationID: app.assignment.RegistrationID,
			Owner: strings.Repeat("a", 32), Target: target.URL}
		private = append(private, app.assignment.RegistrationID, app.assignment.Hostname, app.assignment.PublicURL,
			app.endpoint.Capability, app.endpoint.OwnerId, app.registration.Owner)
		var once sync.Once
		var stopped error
		app.stop = func() error {
			once.Do(func() {
				ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
				defer cancel()
				stopped = publisherprotocol.Call(ctx, app.endpoint, http.MethodPost, "/v1/unregister", app.registration, nil)
			})
			return stopped
		}
		t.Cleanup(func() {
			if err := app.stop(); err != nil {
				t.Error("independent Vite publication unregister/cleanup failure", err)
			}
		})
		apps = append(apps, app)
	}
	// setup alone is not publication, even when it already knows framework=vite.
	viteCompositionBarrier(t, collector, capture)
	if len(capture.ready()) != 0 || f.Runs.Load() != 0 {
		t.Fatal("Vite preparation emitted success before actual registration/publication")
	}
	for _, app := range apps {
		viteCompositionCall(t, app.endpoint, "/v1/register", app.registration, nil)
	}
	seen := map[string]bool{}
	for range 2 {
		publication := restoredWorkerReceive(t, publications, 2*time.Second)
		if seen[publication.service.Name] || publication.service.Name != "enabled" && publication.service.Name != "disabled" ||
			publication.service.Framework != string(publisherprotocol.FrameworkVite) {
			t.Fatal("Vite app registration was not retained at the real worker boundary")
		}
		seen[publication.service.Name] = true
		want := collector
		if publication.service.Name == "disabled" {
			want = nil
		}
		if publication.config.Telemetry != want || publication.config.Prepared == nil || publication.config.AdmitRequest == nil {
			t.Fatal("composed Vite publication changed the real collector or callbacks")
		}
		private = append(private, publication.config.ServiceID, publication.config.PublisherIdentityID,
			publication.config.PublisherGrantID, publication.config.PublisherKeyID, publication.service.TunnelID)
	}
	if len(seen) != 2 {
		t.Fatal("a Vite sibling bypassed the configured publication boundary")
	}
	restoredWorkerReceive(t, entered, 2*time.Second)
	disabled := restoredWorkerService(t, a, "disabled", func(s publisherapp.Service) bool { return s.Routable })
	viteCompositionBarrier(t, collector, capture)
	if len(capture.ready()) != 0 || capture.accepted.Load() || disabledCalls.Load() != 1 {
		t.Fatal("held actual Ready or nil-collector sibling emitted publication success")
	}
	unblock()
	enabled := restoredWorkerService(t, a, "enabled", func(s publisherapp.Service) bool { return s.Routable })
	deadline := time.NewTimer(2 * time.Second)
	defer deadline.Stop()
	for len(capture.ready()) == 0 {
		select {
		case <-capture.requests:
		case <-deadline.C:
			t.Fatal("actual observed Vite publication did not deliver tunnel.ready")
		}
	}
	for range 2 {
		for _, app := range apps {
			viteCompositionCall(t, app.endpoint, "/v1/register", app.registration, nil)
			viteCompositionCall(t, app.endpoint, "/v1/renew", app.registration, nil)
		}
		var snapshot publisherapp.Snapshot
		viteCompositionCall(t, a.capabilities.Owner(), "/v1/check", publisherprotocol.Check{}, &snapshot)
		if len(snapshot.Services) != 2 {
			t.Fatalf("Vite owner returned %d services, want 2", len(snapshot.Services))
		}
		for _, service := range snapshot.Services {
			if !service.Ready || !service.Routable || service.Framework != string(publisherprotocol.FrameworkVite) ||
				service.Name == "enabled" && service.RunNumber != enabled.RunNumber ||
				service.Name == "disabled" && service.RunNumber != disabled.RunNumber {
				t.Error("repeated app registration/check changed the actual Vite run or readiness")
			}
		}
		viteCompositionBarrier(t, collector, capture)
	}
	for _, app := range apps {
		if err := app.stop(); err != nil {
			t.Error("independent Vite publication cleanup failure", err)
		}
	}
	viteCompositionBarrier(t, collector, capture)
	closeViteCompositionCollector(t, collector, capture)
	events := capture.ready()
	if len(events) != 1 || enabledCalls.Load() != 1 || disabledCalls.Load() != 1 || !capture.accepted.Load() {
		t.Errorf("composed Vite Ready count=%d enabled observations=%d disabled observations=%d, want 1 each", len(events), enabledCalls.Load(), disabledCalls.Load())
	}
	for _, event := range events {
		if event.Name != api.TunnelReady || event.EventVersion != 1 || !opaqueid.Valid(event.EventId, opaqueid.TelemetryEventPrefix) ||
			event.Payload.Framework == nil || *event.Payload.Framework != api.PublicationReadyFrameworkVite ||
			event.Payload.PublishMode != api.App || event.Payload.ServerKind != api.SelfHosted {
			t.Error("actual registered Vite app's Ready payload lost framework=vite, app mode or current server kind")
		}
		body, err := json.Marshal(event.Payload)
		var fields map[string]json.RawMessage
		if err != nil || json.Unmarshal(body, &fields) != nil || len(fields) != 3 ||
			fields["framework"] == nil || fields["publish_mode"] == nil || fields["server_kind"] == nil {
			t.Error("actual Vite Ready payload did not retain exactly its anonymous publication facts")
		}
	}
	if f.Enrollments.Load() != 2 || f.Runs.Load() != 2 || f.Allocations.Load() != 0 {
		t.Error("Vite composition bypassed real exact-service enrollment or restarted a run")
	}
	capture.mu.Lock()
	defer capture.mu.Unlock()
	private = append(private, capture.private...)
	for _, body := range capture.wire {
		for _, value := range private {
			if value != "" && bytes.Contains(body, []byte(value)) {
				t.Error("composed Vite telemetry included a local hostname, publication identity, path or credential")
			}
		}
	}
}

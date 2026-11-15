package app

import (
	"context"
	"errors"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	clientproject "github.com/tnldotdev/tnl/internal/client/project"
	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	clienttelemetry "github.com/tnldotdev/tnl/internal/client/telemetry"
	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/observability/inspection"
	"github.com/tnldotdev/tnl/internal/publisher/target"
)

type trip func(*http.Request) (*http.Response, error)

func (f trip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func testWorkers(t *testing.T) (*Workers, <-chan func(uint64, bool) error) {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	database, err := clientstate.OpenWithOptions(t.Context(), filepath.Join(t.TempDir(), "state"), clientstate.OpenOptions{Protection: clientstate.ProtectionFile})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	ready := make(chan func(uint64, bool) error, 8)
	var number atomic.Uint64
	w := &Workers{Database: database}
	w.Configure = func(_ context.Context, service Service) (Configuration, error) {
		return Configuration{Service: &ServicePublication{
			Options: servicePublicationOptions(w, service), URL: "https://public.example",
			Run: func(ctx context.Context, _ *clientstate.Tunnel, observe func(uint64, bool) error, _ inspection.Observer) error {
				run := number.Add(1)
				if err := observe(run, false); err != nil {
					return err
				}
				if err := observe(run, true); err != nil {
					return err
				}
				ready <- observe
				<-ctx.Done()
				return ctx.Err()
			},
			Check: func(_ context.Context, current Service) Observation {
				return Observation{Target: current.Target, RegistrationID: current.RegistrationID, RunNumber: current.RunNumber,
					Readiness: current.Readiness, CheckedAt: time.Now().UTC(), Reason: "runtime.probe_failed"}
			},
		}, Inspection: inspection.Policy{Mode: inspection.None}}, nil
	}
	w.Manager, err = New(t.Context(), root, database, []Service{{Name: "web", ServiceProtocol: "http", Readiness: Readiness{Path: "/health"}}}, w.Run)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(w.Manager.Close)
	return w, ready
}

func TestPublicationTelemetryOptOutDoesNotDisableSiblingWorker(t *testing.T) {
	w, _ := testWorkers(t)
	configure := w.Configure
	type observation struct {
		service  string
		disabled bool
	}
	observed := make(chan observation, 2)
	w.Configure = func(ctx context.Context, service Service) (Configuration, error) {
		configuration, err := configure(ctx, service)
		if err != nil {
			return configuration, err
		}
		var telemetry *clienttelemetry.Collector
		if service.Name != "web" {
			telemetry = &clienttelemetry.Collector{}
		}
		run := configuration.Service.Run
		configuration.Service.Run = func(ctx context.Context, tunnel *clientstate.Tunnel, observe func(uint64, bool) error, summary inspection.Observer) error {
			observed <- observation{service.Name, telemetry == nil}
			return run(ctx, tunnel, observe, summary)
		}
		return configuration, nil
	}
	services := append(w.Manager.Snapshot().Services, Service{Name: "api", ServiceProtocol: "http"})
	if err := w.Manager.Configure(services); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"web", "api"} {
		id, err := w.Manager.Reserve(name, name, 1, "https://public.example")
		if err != nil {
			t.Fatal(err)
		}
		if err := w.Manager.Register(id, name, "http://127.0.0.1:3000", "node"); err != nil {
			t.Fatal(err)
		}
	}
	for range 2 {
		value := receiveServicePublication(t, observed)
		if value.disabled != (value.service == "web") {
			t.Fatalf("mixed sibling choice: %+v", value)
		}
	}
}

func TestOwnerProofIsFreshExactAndStaleReadinessCannotCrossReplacement(t *testing.T) {
	w, ready, _, probe := automaticWorkers(t, time.Second)
	w.AutomaticReadiness = false
	firstObserve, id := registerAutomaticService(t, w, ready)
	var proofs []string
	probe.transport = trip(func(r *http.Request) (*http.Response, error) {
		if r.URL.String() != "https://public.example/health" || r.Header.Get("Cookie") != "" || r.Header.Get("Authorization") != "" {
			t.Error("invalid probe request")
		}
		proofs = append(proofs, r.Header.Get(ProbeHeader))
		return automaticResponse(http.StatusOK), nil
	})
	for range 2 {
		snapshot, err := w.Check(t.Context(), []string{"web"})
		if err != nil || !snapshot.Services[0].Ready {
			t.Fatalf("readiness=%+v err=%v", snapshot.Services, err)
		}
	}
	if len(proofs) != 2 || len(proofs[0]) != 64 || proofs[0] == proofs[1] {
		t.Fatal("operation checks reused a readiness proof")
	}
	var calls atomic.Int32
	probe.transport = trip(func(r *http.Request) (*http.Response, error) {
		if calls.Add(1) == 1 {
			if err := w.Manager.Register(id, "owner", "http://127.0.0.1:3001", "node"); err != nil {
				t.Error(err)
			}
			receiveServicePublication(t, ready)
		}
		return automaticResponse(http.StatusOK), nil
	})
	snapshot, err := w.Check(t.Context(), []string{"web"})
	if err != nil || snapshot.Services[0].Ready {
		t.Fatal("old readiness crossed endpoint replacement")
	}
	if err := firstObserve(2, true); !errors.Is(err, ErrRegistrationStale) {
		t.Fatal("old operation changed the replacement's publication", err)
	}
	if !snapshot.Services[0].Routable {
		t.Fatal("readiness failure stopped publication")
	}
}

func TestReadinessProbeRejectsSameAddressTargetReplacementBeforeAcceptance(t *testing.T) {
	w, ready, _, probe := automaticWorkers(t, time.Second)
	w.AutomaticReadiness = false
	_, id := registerAutomaticService(t, w, ready)
	var replaced atomic.Bool
	probe.transport = trip(func(*http.Request) (*http.Response, error) {
		if replaced.CompareAndSwap(false, true) {
			w.Manager.TargetChanged("web", id, "http://127.0.0.1:3000")
		}
		return automaticResponse(http.StatusOK), nil
	})
	service := w.Manager.Snapshot().Services[0]
	if w.checkService(t.Context(), service) {
		t.Fatal("old target identity's success was accepted at the same address")
	}
	current := w.Manager.Snapshot().Services[0]
	if current.Ready || !current.Routable || current.Observation == nil || current.Observation.Reason != "runtime.target_changed" {
		t.Fatal("target replacement lost its readiness invalidation", current)
	}
	if !w.checkService(t.Context(), current) {
		t.Fatal("a fresh explicit check could not accept the replacement identity")
	}
}

func TestOneJournalContainsDirectNamedAndReadinessTransitions(t *testing.T) {
	w, ready := testWorkers(t)
	cursor := w.Manager.Snapshot().Cursor
	direct, err := w.Database.BeginTunnel(t.Context(), clientstate.BeginTunnelOptions{Command: clientstate.TunnelCommandPublish, Server: "https://control.example", Target: "3000", Project: w.Manager.Snapshot().Project})
	if err != nil {
		t.Fatal(err)
	}
	defer direct.Finish(context.Background(), nil)
	id, err := w.Manager.Reserve("web", "owner", 1, "https://public.example")
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Manager.Register(id, "owner", "http://127.0.0.1:3000", ""); err != nil {
		t.Fatal(err)
	}
	receiveServicePublication(t, ready)
	snapshot := w.Manager.Snapshot()
	if len(snapshot.Publications) != 2 {
		t.Fatalf("publications=%+v", snapshot.Publications)
	}
	events, err := EventsAfterFrom(t.Context(), w.Database, snapshot.Project, cursor)
	if err != nil {
		t.Fatal(err)
	}
	var directEvent, namedEvent bool
	for _, event := range events {
		if event.Publication != nil {
			if event.Publication.ID == direct.ID() {
				directEvent = true
			} else {
				namedEvent = true
			}
		}
		if strings.Contains(event.Cursor, ":") {
			t.Fatal("composed cursor")
		}
	}
	if !directEvent || !namedEvent {
		t.Fatal("journal omitted direct or named publication")
	}
	resumed, err := EventsAfterFrom(t.Context(), w.Database, snapshot.Project, events[len(events)-1].Cursor)
	if err != nil || len(resumed) != 0 {
		t.Fatal("event resume was not exclusive")
	}
}

func TestTargetResolutionDelegatesDiscoveryAndRejectsApps(t *testing.T) {
	protocol := "tcp"
	port := 6379
	container := "redis-worktree"
	project := clientproject.Project{Root: "/project", Config: config.TNL{Services: config.Services{"db": {Protocol: &protocol, Target: &config.ServiceTarget{Type: "docker", Container: &container, Port: &port}}, "web": {}}}}
	var selected string
	resolved, err := target.ResolveTarget(t.Context(), project, "db", target.TargetResolverFunc(func(_ context.Context, p clientproject.Project, name string) (string, string, error) {
		selected = name
		if p.Root != "/project" {
			t.Error("wrong project")
		}
		return "127.0.0.1:16379", "redis-container-id", nil
	}))
	if err != nil || selected != "db" || string(*resolved.Target) != "127.0.0.1:16379" {
		t.Fatalf("resolved=%+v err=%v", resolved, err)
	}
	if _, err := target.ResolveTarget(t.Context(), project, "web", nil); err == nil {
		t.Fatal("app published without a registration")
	}
}

func TestLifecycleAttachmentIsFencedAndJoined(t *testing.T) {
	w, ready := testWorkers(t)
	configure := w.Configure
	attached := make(chan *clientstate.Tunnel, 1)
	stopped := make(chan struct{})
	project := w.Manager.Snapshot().Project
	group := clientstate.IntegrationScope{PrimaryProjectRoot: project, Namespace: "member.example"}
	w.Configure = func(ctx context.Context, service Service) (Configuration, error) {
		configuration, err := configure(ctx, service)
		if err != nil {
			return configuration, err
		}
		configuration.Service.Options.IntegrationScope = group
		run := configuration.Service.Run
		configuration.Service.Run = func(ctx context.Context, tunnel *clientstate.Tunnel, observe func(uint64, bool) error, summary inspection.Observer) error {
			if tunnel == nil || tunnel.Context() != ctx {
				return errors.New("operation did not receive the journal's tunnel and context")
			}
			current := w.Manager.Snapshot()
			if len(current.Publications) != 1 || current.Services[0].TunnelID != tunnel.ID() ||
				current.Publications[0].ID != tunnel.ID() || current.Publications[0].IntegrationScope != group {
				return errors.New("operation started before journal binding or lost its integration scope")
			}
			attached <- tunnel
			defer func() {
				snapshot, err := w.Database.SnapshotProject(context.WithoutCancel(ctx), project)
				if err != nil || len(snapshot.Tunnels) != 1 || snapshot.Tunnels[0].ID != tunnel.ID() {
					t.Error("journal finished before the operation's integration cleanup", err)
				}
				close(stopped)
			}()
			return run(ctx, tunnel, observe, summary)
		}
		return configuration, nil
	}
	id := registerServicePublication(t, w, "http://127.0.0.1:3000", "https://public.example")
	observe := receiveServicePublication(t, ready)
	tunnel := receiveServicePublication(t, attached)
	if tunnel.ID() != w.Manager.Snapshot().Services[0].TunnelID {
		t.Fatal("operation attached to a different local publication")
	}
	if err := w.Manager.UnregisterTarget(id, "owner", "http://127.0.0.1:3000"); err != nil {
		t.Fatal(err)
	}
	if service := w.Manager.Snapshot().Services[0]; service.RegistrationID != "" || service.Target != "" || service.TunnelID != "" || service.RunNumber != 0 || service.ProvisioningStage != "" {
		t.Fatalf("stopped service retained lifecycle identity: %+v", service)
	}
	select {
	case <-stopped:
	default:
		t.Fatal("operation integration cleanup was not joined")
	}
	if err := observe(2, true); !errors.Is(err, ErrRegistrationStale) {
		t.Fatal("stopped operation bypassed owner fencing", err)
	}
}

func TestWorkerFollowsReplacedTargetWithoutChangingItsRun(t *testing.T) {
	w, ready, _, probe := automaticWorkers(t, time.Second)
	w.AutomaticReadiness = false
	observe, id := registerAutomaticService(t, w, ready)
	probe.transport = trip(func(*http.Request) (*http.Response, error) { return automaticResponse(http.StatusOK), nil })
	if snapshot, err := w.Check(t.Context(), []string{"web"}); err != nil || !snapshot.Services[0].Ready {
		t.Fatalf("original target was not ready: %+v, %v", snapshot.Services, err)
	}
	before := w.Manager.Snapshot().Services[0]
	w.Manager.TargetChanged("web", id, before.Target)
	if err := observe(before.RunNumber, true); err != nil {
		t.Fatal(err)
	}
	if current := w.Manager.Snapshot().Services[0]; current.Ready || !current.Routable || current.RunNumber != before.RunNumber || current.TunnelID != before.TunnelID {
		t.Fatal("target replacement kept old readiness or changed publication ownership", current)
	}
	var probes atomic.Int32
	probe.transport = trip(func(*http.Request) (*http.Response, error) {
		probes.Add(1)
		return automaticResponse(http.StatusOK), nil
	})
	if snapshot, err := w.Check(t.Context(), []string{"web"}); err != nil || !snapshot.Services[0].Ready || probes.Load() != 1 {
		t.Fatalf("replacement target readiness=%+v, probes=%d, err=%v", snapshot.Services, probes.Load(), err)
	}
	probe.transport = trip(func(*http.Request) (*http.Response, error) {
		w.Manager.TargetChanged("web", id, before.Target)
		return automaticResponse(http.StatusOK), nil
	})
	if snapshot, err := w.Check(t.Context(), []string{"web"}); err != nil || snapshot.Services[0].Ready {
		t.Fatalf("target replacement during a probe was accepted: %+v, %v", snapshot.Services, err)
	}
	if err := w.Manager.UnregisterTarget(id, "owner", before.Target); err != nil {
		t.Fatal(err)
	}
	if err := observe(before.RunNumber, true); !errors.Is(err, ErrRegistrationStale) {
		t.Fatal("stopped service still accepted operation observations", err)
	}
}

func TestPublicWorkerStartsAutomaticReadiness(t *testing.T) {
	w, ready, _, probe := automaticWorkers(t, time.Second)
	gets := make(chan string, 1)
	probe.transport = trip(func(r *http.Request) (*http.Response, error) {
		gets <- r.Header.Get(ProbeHeader)
		return &http.Response{StatusCode: http.StatusOK, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(""))}, nil
	})
	registerAutomaticService(t, w, ready)
	expectAutomaticGET(t, gets)
	waitAutomaticReady(t, w, 1)
}

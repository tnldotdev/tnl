package projectpublisher

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/clientruntime"
	"github.com/tnldotdev/tnl/internal/clientstate"
	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/inspection"
	"github.com/tnldotdev/tnl/internal/projectconfig"
	"github.com/tnldotdev/tnl/internal/publisher"
)

type trip func(*http.Request) (*http.Response, error)

func (f trip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func testWorkers(t *testing.T) (*Workers, <-chan publisher.Config) {
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
	ready := make(chan publisher.Config, 8)
	var number atomic.Uint64
	w := &Workers{Database: database}
	w.Configure = func(_ context.Context, s clientruntime.Service) (Configuration, error) {
		return Configuration{Publisher: publisher.Config{Hostname: "public.example", ControlURL: "https://control.example", ProjectRoot: root, Target: s.Target, Service: s.Name, ServiceProtocol: "http"}, Inspection: inspection.Policy{Mode: inspection.None}}, nil
	}
	w.RunPublisher = func(ctx context.Context, cfg publisher.Config) error {
		run := number.Add(1)
		id := "url_0123456789abcdefghijkl"
		if err := cfg.Observe(publisher.Event{Type: publisher.EventPublicURLAssigned, PublicURLID: id, Hostname: "public.example"}); err != nil {
			return err
		}
		if err := cfg.Observe(publisher.Event{Type: publisher.EventProvisioning, PublishRunNumber: run}); err != nil {
			return err
		}
		if cfg.ReadinessProof(publisher.PublishRunIdentity{Hostname: "public.example", PublicURLID: id, Number: run}) == nil {
			return errors.New("missing readiness proof")
		}
		if err := cfg.Observe(publisher.Event{Type: publisher.EventReady, PublicURL: "https://public.example", PublishRunNumber: run}); err != nil {
			return err
		}
		ready <- cfg
		<-ctx.Done()
		return ctx.Err()
	}
	w.Manager, err = clientruntime.New(t.Context(), root, database, []clientruntime.Service{{Name: "web", ServiceProtocol: "http", Readiness: clientruntime.Readiness{Path: "/health"}}}, w.Run)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(w.Manager.Close)
	return w, ready
}

func receiveConfig(t *testing.T, ready <-chan publisher.Config) publisher.Config {
	t.Helper()
	select {
	case cfg := <-ready:
		return cfg
	case <-time.After(5 * time.Second):
		t.Fatal("worker did not become routable")
		return publisher.Config{}
	}
}

func TestOwnerProofIsFreshExactAndStaleReadinessCannotCrossReplacement(t *testing.T) {
	w, ready := testWorkers(t)
	id, err := w.Manager.Reserve("web", "owner", 1, "https://public.example")
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Manager.Register(id, "owner", "http://127.0.0.1:3000", "node"); err != nil {
		t.Fatal(err)
	}
	firstCfg := receiveConfig(t, ready)
	var proofs []string
	w.HTTPTransport = trip(func(r *http.Request) (*http.Response, error) {
		if r.URL.String() != "https://public.example/health" || r.Header.Get("Cookie") != "" || r.Header.Get("Authorization") != "" {
			t.Errorf("invalid probe request")
		}
		proofs = append(proofs, r.Header.Get(clientruntime.ProbeHeader))
		return &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(strings.NewReader("")), Request: r}, nil
	})
	for range 2 {
		snapshot, err := w.Check(t.Context(), []string{"web"})
		if err != nil || !snapshot.Services[0].Ready {
			t.Fatalf("readiness=%+v err=%v", snapshot.Services, err)
		}
	}
	if len(proofs) != 2 || len(proofs[0]) != 64 || proofs[0] == proofs[1] {
		t.Fatal("owner reused a readiness proof")
	}
	var calls atomic.Int32
	w.HTTPTransport = trip(func(r *http.Request) (*http.Response, error) {
		if calls.Add(1) == 1 {
			if err := w.Manager.Register(id, "owner", "http://127.0.0.1:3001", "node"); err != nil {
				t.Error(err)
			}
			receiveConfig(t, ready)
		}
		return &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(strings.NewReader("")), Request: r}, nil
	})
	snapshot, err := w.Check(t.Context(), []string{"web"})
	if err != nil || snapshot.Services[0].Ready {
		t.Fatal("old run readiness crossed endpoint replacement")
	}
	if firstCfg.PromoteVisitor != nil {
		t.Fatal("worker replaced the authenticated promotion default")
	}
	if err := firstCfg.AdmitVisitor(t.Context(), publisher.Visitor{Run: publisher.PublishRunIdentity{Number: 1}}); err == nil {
		t.Fatal("old worker admitted a visitor")
	}
	if !snapshot.Services[0].Routable {
		t.Fatal("readiness failure stopped publication")
	}
}

func TestReadinessProbeRejectsSameAddressTargetReplacementBeforeAcceptance(t *testing.T) {
	w, ready := testWorkers(t)
	var identity atomic.Value
	identity.Store("container-a")
	configure := w.Configure
	w.Configure = func(ctx context.Context, service clientruntime.Service) (Configuration, error) {
		cfg, err := configure(ctx, service)
		cfg.TargetBinding = &TargetBinding{Resolve: func(context.Context) (TargetSnapshot, error) {
			return TargetSnapshot{Address: service.Target, Identity: identity.Load().(string)}, nil
		}}
		return cfg, err
	}
	registerAutomaticWorker(t, w, ready)
	w.HTTPTransport = trip(func(*http.Request) (*http.Response, error) {
		identity.Store("container-b")
		return automaticResponse(200), nil
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
		t.Fatal("a fresh explicit probe could not accept the replacement identity")
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
	receiveConfig(t, ready)
	snapshot := w.Manager.Snapshot()
	if len(snapshot.Publications) != 2 {
		t.Fatalf("publications=%+v", snapshot.Publications)
	}
	events, err := clientruntime.EventsAfterFrom(t.Context(), w.Database, snapshot.Project, cursor)
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
	resumed, err := clientruntime.EventsAfterFrom(t.Context(), w.Database, snapshot.Project, events[len(events)-1].Cursor)
	if err != nil || len(resumed) != 0 {
		t.Fatal("event resume was not exclusive")
	}
}

func TestTargetResolutionDelegatesDiscoveryAndRejectsApps(t *testing.T) {
	protocol := "tcp"
	port := 6379
	container := "redis-worktree"
	project := projectconfig.Project{Root: "/project", Config: config.TNL{Services: config.Services{"db": {Protocol: &protocol, Target: &config.ServiceTarget{Type: "docker", Container: &container, Port: &port}}, "web": {}}}}
	var selected string
	resolved, err := ResolveTarget(t.Context(), project, "db", TargetResolverFunc(func(_ context.Context, p projectconfig.Project, name string) (string, error) {
		selected = name
		if p.Root != "/project" {
			t.Error("wrong project")
		}
		return "127.0.0.1:16379", nil
	}))
	if err != nil || selected != "db" || string(*resolved.Target) != "127.0.0.1:16379" {
		t.Fatalf("resolved=%+v err=%v", resolved, err)
	}
	if _, err := ResolveTarget(t.Context(), project, "web", nil); err == nil {
		t.Fatal("app published without a registration")
	}
}

func TestLifecycleAttachmentIsFencedAndJoined(t *testing.T) {
	w, ready := testWorkers(t)
	configure := w.Configure
	var admissions atomic.Int32
	stopped := make(chan struct{})
	w.Configure = func(ctx context.Context, service clientruntime.Service) (Configuration, error) {
		configuration, err := configure(ctx, service)
		configuration.Attach = func(_ context.Context, _ *clientstate.Tunnel, cfg *publisher.Config) (func(), error) {
			cfg.AdmitVisitor = func(context.Context, publisher.Visitor) error { admissions.Add(1); return nil }
			return func() { close(stopped) }, nil
		}
		return configuration, err
	}
	id, err := w.Manager.Reserve("web", "owner", 1, "https://public.example")
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Manager.Register(id, "owner", "http://127.0.0.1:3000", ""); err != nil {
		t.Fatal(err)
	}
	cfg := receiveConfig(t, ready)
	visitor := publisher.Visitor{Run: publisher.PublishRunIdentity{Number: 1}}
	if cfg.PromoteVisitor != nil {
		t.Fatal("worker disabled the authenticated promotion default")
	}
	if err := cfg.AdmitVisitor(t.Context(), visitor); err != nil || admissions.Load() != 1 {
		t.Fatal("lifecycle admission hook was not composed")
	}
	if err := w.Manager.UnregisterTarget(id, "owner", "http://127.0.0.1:3000"); err != nil {
		t.Fatal(err)
	}
	if service := w.Manager.Snapshot().Services[0]; service.RegistrationID != "" || service.Target != "" || service.TunnelID != "" || service.PublishRunNumber != 0 || service.ProvisioningStage != "" {
		t.Fatalf("stopped service retained lifecycle identity: %+v", service)
	}
	select {
	case <-stopped:
	default:
		t.Fatal("lifecycle cleanup was not joined")
	}
	if err := cfg.AdmitVisitor(t.Context(), visitor); err == nil || admissions.Load() != 1 {
		t.Fatal("lifecycle hook bypassed owner fencing")
	}
}

func TestWorkerFollowsReplacedTargetWithoutChangingItsRun(t *testing.T) {
	w, ready := testWorkers(t)
	original := w.Configure
	var identity atomic.Value
	identity.Store("container-a")
	var aliasAdmit func(*http.Request, publisher.PublishRunIdentity) error
	w.Configure = func(ctx context.Context, service clientruntime.Service) (Configuration, error) {
		cfg, err := original(ctx, service)
		cfg.TargetBinding = &TargetBinding{Resolve: func(context.Context) (TargetSnapshot, error) {
			return TargetSnapshot{Address: service.Target, Identity: identity.Load().(string)}, nil
		}}
		cfg.Attach = func(_ context.Context, _ *clientstate.Tunnel, entry *publisher.Config) (func(), error) {
			aliasAdmit = entry.AdmitRequest
			return nil, nil
		}
		return cfg, err
	}
	id, err := w.Manager.Reserve("web", "owner", 1, "https://public.example")
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Manager.Register(id, "owner", "http://127.0.0.1:3000", "node"); err != nil {
		t.Fatal(err)
	}
	cfg := receiveConfig(t, ready)
	run := publisher.PublishRunIdentity{Number: 1}
	if err := cfg.AdmitRequest(httptest.NewRequest("GET", "http://public.example/", nil), run); err != nil {
		t.Fatal(err)
	}
	w.HTTPTransport = trip(func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(strings.NewReader("")), Request: r}, nil
	})
	if snapshot, err := w.Check(t.Context(), []string{"web"}); err != nil || !snapshot.Services[0].Ready {
		t.Fatalf("original target was not ready: %+v, %v", snapshot.Services, err)
	}
	identity.Store("container-b")
	if err := cfg.AdmitRequest(httptest.NewRequest("GET", "http://public.example/", nil), run); err != nil {
		t.Fatalf("replacement container blocked new HTTP request: %v", err)
	}
	if snapshot := w.Manager.Snapshot(); snapshot.Services[0].Ready {
		t.Fatal("target replacement kept readiness from the previous target")
	}
	if aliasAdmit == nil || aliasAdmit(httptest.NewRequest("GET", "http://public.example/", nil), run) != nil {
		t.Fatal("alias attachment did not follow the selected target")
	}
	if err := cfg.AdmitVisitor(t.Context(), publisher.Visitor{Run: run}); err != nil {
		t.Fatalf("replacement container blocked new TCP connection: %v", err)
	}
	var probes atomic.Int32
	w.HTTPTransport = trip(func(*http.Request) (*http.Response, error) {
		probes.Add(1)
		return &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(""))}, nil
	})
	snapshot, err := w.Check(t.Context(), []string{"web"})
	if err != nil || !snapshot.Services[0].Ready || probes.Load() != 1 {
		t.Fatalf("replacement target readiness=%+v, probes=%d, err=%v", snapshot.Services, probes.Load(), err)
	}
	w.HTTPTransport = trip(func(*http.Request) (*http.Response, error) {
		identity.Store("container-c")
		return &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(""))}, nil
	})
	if snapshot, err := w.Check(t.Context(), []string{"web"}); err != nil || snapshot.Services[0].Ready {
		t.Fatalf("target replacement during public probe was accepted: %+v, %v", snapshot.Services, err)
	}
	if err := w.Manager.UnregisterTarget(id, "owner", "http://127.0.0.1:3000"); err != nil {
		t.Fatal(err)
	}
	if err := cfg.AdmitVisitor(t.Context(), publisher.Visitor{Run: run}); err == nil {
		t.Fatal("stopped service still admitted a visitor")
	}
}

func TestPublicWorkerStartsAutomaticReadiness(t *testing.T) {
	w, ready := testWorkers(t)
	w.AutomaticReadiness = true
	probed := make(chan struct{}, 1)
	w.HTTPTransport = trip(func(r *http.Request) (*http.Response, error) {
		if len(r.Header.Get(clientruntime.ProbeHeader)) != 64 {
			t.Error("automatic readiness omitted proof")
		}
		select {
		case probed <- struct{}{}:
		default:
		}
		return &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(""))}, nil
	})
	id, err := w.Manager.Reserve("web", "owner", 1, "https://public.example")
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Manager.Register(id, "owner", "http://127.0.0.1:3000", "node"); err != nil {
		t.Fatal(err)
	}
	receiveConfig(t, ready)
	select {
	case <-probed:
	case <-time.After(2 * time.Second):
		t.Fatal("public readiness was never started")
	}
	deadline := time.Now().Add(time.Second)
	for !w.Manager.Snapshot().Services[0].Ready {
		if time.Now().After(deadline) {
			t.Fatal("automatic readiness was not recorded")
		}
		time.Sleep(time.Millisecond)
	}
}

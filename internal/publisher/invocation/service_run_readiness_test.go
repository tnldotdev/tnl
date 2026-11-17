package invocation

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/observability/inspection"
	"github.com/tnldotdev/tnl/internal/policy/visitorscope"
	publisherapp "github.com/tnldotdev/tnl/internal/publisher/app"
	"github.com/tnldotdev/tnl/internal/publisher/httpaccess"
	publisherservice "github.com/tnldotdev/tnl/internal/publisher/service"
	targetplan "github.com/tnldotdev/tnl/internal/publisher/target"
	"github.com/tnldotdev/tnl/internal/transport/targettransport"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestServiceRunReadinessReplacesTheExactBindingAndProof(t *testing.T) {
	for _, path := range []string{"", "/health"} {
		t.Run("path="+path, func(t *testing.T) {
			readiness, _, preparation := testServiceRunReadiness(t, http.NotFoundHandler())
			readiness.path = path
			original := readiness.load()
			captured := readiness.current
			proof := readiness.proof(original.run)
			if proof == nil {
				t.Fatal("current run did not receive a proof")
			}
			requestPath := path
			if requestPath == "" {
				requestPath = "/"
			}
			request := httptest.NewRequest(http.MethodGet, "https://app.example"+requestPath, nil)
			request.Header.Set(publisherapp.ProbeHeader, proof.HeaderValue())
			if !proof.Consume(request, original.run) || proof.Consume(request, original.run) {
				t.Fatal("proof was not restricted to one use on the configured path")
			}
			for _, field := range []string{"service", "id", "number", "hostname"} {
				other := original.run
				switch field {
				case "service":
					other.Subject.ID = "svc_2222222222222222222222"
				case "id":
					other.ID = "srun_2222222222222222222222"
				case "number":
					other.Number++
				case "hostname":
					other.Hostname = "other.example"
				}
				if readiness.proof(other) != nil || readiness.load().proof != proof {
					t.Fatalf("mismatched %s changed the current proof", field)
				}
			}
			preparation.ServiceRunId = "srun_2222222222222222222222"
			preparation.RunNumber++
			target := original.target
			target.Identity = "replacement"
			readiness.prepare(target, preparation)
			current := readiness.load()
			if current.target != target || current.run.Number != uint64(preparation.RunNumber) || current.proof != nil {
				t.Fatal("preparation did not replace the target/run and clear its proof")
			}
			if captured.run != original.run || captured.target != original.target || captured == readiness.current {
				t.Fatal("a captured callback binding followed its replacement run")
			}
			if readiness.proof(original.run) != nil || readiness.load() != current {
				t.Fatal("an old proof callback modified the replacement run")
			}
			if next := readiness.proof(current.run); next == nil || next == proof || next.HeaderValue() == "" {
				t.Fatal("replacement run did not receive its own fresh proof")
			}
		})
	}
}

func TestServiceRunReadinessAvailabilityUsesExactRunAndSerializedPublication(t *testing.T) {
	project, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	database, err := clientstate.OpenWithOptions(t.Context(), filepath.Join(t.TempDir(), "state"), clientstate.OpenOptions{Protection: clientstate.ProtectionFile})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	callbacks := make(chan func(uint64, bool) error, 2)
	workers := &publisherapp.Workers{Database: database}
	workers.Configure = func(_ context.Context, service publisherapp.Service) (publisherapp.Configuration, error) {
		return publisherapp.Configuration{Service: &publisherapp.ServicePublication{
			Options: clientstate.BeginTunnelOptions{Command: clientstate.TunnelCommandPublish, Server: "https://control.example",
				Project: project, Service: service.Name, Target: service.Target, ServiceProtocol: controlv1.ServiceProtocolHTTP},
			URL: "https://public.example",
			Run: func(ctx context.Context, _ *clientstate.Tunnel, observe func(uint64, bool) error, _ inspection.Observer) error {
				callbacks <- observe
				<-ctx.Done()
				return ctx.Err()
			},
			Check: func(context.Context, publisherapp.Service) publisherapp.Observation {
				return publisherapp.Observation{}
			},
		}}, nil
	}
	manager, err := publisherapp.New(t.Context(), project, database, []publisherapp.Service{{Name: "web", ServiceProtocol: "http"}}, workers.Run)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(manager.Close)
	workers.Manager = manager
	runtime := &ProjectRuntime{manager: manager}
	id, err := manager.Reserve("web", "owner", 1, "")
	if err != nil {
		t.Fatal(err)
	}
	target := "http://127.0.0.1:3000"
	if err := manager.Register(id, "owner", target, ""); err != nil {
		t.Fatal(err)
	}
	var observe func(uint64, bool) error
	select {
	case observe = <-callbacks:
	case <-time.After(5 * time.Second):
		t.Fatal("service operation did not start")
	}
	run := httpaccess.ReadinessRun{Subject: visitorscope.Scope{Kind: visitorscope.Service, ID: "svc_1111111111111111111111"},
		ID: "srun_1111111111111111111111", Number: 7, Hostname: "public.example"}
	if err := observe(run.Number, false); err != nil {
		t.Fatal(err)
	}
	// the one-time Ready callback announces initial publication before ongoing
	// RunStatus observations can change its availability.
	if err := observe(run.Number, true); err != nil {
		t.Fatal(err)
	}
	service := manager.Snapshot().Services[0]
	for _, ready := range []bool{false, true} {
		cursor := manager.Snapshot().Cursor
		status := publisherservice.RunStatus{Ready: ready, TargetHealthy: true, ConfigurationCurrent: true,
			LastCheck: time.Now(), LeaseExpiresAt: time.Now().Add(time.Minute)}
		if err := runtime.observeServiceReadiness(service, run, status, observe); err != nil {
			t.Fatal(err)
		}
		snapshot := manager.Snapshot()
		state := clientstate.TunnelStateProvisioning
		if ready {
			state = clientstate.TunnelStateReady
		}
		current := snapshot.Services[0]
		if current.Routable != ready || current.Ready || current.RunNumber != run.Number || current.RegistrationID != id ||
			len(snapshot.Publications) != 1 || snapshot.Publications[0].State != state || snapshot.Publications[0].PublishRunNumber != run.Number {
			t.Fatal("availability changed the run or conflated the owner check", snapshot)
		}
		events, err := publisherapp.EventsAfterFrom(t.Context(), database, project, cursor)
		if err != nil {
			t.Fatal(err)
		}
		var transitions []string
		for _, event := range events {
			if event.Publication != nil && event.Publication.ID == current.TunnelID {
				transitions = append(transitions, "journal")
			}
			if event.Type == "service.publication" {
				transitions = append(transitions, "manager")
			}
		}
		if !reflect.DeepEqual(transitions, []string{"journal", "manager"}) {
			t.Fatal("availability observation preceded its journal commit", transitions)
		}
		// repeated runtime reports do not write another publication transition.
		cursor = snapshot.Cursor
		if err := runtime.observeServiceReadiness(service, run, status, observe); err != nil {
			t.Fatal(err)
		}
		if after := manager.Snapshot(); after.Cursor != cursor {
			t.Fatal("unchanged runtime availability rewrote the journal", after)
		}
	}
	observationFailure := errors.New("publication observation failed")
	beforeFailure := manager.Snapshot()
	if err := runtime.observeServiceReadiness(service, run, publisherservice.RunStatus{}, func(uint64, bool) error {
		return errors.Join(context.Canceled, observationFailure)
	}); !errors.Is(err, observationFailure) {
		t.Fatal("availability discarded an independent observation failure", err)
	}
	if after := manager.Snapshot(); after.Cursor != beforeFailure.Cursor || !reflect.DeepEqual(after.Services, beforeFailure.Services) {
		t.Fatal("failed availability observation changed the manager", after)
	}
	// hold a status after its current-run read, then replace the run before it
	// reaches the worker's existing serialized publication transition.
	entered, release := make(chan struct{}), make(chan struct{})
	unblock := sync.OnceFunc(func() { close(release) })
	defer unblock()
	stale := make(chan error, 1)
	go func() {
		stale <- runtime.observeServiceReadiness(service, run, publisherservice.RunStatus{}, func(number uint64, ready bool) error {
			close(entered)
			<-release
			return observe(number, ready)
		})
	}()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("runtime status did not reach publication observation")
	}
	if err := observe(8, true); err != nil {
		t.Fatal(err)
	}
	before := manager.Snapshot()
	unblock()
	select {
	case err := <-stale:
		if !errors.Is(err, publisherapp.ErrRegistrationStale) {
			t.Fatal("stale in-flight status was accepted", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("stale runtime status did not finish")
	}
	for _, ready := range []bool{false, true} {
		if err := runtime.observeServiceReadiness(service, run, publisherservice.RunStatus{Ready: ready}, observe); !errors.Is(err, publisherapp.ErrRegistrationStale) {
			t.Fatal("old run status was accepted", err)
		}
	}
	if after := manager.Snapshot(); after.Cursor != before.Cursor || !reflect.DeepEqual(after.Services, before.Services) {
		t.Fatal("stale status changed the journal or manager", after)
	}
}

func TestServiceRunReadinessKeepsLocalHealthSeparateFromPublicProof(t *testing.T) {
	var requests atomic.Int32
	readiness, service, _ := testServiceRunReadiness(t, http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		requests.Add(1)
		if request.URL.Path != "/health" {
			t.Errorf("unexpected readiness path %q", request.URL.Path)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	current := readiness.load()
	proof := readiness.proof(current.run)
	if proof == nil {
		t.Fatal("current run did not receive a proof")
	}
	secret := proof.HeaderValue()
	service.Target = "http://reported.example"
	observation := readiness.check(t.Context(), service)
	if !observation.Ready || observation.Target != service.Target || observation.RegistrationID != service.RegistrationID || observation.RunNumber != service.RunNumber {
		t.Fatalf("local health lost its registration/target/run: %+v", observation)
	}
	if proof.HeaderValue() != secret {
		t.Fatal("local health consumed or renewed the public proof")
	}
	readiness.publicURL = current.target.Address
	observation = readiness.check(t.Context(), service)
	if observation.Ready || observation.Reason != "runtime.target_changed" || proof.HeaderValue() == "" {
		t.Fatalf("an unrelated successful response counted as public readiness: %+v", observation)
	}
	service.RunNumber++
	for _, check := range []func(context.Context, publisherapp.Service) publisherapp.Observation{readiness.check, readiness.localCheck} {
		if observation := check(t.Context(), service); observation.Ready || observation.Reason != "runtime.target_changed" {
			t.Fatalf("stale run reached a readiness check: %+v", observation)
		}
	}
	if requests.Load() != 2 {
		t.Fatalf("stale checks reached the target: %d requests", requests.Load())
	}
}

func TestServiceRunReadinessRejectsReplacementDuringCheck(t *testing.T) {
	for _, public := range []bool{false, true} {
		for _, replacement := range []string{"run", "target"} {
			name := "local/" + replacement
			if public {
				name = "public/" + replacement
			}
			t.Run(name, func(t *testing.T) {
				ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
				defer cancel()
				entered, release := make(chan struct{}), make(chan struct{})
				unblock := sync.OnceFunc(func() { close(release) })
				var readiness *serviceRunReadiness
				handler := http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
					current := readiness.load()
					if public {
						if !current.proof.Consume(request, current.run) {
							t.Error("current owner probe did not consume its proof")
						}
					} else if request.Header.Get(publisherapp.ProbeHeader) != "" {
						t.Error("local health sent a public readiness proof")
					}
					close(entered)
					select {
					case <-release:
					case <-request.Context().Done():
					}
					w.WriteHeader(http.StatusNoContent)
				})
				readiness, service, preparation := testServiceRunReadiness(t, handler)
				t.Cleanup(unblock)
				current := readiness.load()
				var resolved atomic.Pointer[targetplan.TargetSnapshot]
				resolved.Store(&current.target)
				readiness.binding.Resolve = func(context.Context) (targetplan.TargetSnapshot, error) { return *resolved.Load(), nil }
				if public {
					readiness.publicURL = service.Target
					if readiness.proof(current.run) == nil {
						t.Fatal("current run did not receive a proof")
					}
				}
				result := make(chan publisherapp.Observation, 1)
				var worker sync.WaitGroup
				worker.Go(func() { result <- readiness.check(ctx, service) })
				t.Cleanup(worker.Wait)
				select {
				case <-entered:
				case <-ctx.Done():
					t.Fatal("readiness request did not reach its target")
				}
				if replacement == "run" {
					preparation.RunNumber++
					preparation.ServiceRunId = "srun_2222222222222222222222"
					readiness.prepare(current.target, preparation)
				} else {
					target := current.target
					target.Identity = "replacement-at-the-same-address"
					resolved.Store(&target)
				}
				unblock()
				select {
				case observation := <-result:
					if observation.Ready || observation.Reason != "runtime.target_changed" {
						t.Fatalf("replacement accepted the old observation: %+v", observation)
					}
				case <-ctx.Done():
					t.Fatal("readiness check did not finish")
				}
			})
		}
	}
}

func TestServiceRunReadinessSerializesPublicProbes(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	entered, release := make(chan struct{}), make(chan struct{})
	unblock := sync.OnceFunc(func() { close(release) })
	var first sync.Once
	var readiness *serviceRunReadiness
	var mu sync.Mutex
	secrets := make(map[string]bool)
	handler := http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		first.Do(func() { close(entered) })
		select {
		case <-release:
		case <-request.Context().Done():
		}
		if readiness.probeMu.TryLock() {
			readiness.probeMu.Unlock()
			t.Error("public check did not hold probe serialization through the request")
		}
		secret := request.Header.Get(publisherapp.ProbeHeader)
		mu.Lock()
		if secret == "" || secrets[secret] {
			t.Error("public checks did not renew a distinct proof for each request")
		}
		secrets[secret] = true
		mu.Unlock()
		current := readiness.load()
		if !current.proof.Consume(request, current.run) || current.proof.Consume(request, current.run) {
			t.Error("concurrent probes replaced an outstanding proof or reused it")
		}
		w.WriteHeader(http.StatusNoContent)
	})
	readiness, service, _ := testServiceRunReadiness(t, handler)
	t.Cleanup(unblock)
	readiness.publicURL = service.Target
	if readiness.proof(readiness.load().run) == nil {
		t.Fatal("current run did not receive a proof")
	}
	const checks = 12
	start := make(chan struct{})
	results := make(chan publisherapp.Observation, checks)
	var workers sync.WaitGroup
	for range checks {
		workers.Go(func() {
			<-start
			results <- readiness.check(ctx, service)
		})
	}
	t.Cleanup(workers.Wait)
	close(start)
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal("public readiness request did not arrive")
	}
	unblock()
	for range checks {
		select {
		case observation := <-results:
			if !observation.Ready {
				t.Errorf("serialized owner probe was not ready: %+v", observation)
			}
		case <-ctx.Done():
			t.Fatal("concurrent readiness checks did not finish")
		}
	}
}

func testServiceRunReadiness(t *testing.T, handler http.Handler) (*serviceRunReadiness, publisherapp.Service, controlv1.ServiceRunPreparation) {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	binding := &targetplan.TargetBinding{Resolve: func(context.Context) (targetplan.TargetSnapshot, error) {
		return targetplan.TargetSnapshot{Address: server.URL, Identity: "original"}, nil
	}}
	captured, err := binding.Capture(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	service := publisherapp.Service{Name: "web", RegistrationID: "registration", Target: server.URL, RunNumber: 7,
		ServiceProtocol: "http", Readiness: publisherapp.Readiness{Path: "/health"}}
	preparation := controlv1.ServiceRunPreparation{ServiceId: "svc_1111111111111111111111", ServiceRunId: "srun_1111111111111111111111",
		RunNumber: int64(service.RunNumber), Hostname: "app.example"}
	readiness := &serviceRunReadiness{binding: binding, transport: targettransport.Transport{Protocol: config.ProtocolHTTP}, path: service.Readiness.Path}
	readiness.prepare(captured, preparation)
	return readiness, service, preparation
}

package invocation

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/config"
	publisherapp "github.com/tnldotdev/tnl/internal/publisher/app"
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
			if readiness.proof(original.run) != nil || readiness.load() != current {
				t.Fatal("an old proof callback modified the replacement run")
			}
			if next := readiness.proof(current.run); next == nil || next == proof || next.HeaderValue() == "" {
				t.Fatal("replacement run did not receive its own fresh proof")
			}
		})
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

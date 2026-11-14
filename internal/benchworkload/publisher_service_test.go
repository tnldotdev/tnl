package benchworkload

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	publisheridentity "github.com/tnldotdev/tnl/internal/publisher/identity"
	publisherservice "github.com/tnldotdev/tnl/internal/publisher/service"
	"github.com/tnldotdev/tnl/internal/transport/tunnel"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestBenchmarkDeclarationKeepsRequestLimitsSeparateFromTrafficAndTargetTLS(t *testing.T) {
	for _, target := range []string{"http://localhost:8080", "https://origin.example.test:8443"} {
		t.Run(target, func(t *testing.T) {
			config := PublisherConfig{Target: target, Concurrency: 7, RateRequests: 11, Ephemeral: true, AllowedIPPrefixes: []string{"192.0.2.4/32"}}
			declaration, address, trust, err := benchmarkDeclaration(config)
			if err != nil {
				t.Fatal(err)
			}
			if declaration.Traffic != nil || declaration.Hostname != nil || declaration.DomainId != nil || declaration.Name != nil ||
				declaration.Public == nil || !*declaration.Public || declaration.Ephemeral == nil || !*declaration.Ephemeral ||
				declaration.Protocol == nil || *declaration.Protocol != controlv1.ServiceProtocolHTTP || declaration.Target != address ||
				declaration.Http == nil || declaration.Http.Access == nil || *declaration.Http.Access.Mode != "anonymous" ||
				declaration.Http.Limits == nil || *declaration.Http.Limits.Concurrency != 7 || declaration.Http.Limits.Rate.Count != 11 ||
				declaration.Http.Limits.Rate.Per != "1s" || *declaration.Http.Limits.Rate.Burst != 11 {
				t.Fatal("benchmark conflated saved HTTP request policy with endpoint traffic")
			}
			(*declaration.Http.Access.Ip)[0] = "203.0.113.4/32"
			if config.AllowedIPPrefixes[0] != "192.0.2.4/32" {
				t.Fatal("declaration retained caller-owned IP policy")
			}
			if target == "http://localhost:8080" {
				if address != "127.0.0.1:8080" || trust != nil || declaration.TargetTls != nil {
					t.Fatal("plaintext target acquired TLS or lost its normalized address")
				}
			} else if address != "origin.example.test:8443" || trust == nil || !trust.System || trust.Hostname != "origin.example.test" ||
				trust.Validate() != nil || declaration.TargetTls == nil || declaration.TargetTls.Hostname != trust.Hostname || declaration.TargetTls.CaPem != nil {
				t.Fatal("HTTPS target did not retain separate verified system trust")
			}
		})
	}
	for _, config := range []PublisherConfig{
		{Target: "http://user:secret@origin.example.test:80"},
		{Target: "http://origin.example.test:80", Concurrency: -1},
		{Target: "http://origin.example.test:80", RateRequests: -1},
		{Target: "http://origin.example.test:80", AllowedIPPrefixes: []string{}},
	} {
		if _, _, _, err := benchmarkDeclaration(config); err == nil {
			t.Fatal("invalid benchmark declaration was accepted")
		}
	}
}

func TestBenchmarkServiceSelectionKeepsExactEndpointAndTrust(t *testing.T) {
	service := controlv1.Service{
		Id: "svc_0123456789ABCDEFGHIJKL", TeamId: "team", DomainId: new("dom_0123456789ABCDEFGHIJKL"),
		Enabled: true, Protocol: controlv1.ServiceProtocolHTTP, TrustRevision: 1,
		Endpoint: &controlv1.ServiceEndpoint{Hostname: "web.example.test", Port: 443, Public: true},
	}
	if err := validateBenchmarkService(service, "team", *service.DomainId, service.Endpoint.Hostname, false, nil); err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*controlv1.Service){
		"service":   func(s *controlv1.Service) { s.Id = "url_0123456789ABCDEFGHIJKL" },
		"team":      func(s *controlv1.Service) { s.TeamId = "other" },
		"domain":    func(s *controlv1.Service) { s.DomainId = new("dom_1123456789ABCDEFGHIJKL") },
		"disabled":  func(s *controlv1.Service) { s.Enabled = false },
		"ephemeral": func(s *controlv1.Service) { s.Ephemeral = true },
		"protocol":  func(s *controlv1.Service) { s.Protocol = controlv1.Tcp },
		"hostname":  func(s *controlv1.Service) { s.Endpoint.Hostname = "different.example.test" },
		"private":   func(s *controlv1.Service) { s.Endpoint.Public = false },
		"port":      func(s *controlv1.Service) { s.Endpoint.Port = 8443 },
		"trust":     func(s *controlv1.Service) { s.TrustRevision = 0 },
	} {
		t.Run(name, func(t *testing.T) {
			changed := service
			endpoint := *service.Endpoint
			changed.Endpoint = &endpoint
			change(&changed)
			if err := validateBenchmarkService(changed, "team", *service.DomainId, service.Endpoint.Hostname, false, nil); !errors.Is(err, publisheridentity.ErrScope) {
				t.Fatal("benchmark accepted another service identity or trust", err)
			}
		})
	}
	run := ServiceRun{ServiceID: service.Id, RunID: "srun_0123456789ABCDEFGHIJKL", Number: 1, Endpoint: *service.Endpoint}
	if !run.Valid() || run.URL() != "https://web.example.test" {
		t.Fatal("measurement lost the exact public service run")
	}
}

type benchmarkAllocationResult struct {
	service controlv1.Service
	err     error
}

type benchmarkAllocationFixture struct {
	results     []benchmarkAllocationResult
	requests    []controlv1.AllocateServiceRequest
	deleted     []string
	deleteErr   error
	checkAccess func(context.Context)
}

func (f *benchmarkAllocationFixture) AllocateService(ctx context.Context, request controlv1.AllocateServiceRequest) (controlv1.Service, error) {
	if f.checkAccess != nil {
		f.checkAccess(ctx)
	}
	result := f.results[len(f.requests)]
	f.requests = append(f.requests, request)
	return result.service, result.err
}

func (f *benchmarkAllocationFixture) DeleteAllocatedService(ctx context.Context, service string) error {
	if f.checkAccess != nil {
		f.checkAccess(ctx)
	}
	f.deleted = append(f.deleted, service)
	return f.deleteErr
}

func TestBenchmarkAllocationCleanupRecoversOnlyItsOriginalInvocation(t *testing.T) {
	lost, selection, recovery, deletion := errors.New("response lost"), errors.New("selection failed"), errors.New("recovery failed"), errors.New("deletion failed")
	service := controlv1.Service{Id: "svc_0123456789ABCDEFGHIJKL"}
	for _, test := range []struct {
		name       string
		results    []benchmarkAllocationResult
		deleteErr  error
		wantError  error
		wantDelete bool
	}{
		{"observed", []benchmarkAllocationResult{{service: service}}, nil, nil, true},
		{"observed-selection-failure", []benchmarkAllocationResult{{service: service, err: selection}}, deletion, deletion, true},
		{"lost-response", []benchmarkAllocationResult{{err: lost}, {service: service}}, nil, nil, true},
		{"lost-response-selection-failure", []benchmarkAllocationResult{{err: lost}, {service: service, err: selection}}, nil, selection, true},
		{"unrecoverable", []benchmarkAllocationResult{{err: lost}, {err: recovery}}, nil, recovery, false},
		{"invalid-recovery", []benchmarkAllocationResult{{err: lost}, {}}, nil, nil, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			request := controlv1.AllocateServiceRequest{InvocationId: "inv_0123456789ABCDEFGHIJKL",
				Configuration: controlv1.ProjectServiceConfiguration{Target: "127.0.0.1:8080", Ephemeral: new(true)}}
			fixture := &benchmarkAllocationFixture{results: test.results, deleteErr: test.deleteErr}
			_, cleanup, primary := allocateBenchmarkService(ctx, fixture, request)
			if !errors.Is(primary, test.results[0].err) || cleanup == nil {
				t.Fatal("allocation lost its primary error or cleanup owner", primary)
			}
			cancel()
			fixture.checkAccess = func(ctx context.Context) {
				if ctx.Err() != nil {
					t.Error("cleanup inherited the canceled publication context")
				}
			}
			cleanupCtx, stop := context.WithTimeout(context.Background(), 10*time.Second)
			defer stop()
			err := cleanup(cleanupCtx)
			if test.wantError != nil && !errors.Is(err, test.wantError) ||
				test.wantError == nil && test.wantDelete && err != nil ||
				!test.wantDelete && err == nil {
				t.Fatal("cleanup lost an independent failure or claimed unconfirmed deletion", err)
			}
			if len(fixture.requests) != len(test.results) || len(fixture.deleted) != map[bool]int{false: 0, true: 1}[test.wantDelete] {
				t.Fatal("cleanup allocated again or deleted without an observed service")
			}
			for _, actual := range fixture.requests {
				if !reflect.DeepEqual(actual, request) {
					t.Fatal("cleanup changed the invocation or declaration")
				}
			}
			if test.wantDelete && fixture.deleted[0] != service.Id {
				t.Fatal("cleanup deleted another service")
			}
		})
	}
}

type benchmarkSlotSession struct {
	transport tunnel.Transport
	closed    atomic.Int32
	closeErr  error
}

func (s *benchmarkSlotSession) Transport() tunnel.Transport   { return s.transport }
func (*benchmarkSlotSession) Serve(ctx context.Context) error { <-ctx.Done(); return ctx.Err() }
func (*benchmarkSlotSession) Drain(context.Context) error     { return nil }
func (s *benchmarkSlotSession) Close() error                  { s.closed.Add(1); return s.closeErr }

func TestBenchmarkTransportObservesActualSlotsAndOneFallbackPerRun(t *testing.T) {
	var mu sync.Mutex
	var observations []TransportObservation
	group := &Publishers{config: PublisherConfig{Transport: TransportAuto,
		ObserveTransport: func(index int, observation TransportObservation) error {
			if index != 9 {
				t.Error("transport observation changed publisher index")
			}
			mu.Lock()
			defer mu.Unlock()
			observations = append(observations, observation)
			return nil
		},
	}}
	ctx, stop := context.WithCancelCause(t.Context())
	defer stop(nil)
	connect := group.observeConnections(9, func(_ context.Context, _ *publisherservice.Bound, _ uint8, options publisherservice.ConnectOptions) (publisherservice.SlotSession, error) {
		if options.PreferTCP {
			t.Error("auto changed production transport preference")
		}
		return &benchmarkSlotSession{transport: tunnel.TransportTLSTCP}, nil
	}, stop)
	var workers sync.WaitGroup
	for slot := range uint8(2) {
		workers.Go(func() {
			session, err := connect(ctx, nil, slot, publisherservice.ConnectOptions{})
			if err != nil {
				t.Error(err)
				return
			}
			_ = session.Close()
		})
	}
	workers.Wait()
	// a replacement connection is observed, not another per-run fallback.
	session, err := connect(ctx, nil, 1, publisherservice.ConnectOptions{})
	if err != nil {
		t.Fatal(err)
	}
	_ = session.Close()
	var fallback, slotZero, slotOne int
	for _, observation := range observations {
		if observation.Transport != tunnel.TransportTLSTCP || observation.PreferredTCP {
			t.Fatal("observation did not come from the claimed session")
		}
		if observation.FirstFallback {
			fallback++
		}
		if observation.Slot == 0 {
			slotZero++
		} else if observation.Slot == 1 {
			slotOne++
		}
	}
	if len(observations) != 3 || fallback != 1 || slotZero != 1 || slotOne != 2 {
		t.Fatal("transport observation counts lost a slot or duplicated fallback", observations)
	}
}

func TestBenchmarkTransportCohortsKeepConfiguredPreferences(t *testing.T) {
	for _, test := range []struct {
		cohort TransportChoice
		index  int
		tcp    bool
	}{{TransportQUIC, 1, false}, {TransportTCP, 0, true}, {TransportMixed, 0, false}, {TransportMixed, 1, true}} {
		t.Run(string(test.cohort)+fmt.Sprint(test.index), func(t *testing.T) {
			count := 0
			group := &Publishers{config: PublisherConfig{Transport: test.cohort, ObserveTransport: func(_ int, observation TransportObservation) error {
				count++
				if observation.PreferredTCP != test.tcp || observation.FirstFallback {
					t.Error("an explicit cohort was counted as automatic fallback")
				}
				return nil
			}}}
			ctx, stop := context.WithCancelCause(t.Context())
			defer stop(nil)
			connect := group.observeConnections(test.index, func(_ context.Context, _ *publisherservice.Bound, _ uint8, options publisherservice.ConnectOptions) (publisherservice.SlotSession, error) {
				if options.PreferTCP != test.tcp {
					t.Error("cohort used a stale replacement transport preference")
				}
				transport := tunnel.TransportQUIC
				if test.tcp {
					transport = tunnel.TransportTLSTCP
				}
				return &benchmarkSlotSession{transport: transport}, nil
			}, stop)
			session, err := connect(ctx, nil, 0, publisherservice.ConnectOptions{PreferTCP: !test.tcp})
			if err != nil {
				t.Fatal(err)
			}
			_ = session.Close()
			if count != 1 {
				t.Fatal("successful claimed connection was not observed exactly once")
			}
		})
	}
}

func TestBenchmarkTransportObserverFailureClosesSessionAndPreservesCause(t *testing.T) {
	problem, closeProblem := errors.New("observation failed"), errors.New("close failed")
	session := &benchmarkSlotSession{transport: tunnel.TransportQUIC, closeErr: closeProblem}
	group := &Publishers{config: PublisherConfig{Transport: TransportAuto, ObserveTransport: func(int, TransportObservation) error { return problem }}}
	ctx, stop := context.WithCancelCause(t.Context())
	defer stop(nil)
	connect := group.observeConnections(0, func(context.Context, *publisherservice.Bound, uint8, publisherservice.ConnectOptions) (publisherservice.SlotSession, error) {
		return session, nil
	}, stop)
	got, err := connect(ctx, nil, 0, publisherservice.ConnectOptions{})
	if got != nil || !errors.Is(err, problem) || !errors.Is(err, closeProblem) ||
		!errors.Is(context.Cause(ctx), problem) || !errors.Is(context.Cause(ctx), closeProblem) || session.closed.Load() != 1 {
		t.Fatal("observer failure lost owned cleanup or its independent cause", err)
	}
}

func TestBenchmarkFailedConnectionsDoNotBecomeTransportObservations(t *testing.T) {
	problem, closeProblem := errors.New("claim failed"), errors.New("close failed")
	for _, test := range []struct {
		name    string
		session *benchmarkSlotSession
		err     error
		reports int
	}{
		{"missing-session", nil, nil, 1},
		{"claim-failed", nil, problem, 1},
		{"claim-canceled", nil, context.Canceled, 0},
		{"session-returned-with-failure", &benchmarkSlotSession{}, problem, 1},
		{"session-cleanup-failed", &benchmarkSlotSession{closeErr: closeProblem}, problem, 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			observed, reports := 0, 0
			group := &Publishers{config: PublisherConfig{Transport: TransportAuto,
				ObserveTransport: func(int, TransportObservation) error { observed++; return nil },
				Report:           func(int, error) { reports++ },
			}}
			ctx, stop := context.WithCancelCause(t.Context())
			defer stop(nil)
			connect := group.observeConnections(0, func(context.Context, *publisherservice.Bound, uint8, publisherservice.ConnectOptions) (publisherservice.SlotSession, error) {
				if test.session == nil {
					return nil, test.err
				}
				return test.session, test.err
			}, stop)
			session, err := connect(ctx, nil, 0, publisherservice.ConnectOptions{})
			if session != nil || err == nil || observed != 0 || reports != test.reports ||
				test.err != nil && !errors.Is(err, test.err) {
				t.Fatal("failed claim became a measured connection or lost its diagnostic", err)
			}
			if test.session != nil && test.session.closed.Load() != 1 {
				t.Fatal("failed connection retained its returned session")
			}
			if test.session != nil && test.session.closeErr != nil {
				if !errors.Is(err, closeProblem) || !errors.Is(context.Cause(ctx), closeProblem) {
					t.Fatal("connection retry hid an independent session cleanup failure", err)
				}
			} else if context.Cause(ctx) != nil {
				t.Fatal("ordinary connection failure changed the run's retry policy")
			}
		})
	}
}

func TestPublisherActivationIncludesPreparationAndRecordsReadyOnce(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		group := &Publishers{ctx: ctx, cancel: cancel, failures: make(chan error, 1),
			config: PublisherConfig{Parallel: 1, ReadyTimeout: 10 * time.Second, StopTimeout: time.Second}}
		group.prepare = func(ctx context.Context, index int, cfg publisherservice.RunConfig) (publisherservice.RunConfig, func(context.Context) error, error) {
			time.Sleep(2 * time.Second)
			return benchmarkTestPreparation(ctx, index, cfg)
		}
		group.run = func(ctx context.Context, cfg publisherservice.RunConfig) error {
			time.Sleep(3 * time.Second)
			if err := benchmarkTestReady(cfg); err != nil {
				return err
			}
			if err := cfg.Ready(); err != nil {
				return err
			}
			<-ctx.Done()
			return ctx.Err()
		}
		ready, err := group.Start(t.Context(), []int{4})
		if err != nil || len(ready) != 1 || ready[0].Index != 4 || !ready[0].Run.Valid() ||
			ready[0].Run.Endpoint.Hostname != "p4.example.test" || ready[0].Activation != 5*time.Second {
			t.Fatal("activation excluded preparation or duplicated readiness", ready, err)
		}
		if _, err := group.Stop(t.Context(), []int{4}); err != nil {
			t.Fatal(err)
		}
	})
}

func TestPublisherCleanupJoinsAndKeepsIndependentFailures(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		runProblem, cleanupProblem := errors.New("run cleanup failed"), errors.New("allocation delete failed")
		var cleaned bool
		group := &Publishers{ctx: ctx, cancel: cancel, failures: make(chan error, 1),
			config: PublisherConfig{Parallel: 1, ReadyTimeout: 10 * time.Second, StopTimeout: 5 * time.Second}}
		group.prepare = func(ctx context.Context, index int, cfg publisherservice.RunConfig) (publisherservice.RunConfig, func(context.Context) error, error) {
			cfg, _, err := benchmarkTestPreparation(ctx, index, cfg)
			return cfg, func(cleanup context.Context) error {
				if cleanup.Err() != nil {
					t.Error("caller cancellation abandoned allocation cleanup")
				}
				if deadline, ok := cleanup.Deadline(); !ok || deadline.After(time.Now().Add(10*time.Second)) {
					t.Error("allocation cleanup lost its fixed deadline")
				}
				time.Sleep(3 * time.Second)
				cleaned = true
				return cleanupProblem
			}, err
		}
		group.run = func(ctx context.Context, cfg publisherservice.RunConfig) error {
			if err := benchmarkTestReady(cfg); err != nil {
				return err
			}
			<-ctx.Done()
			return errors.Join(ctx.Err(), runProblem)
		}
		if _, err := group.Start(t.Context(), []int{0}); err != nil {
			t.Fatal(err)
		}
		start := time.Now()
		result, err := group.Stop(t.Context(), []int{0})
		if !cleaned || !errors.Is(err, runProblem) || !errors.Is(err, cleanupProblem) ||
			result.Attempts != 1 || result.Failures != 1 || result.Successes != 0 || time.Since(start) != 3*time.Second {
			t.Fatal("shutdown did not join cleanup or preserve independent failures", result, err)
		}
	})
}

func TestPublisherCloseDoesNotCloseStateUnderUnjoinedWorker(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		database, err := clientstate.Open(t.Context(), filepath.Join(t.TempDir(), "state"))
		if err != nil {
			t.Fatal(err)
		}
		defer database.Close()
		store, err := database.Server(t.Context(), "https://control.example.test")
		if err != nil {
			t.Fatal(err)
		}
		done := make(chan struct{})
		group := &Publishers{ctx: ctx, cancel: cancel, database: database,
			config:    PublisherConfig{Parallel: 1, StopTimeout: time.Second},
			processes: []*serviceProcess{{index: 0, cancel: func() {}, done: done}}}
		if _, err := group.Close(t.Context()); !errors.Is(err, context.DeadlineExceeded) {
			t.Fatal("unjoined publisher did not exhaust its stop budget", err)
		}
		if _, _, err := store.ControlSession(t.Context()); err != nil {
			t.Fatal("state was closed under the unjoined publisher", err)
		}
		close(done)
		if _, err := group.Close(t.Context()); err != nil {
			t.Fatal(err)
		}
		if _, _, err := store.ControlSession(t.Context()); err == nil {
			t.Fatal("joined publisher retained the state database")
		}
	})
}

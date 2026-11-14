package app

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/tnldotdev/tnl/internal/observability/inspection"
	"github.com/tnldotdev/tnl/internal/policy/visitorscope"
	"github.com/tnldotdev/tnl/internal/publisher"
	"github.com/tnldotdev/tnl/internal/publisher/httpaccess"
	"github.com/tnldotdev/tnl/internal/publisher/target"
)

const automaticTestDelay = 10 * time.Millisecond

func automaticWorkers(t *testing.T, budget time.Duration) (*Workers, <-chan func(uint64, bool) error, <-chan struct{}) {
	t.Helper()
	w, _ := testWorkers(t)
	w.AutomaticReadiness = true
	w.readinessBudget = budget
	w.readinessDelay = func(int) time.Duration { return automaticTestDelay }
	ready := make(chan func(uint64, bool) error, 8)
	exited := make(chan struct{}, 8)
	w.Configure = func(_ context.Context, service Service) (Configuration, error) {
		return Configuration{Service: &ServicePublication{
			Options: servicePublicationOptions(w, service), URL: "https://public.example",
			Run: func(ctx context.Context, observe func(uint64, bool) error, _ inspection.Observer) error {
				defer func() { exited <- struct{}{} }()
				if err := observe(1, false); err != nil {
					return err
				}
				if err := observe(1, true); err != nil {
					return err
				}
				ready <- observe
				<-ctx.Done()
				return ctx.Err()
			},
			Check: func(ctx context.Context, current Service) Observation {
				proof, err := httpaccess.NewReadinessProof(httpaccess.ReadinessRun{
					Subject: visitorscope.Scope{Kind: visitorscope.Service, ID: "svc_1111111111111111111111"},
					ID:      "run_" + strconv.FormatUint(current.RunNumber, 10), Number: current.RunNumber, Hostname: "public.example",
				}, current.Readiness.Path)
				if err != nil {
					t.Error(err)
					return Observation{}
				}
				return ProbeWithProof(ctx, current, w.HTTPTransport, proof.HeaderValue())
			},
		}}, nil
	}
	return w, ready, exited
}

func registerAutomaticService(t *testing.T, w *Workers, ready <-chan func(uint64, bool) error) (func(uint64, bool) error, string) {
	t.Helper()
	id := registerServicePublication(t, w, "http://127.0.0.1:3000", "https://public.example")
	return receiveServicePublication(t, ready), id
}

func registerAutomaticWorker(t *testing.T, w *Workers, ready <-chan publisher.Config) (publisher.Config, string) {
	t.Helper()
	id, err := w.Manager.Reserve("web", "owner", 1, "https://public.example")
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Manager.Register(id, "owner", "http://127.0.0.1:3000", "node"); err != nil {
		t.Fatal(err)
	}
	return receiveConfig(t, ready), id
}

func automaticResponse(status int) *http.Response {
	return &http.Response{StatusCode: status, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(""))}
}

func waitAutomaticReady(t *testing.T, w *Workers, run uint64) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		service := w.Manager.Snapshot().Services[0]
		if service.Ready && service.RunNumber == run {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("run %d never became ready: %+v", run, service)
		}
		time.Sleep(time.Millisecond)
	}
}

func expectAutomaticGET(t *testing.T, gets <-chan string) string {
	t.Helper()
	select {
	case proof := <-gets:
		if len(proof) != 64 {
			t.Fatal("automatic GET omitted the run proof")
		}
		return proof
	case <-time.After(2 * time.Second):
		t.Fatal("automatic GET did not start")
		return ""
	}
}

func expectNoAutomaticGET(t *testing.T, gets <-chan string) {
	t.Helper()
	select {
	case <-gets:
		t.Fatal("automatic readiness issued another GET after completion")
	case <-time.After(8 * automaticTestDelay):
	}
}

func TestAutomaticReadinessStopsAfterSuccessAndOnlyRearmsForNewRun(t *testing.T) {
	w, ready, _ := automaticWorkers(t, time.Second)
	gets := make(chan string, 32)
	w.HTTPTransport = trip(func(r *http.Request) (*http.Response, error) {
		gets <- r.Header.Get(ProbeHeader)
		return automaticResponse(200), nil
	})
	observe, _ := registerAutomaticService(t, w, ready)
	first := expectAutomaticGET(t, gets)
	waitAutomaticReady(t, w, 1)
	if err := observe(1, true); err != nil {
		t.Fatal(err)
	}
	expectNoAutomaticGET(t, gets)
	if err := observe(1, false); err != nil {
		t.Fatal(err)
	}
	if err := observe(1, true); err != nil {
		t.Fatal(err)
	}
	expectNoAutomaticGET(t, gets)
	if service := w.Manager.Snapshot().Services[0]; service.Ready || !service.Routable {
		t.Fatal("same-run recovery invented a fresh readiness check", service)
	}
	if snapshot, err := w.Check(t.Context(), []string{"web"}); err != nil || !snapshot.Services[0].Ready {
		t.Fatalf("manual check could not verify the recovered run: %+v %v", snapshot.Services, err)
	}
	expectAutomaticGET(t, gets)
	expectNoAutomaticGET(t, gets)
	if err := observe(2, false); err != nil {
		t.Fatal(err)
	}
	if err := observe(2, true); err != nil {
		t.Fatal(err)
	}
	second := expectAutomaticGET(t, gets)
	if first == second {
		t.Fatal("replacement run reused a readiness proof")
	}
	waitAutomaticReady(t, w, 2)
	expectNoAutomaticGET(t, gets)
}

func TestAutomaticReadinessDisabledKeepsManualCheck(t *testing.T) {
	w, ready, _ := automaticWorkers(t, time.Second)
	w.AutomaticReadiness = false
	gets := make(chan string, 8)
	w.HTTPTransport = trip(func(r *http.Request) (*http.Response, error) {
		gets <- r.Header.Get(ProbeHeader)
		return automaticResponse(http.StatusNoContent), nil
	})
	registerAutomaticService(t, w, ready)
	expectNoAutomaticGET(t, gets)
	if service := w.Manager.Snapshot().Services[0]; service.Ready || !service.Routable {
		t.Fatal("disabled automatic readiness changed publication", service)
	}
	if snapshot, err := w.Check(t.Context(), []string{"web"}); err != nil || !snapshot.Services[0].Ready {
		t.Fatalf("manual check was disabled with automatic readiness: %+v %v", snapshot.Services, err)
	}
	expectAutomaticGET(t, gets)
	expectNoAutomaticGET(t, gets)
}

func TestAutomaticReadinessWaitsForCompletedPublicationObservation(t *testing.T) {
	w, ready, _ := automaticWorkers(t, time.Second)
	observed, release := make(chan struct{}), make(chan struct{})
	unblock := sync.OnceFunc(func() { close(release) })
	defer unblock()
	w.Manager.run = func(ctx context.Context, service Service, observe func(PublicationUpdate) error) error {
		return w.Run(ctx, service, func(update PublicationUpdate) error {
			err := observe(update)
			if update.Routable {
				close(observed)
				<-release
			}
			return err
		})
	}
	gets := make(chan string, 8)
	w.HTTPTransport = trip(func(r *http.Request) (*http.Response, error) {
		gets <- r.Header.Get(ProbeHeader)
		return automaticResponse(http.StatusNoContent), nil
	})
	target := "http://127.0.0.1:3000"
	registerServicePublication(t, w, target, "")
	receiveServicePublication(t, observed)
	snapshot := assertServicePublication(t, w, "http", target, "ready", 1, "https://public.example")
	if !snapshot.Services[0].Routable || snapshot.Services[0].Ready {
		t.Fatal("publication invented a check before observation completed", snapshot)
	}
	expectNoAutomaticGET(t, gets)
	unblock()
	receiveServicePublication(t, ready)
	expectAutomaticGET(t, gets)
	waitAutomaticReady(t, w, 1)
}

func TestAutomaticReadinessBudgetCancelsProbeWithoutStoppingPublication(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const budget = 250 * time.Millisecond
		w, ready, exited := automaticWorkers(t, budget)
		var gets atomic.Int32
		deadlineReached := make(chan struct{})
		var deadlineOnce sync.Once
		retries := make(chan int, 8)
		w.readinessDelay = func(attempt int) time.Duration { retries <- attempt; return automaticTestDelay }
		w.HTTPTransport = trip(func(r *http.Request) (*http.Response, error) {
			if gets.Add(1) <= 2 {
				return automaticResponse(503), nil
			}
			<-r.Context().Done()
			deadlineOnce.Do(func() { close(deadlineReached) })
			return nil, r.Context().Err()
		})
		started := time.Now()
		observe, id := registerAutomaticService(t, w, ready)
		select {
		case <-deadlineReached:
		case <-time.After(2 * time.Second):
			t.Fatal("automatic readiness did not enforce its overall budget")
		}
		if elapsed := time.Since(started); elapsed != budget {
			t.Fatalf("automatic readiness canceled after %s, want %s", elapsed, budget)
		}
		synctest.Wait()
		count := gets.Load()
		if count != 3 {
			t.Fatalf("automatic readiness issued %d GETs, want two failures and one canceled probe", count)
		}
		for _, want := range []int{0, 1} {
			select {
			case got := <-retries:
				if got != want {
					t.Fatalf("retry attempt = %d, want %d", got, want)
				}
			default:
				t.Fatal("failed probe did not retry")
			}
		}
		if err := observe(1, true); err != nil {
			t.Fatal(err)
		}
		time.Sleep(8 * automaticTestDelay)
		if gets.Load() != count {
			t.Fatal("automatic readiness retried after exhausting its budget")
		}
		select {
		case <-retries:
			t.Fatal("automatic readiness scheduled another retry after its budget")
		default:
		}
		service := w.Manager.Snapshot().Services[0]
		if !service.Registered || !service.Routable || service.Ready || !w.Manager.CurrentRun("web", id, service.Target, 1) {
			t.Fatalf("readiness budget changed publication lifetime: %+v", service)
		}
		select {
		case <-exited:
			t.Fatal("readiness failure stopped the publisher")
		default:
		}
	})
}

func TestAutomaticReadinessBudgetExpiresBeforeNextProbe(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const budget = 250 * time.Millisecond
		w, ready, exited := automaticWorkers(t, budget)
		var gets atomic.Int32
		retries := make(chan int, 8)
		w.readinessDelay = func(attempt int) time.Duration {
			retries <- attempt
			return 2 * budget
		}
		w.HTTPTransport = trip(func(*http.Request) (*http.Response, error) {
			gets.Add(1)
			return automaticResponse(503), nil
		})
		observe, id := registerAutomaticService(t, w, ready)
		synctest.Wait()
		if gets.Load() != 1 {
			t.Fatalf("initial GETs = %d, want 1", gets.Load())
		}
		select {
		case attempt := <-retries:
			if attempt != 0 {
				t.Fatalf("retry attempt = %d, want 0", attempt)
			}
		default:
			t.Fatal("failed probe did not schedule a retry")
		}
		// let both the budget and the retry delay pass. expiry must prevent the
		// next GET without requiring another probe to observe cancellation.
		time.Sleep(3 * budget)
		synctest.Wait()
		if err := observe(1, true); err != nil {
			t.Fatal(err)
		}
		time.Sleep(3 * budget)
		synctest.Wait()
		if gets.Load() != 1 {
			t.Fatalf("GETs after budget expiry = %d, want 1", gets.Load())
		}
		select {
		case <-retries:
			t.Fatal("automatic readiness scheduled another retry after its budget")
		default:
		}
		service := w.Manager.Snapshot().Services[0]
		if !service.Registered || !service.Routable || service.Ready || !w.Manager.CurrentRun("web", id, service.Target, 1) {
			t.Fatalf("readiness budget changed publication lifetime: %+v", service)
		}
		select {
		case <-exited:
			t.Fatal("readiness failure stopped the publisher")
		default:
		}
	})
}

func TestAutomaticReadinessReplacementJoinsOldRunBeforeCheckingNewRun(t *testing.T) {
	for _, preparation := range []bool{false, true} {
		name := "direct"
		if preparation {
			name = "prepared"
		}
		t.Run(name, func(t *testing.T) {
			w, ready, _ := automaticWorkers(t, time.Second)
			started, canceled, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
			var once sync.Once
			unblock := func() { once.Do(func() { close(release) }) }
			defer unblock()
			var count atomic.Int32
			gets := make(chan string, 8)
			w.HTTPTransport = trip(func(r *http.Request) (*http.Response, error) {
				gets <- r.Header.Get(ProbeHeader)
				if count.Add(1) == 1 {
					close(started)
					<-r.Context().Done()
					close(canceled)
					<-release
					return nil, r.Context().Err()
				}
				return automaticResponse(200), nil
			})
			observe, _ := registerAutomaticService(t, w, ready)
			select {
			case <-started:
			case <-time.After(2 * time.Second):
				t.Fatal("first run did not start its readiness probe")
			}
			first := expectAutomaticGET(t, gets)
			done := make(chan error, 1)
			go func() {
				if preparation {
					if err := observe(2, false); err != nil {
						done <- err
						return
					}
				}
				done <- observe(2, true)
			}()
			select {
			case <-canceled:
			case err := <-done:
				t.Fatalf("replacement run did not cancel and join its predecessor's check: %v", err)
			case <-time.After(500 * time.Millisecond):
				t.Fatal("replacement run did not cancel its predecessor's check")
			}
			select {
			case err := <-done:
				t.Fatalf("replacement run did not join the old probe: %v", err)
			default:
			}
			if snapshot := w.Manager.Snapshot(); snapshot.Services[0].RunNumber != 1 || !snapshot.Services[0].Routable ||
				len(snapshot.Publications) != 1 || snapshot.Publications[0].PublishRunNumber != 1 {
				t.Fatal("replacement changed the journal before joining the old probe", snapshot)
			}
			unblock()
			select {
			case err := <-done:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("replacement run did not join")
			}
			second := expectAutomaticGET(t, gets)
			if first == second {
				t.Fatal("replacement run reused the old proof")
			}
			waitAutomaticReady(t, w, 2)
			expectNoAutomaticGET(t, gets)
		})
	}
}

func TestAutomaticReadinessStaleRunDoesNotCancelCurrentCheck(t *testing.T) {
	w, ready, _ := automaticWorkers(t, time.Second)
	gets := make(chan string, 8)
	canceled, release := make(chan struct{}), make(chan struct{})
	unblock := sync.OnceFunc(func() { close(release) })
	defer unblock()
	var count atomic.Int32
	w.HTTPTransport = trip(func(r *http.Request) (*http.Response, error) {
		gets <- r.Header.Get(ProbeHeader)
		if count.Add(1) == 1 {
			return automaticResponse(http.StatusNoContent), nil
		}
		<-r.Context().Done()
		close(canceled)
		<-release
		return nil, r.Context().Err()
	})
	observe, _ := registerAutomaticService(t, w, ready)
	expectAutomaticGET(t, gets)
	waitAutomaticReady(t, w, 1)
	if err := observe(2, true); err != nil {
		t.Fatal(err)
	}
	expectAutomaticGET(t, gets)
	before := w.Manager.Snapshot()
	for _, routable := range []bool{false, true} {
		done := make(chan error, 1)
		go func() { done <- observe(1, routable) }()
		if err := receiveServicePublication(t, done); !errors.Is(err, ErrRegistrationStale) {
			t.Fatal("old run observation was accepted", err)
		}
		select {
		case <-canceled:
			t.Fatal("old run observation canceled the current check")
		default:
		}
	}
	if after := w.Manager.Snapshot(); before.Cursor != after.Cursor || !reflect.DeepEqual(before.Services, after.Services) {
		t.Fatal("old run observation changed publication or readiness", after)
	}
}

func TestAutomaticReadinessOperationReturnJoinsBeforeCleanup(t *testing.T) {
	w, _, _ := automaticWorkers(t, time.Second)
	started, canceled, release, joined := make(chan struct{}), make(chan struct{}), make(chan struct{}), make(chan struct{})
	finishOperation, cleaned := make(chan struct{}), make(chan struct{})
	unblock := sync.OnceFunc(func() { close(release) })
	defer unblock()
	operationFailure, cleanupFailure := errors.New("operation failed"), errors.New("cleanup failed")
	configure := w.Configure
	w.Configure = func(ctx context.Context, service Service) (Configuration, error) {
		cfg, err := configure(ctx, service)
		if err != nil {
			return cfg, err
		}
		cfg.Service.Run = func(ctx context.Context, observe func(uint64, bool) error, _ inspection.Observer) error {
			if err := observe(1, true); err != nil {
				return err
			}
			select {
			case <-finishOperation:
				if ctx.Err() != nil {
					t.Error("operation return required parent cancellation")
				}
			case <-ctx.Done():
			}
			return errors.Join(context.Canceled, operationFailure)
		}
		cfg.Service.Check = func(ctx context.Context, _ Service) Observation {
			close(started)
			<-ctx.Done()
			close(canceled)
			<-release
			close(joined)
			return Observation{}
		}
		cfg.Cleanup = func() error {
			select {
			case <-joined:
			default:
				t.Error("configuration cleanup preceded the automatic check join")
			}
			close(cleaned)
			return errors.Join(context.Canceled, cleanupFailure)
		}
		return cfg, nil
	}
	target := "http://127.0.0.1:3000"
	id := registerServicePublication(t, w, target, "")
	receiveServicePublication(t, started)
	close(finishOperation)
	receiveServicePublication(t, canceled)
	select {
	case <-cleaned:
		t.Fatal("operation return did not join its automatic check before cleanup")
	default:
	}
	if snapshot := w.Manager.Snapshot(); len(snapshot.Publications) != 1 || snapshot.Services[0].TunnelID == "" {
		t.Fatal("operation return finished the journal before joining its check", snapshot)
	}
	unblock()
	receiveServicePublication(t, cleaned)
	err := w.Manager.UnregisterTarget(id, "owner", target)
	for _, cause := range []error{operationFailure, cleanupFailure, ErrRegistrationStopped} {
		if !errors.Is(err, cause) {
			t.Fatalf("automatic readiness cleanup lost %v: %v", cause, err)
		}
	}
	assertNoServicePublications(t, w)
}

func TestAutomaticReadinessCancellationIsJoined(t *testing.T) {
	for _, action := range []string{"unavailable", "shutdown"} {
		t.Run(action, func(t *testing.T) {
			w, ready, _ := automaticWorkers(t, time.Second)
			started, canceled, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
			var once sync.Once
			unblock := func() { once.Do(func() { close(release) }) }
			defer unblock()
			w.HTTPTransport = trip(func(r *http.Request) (*http.Response, error) {
				close(started)
				<-r.Context().Done()
				close(canceled)
				<-release
				return nil, r.Context().Err()
			})
			observe, id := registerAutomaticService(t, w, ready)
			select {
			case <-started:
			case <-time.After(2 * time.Second):
				t.Fatal("readiness probe did not start")
			}
			done := make(chan error, 1)
			go func() {
				if action == "unavailable" {
					done <- observe(1, false)
					return
				}
				done <- w.Manager.UnregisterTarget(id, "owner", "http://127.0.0.1:3000")
			}()
			select {
			case <-canceled:
			case err := <-done:
				t.Fatalf("%s returned without canceling and joining the readiness probe: %v", action, err)
			case <-time.After(500 * time.Millisecond):
				t.Fatalf("%s did not cancel its readiness probe", action)
			}
			select {
			case err := <-done:
				t.Fatalf("%s returned before the probe joined: %v", action, err)
			default:
			}
			unblock()
			select {
			case err := <-done:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(2 * time.Second):
				t.Fatalf("%s did not join its readiness probe", action)
			}
		})
	}
}

func TestAutomaticReadinessTargetChangeNeedsExplicitCheckAfterSuccess(t *testing.T) {
	w, ready := testWorkers(t)
	w.AutomaticReadiness = true
	w.readinessBudget = time.Second
	w.readinessDelay = func(int) time.Duration { return automaticTestDelay }
	var identity atomic.Value
	identity.Store("container-a")
	configure := w.Configure
	w.Configure = func(ctx context.Context, service Service) (Configuration, error) {
		cfg, err := configure(ctx, service)
		cfg.TargetBinding = &target.TargetBinding{Resolve: func(context.Context) (target.TargetSnapshot, error) {
			return target.TargetSnapshot{Address: service.Target, Identity: identity.Load().(string)}, nil
		}}
		return cfg, err
	}
	gets := make(chan string, 32)
	w.HTTPTransport = trip(func(r *http.Request) (*http.Response, error) {
		gets <- r.Header.Get(ProbeHeader)
		return automaticResponse(200), nil
	})
	cfg, _ := registerAutomaticWorker(t, w, ready)
	expectAutomaticGET(t, gets)
	waitAutomaticReady(t, w, 1)
	identity.Store("container-b")
	if err := cfg.AdmitRequest(httptest.NewRequest("GET", "https://public.example/", nil), publisher.PublishRunIdentity{Number: 1}); err != nil {
		t.Fatal(err)
	}
	if service := w.Manager.Snapshot().Services[0]; service.Ready || service.Observation == nil || service.Observation.Reason != "runtime.target_changed" {
		t.Fatalf("changed target retained readiness: %+v", service)
	}
	expectNoAutomaticGET(t, gets)
	if snapshot, err := w.Check(t.Context(), []string{"web"}); err != nil || !snapshot.Services[0].Ready {
		t.Fatalf("explicit check could not verify the changed target: %+v %v", snapshot.Services, err)
	}
	expectAutomaticGET(t, gets)
	expectNoAutomaticGET(t, gets)
}

func TestAutomaticReadinessAcceptedSuccessStopsAfterImmediateInvalidation(t *testing.T) {
	w, ready, _ := automaticWorkers(t, time.Second)
	gets := make(chan string, 8)
	w.HTTPTransport = trip(func(r *http.Request) (*http.Response, error) {
		gets <- r.Header.Get(ProbeHeader)
		return automaticResponse(200), nil
	})
	accepted := make(chan bool, 1)
	w.acceptReadiness = func(observation Observation) bool {
		ok := w.Manager.Observe(observation)
		w.Manager.TargetChanged("web", observation.RegistrationID, observation.Target)
		accepted <- ok && observation.Ready
		return ok
	}
	observe, _ := registerAutomaticService(t, w, ready)
	expectAutomaticGET(t, gets)
	if !<-accepted {
		t.Fatal("probe success was not accepted before invalidation")
	}
	if service := w.Manager.Snapshot().Services[0]; service.Ready || service.Observation == nil || service.Observation.Reason != "runtime.target_changed" {
		t.Fatalf("target invalidation was lost: %+v", service)
	}
	if err := observe(1, true); err != nil {
		t.Fatal(err)
	}
	expectNoAutomaticGET(t, gets)
}

func TestAutomaticReadinessReplacementBeforeAcceptanceRejectsOldSuccess(t *testing.T) {
	w, ready, _ := automaticWorkers(t, time.Second)
	gets := make(chan string, 8)
	w.HTTPTransport = trip(func(r *http.Request) (*http.Response, error) {
		gets <- r.Header.Get(ProbeHeader)
		return automaticResponse(200), nil
	})
	accepted := make(chan bool, 1)
	w.acceptReadiness = func(observation Observation) bool {
		service, current := w.Manager.ServiceForRun("web", observation.RegistrationID, observation.Target, observation.RunNumber)
		if !current {
			t.Error("probe lost its current registration before replacement")
			return false
		}
		if err := w.Manager.Published(observation.RegistrationID, PublicationUpdate{RunNumber: 2, Routable: true, Target: service.Target, TunnelID: service.TunnelID, PublicURL: service.PublicURL}); err != nil {
			t.Error(err)
		}
		ok := w.Manager.Observe(observation)
		accepted <- ok
		return ok
	}
	registerAutomaticService(t, w, ready)
	expectAutomaticGET(t, gets)
	if <-accepted {
		t.Fatal("old probe success crossed publish run replacement")
	}
	expectNoAutomaticGET(t, gets)
	if service := w.Manager.Snapshot().Services[0]; service.RunNumber != 2 || service.Ready || !service.Routable {
		t.Fatalf("old result changed the replacement's readiness: %+v", service)
	}
}

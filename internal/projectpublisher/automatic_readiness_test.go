package projectpublisher

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/clientruntime"
	"github.com/tnldotdev/tnl/internal/publisher"
)

const automaticTestDelay = 10 * time.Millisecond

func automaticWorkers(t *testing.T, budget time.Duration) (*Workers, <-chan publisher.Config, <-chan struct{}) {
	t.Helper()
	w, ready := testWorkers(t)
	w.AutomaticReadiness = true
	w.readinessBudget = budget
	w.readinessDelay = func(int) time.Duration { return automaticTestDelay }
	previous := w.RunPublisher
	exited := make(chan struct{})
	w.RunPublisher = func(ctx context.Context, cfg publisher.Config) error {
		defer close(exited)
		return previous(ctx, cfg)
	}
	return w, ready, exited
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
		if service.Ready && service.PublishRunNumber == run {
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
		gets <- r.Header.Get(clientruntime.ProbeHeader)
		return automaticResponse(200), nil
	})
	cfg, _ := registerAutomaticWorker(t, w, ready)
	first := expectAutomaticGET(t, gets)
	waitAutomaticReady(t, w, 1)
	if err := cfg.Observe(publisher.Event{Type: publisher.EventReady, PublishRunNumber: 1, PublicURL: "https://public.example"}); err != nil {
		t.Fatal(err)
	}
	expectNoAutomaticGET(t, gets)
	if err := cfg.Observe(publisher.Event{Type: publisher.EventProvisioning, PublishRunNumber: 2}); err != nil {
		t.Fatal(err)
	}
	if cfg.ReadinessProof(publisher.PublishRunIdentity{Hostname: "public.example", PublicURLID: "url_0123456789abcdefghijkl", Number: 2}) == nil {
		t.Fatal("replacement run omitted its proof")
	}
	if err := cfg.Observe(publisher.Event{Type: publisher.EventReady, PublishRunNumber: 2, PublicURL: "https://public.example"}); err != nil {
		t.Fatal(err)
	}
	second := expectAutomaticGET(t, gets)
	if first == second {
		t.Fatal("replacement run reused a readiness proof")
	}
	waitAutomaticReady(t, w, 2)
	expectNoAutomaticGET(t, gets)
}

func TestAutomaticReadinessBudgetCancelsProbeWithoutStoppingPublication(t *testing.T) {
	w, ready, exited := automaticWorkers(t, 250*time.Millisecond)
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
	cfg, id := registerAutomaticWorker(t, w, ready)
	select {
	case <-deadlineReached:
	case <-time.After(2 * time.Second):
		t.Fatal("automatic readiness did not enforce its overall budget")
	}
	count := gets.Load()
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
	if err := cfg.Observe(publisher.Event{Type: publisher.EventReady, PublishRunNumber: 1, PublicURL: "https://public.example"}); err != nil {
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
	if !service.Registered || !service.Routable || service.Ready || !w.Manager.Current("web", id, service.Target, 1) {
		t.Fatalf("readiness budget changed publication lifetime: %+v", service)
	}
	select {
	case <-exited:
		t.Fatal("readiness failure stopped the publisher")
	default:
	}
}

func TestAutomaticReadinessReplacementJoinsOldRunBeforeCheckingNewRun(t *testing.T) {
	w, ready, _ := automaticWorkers(t, time.Second)
	started, canceled, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	defer unblock()
	var count atomic.Int32
	gets := make(chan string, 8)
	w.HTTPTransport = trip(func(r *http.Request) (*http.Response, error) {
		gets <- r.Header.Get(clientruntime.ProbeHeader)
		if count.Add(1) == 1 {
			close(started)
			<-r.Context().Done()
			close(canceled)
			<-release
			return nil, r.Context().Err()
		}
		return automaticResponse(200), nil
	})
	cfg, _ := registerAutomaticWorker(t, w, ready)
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("first run did not start its readiness probe")
	}
	first := expectAutomaticGET(t, gets)
	done := make(chan error, 1)
	go func() {
		if err := cfg.Observe(publisher.Event{Type: publisher.EventProvisioning, PublishRunNumber: 2}); err != nil {
			done <- err
			return
		}
		if cfg.ReadinessProof(publisher.PublishRunIdentity{Hostname: "public.example", PublicURLID: "url_0123456789abcdefghijkl", Number: 2}) == nil {
			done <- io.ErrUnexpectedEOF
			return
		}
		done <- cfg.Observe(publisher.Event{Type: publisher.EventReady, PublishRunNumber: 2, PublicURL: "https://public.example"})
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
}

func TestAutomaticReadinessCancellationIsJoined(t *testing.T) {
	for _, action := range []string{"drain", "shutdown"} {
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
			cfg, id := registerAutomaticWorker(t, w, ready)
			select {
			case <-started:
			case <-time.After(2 * time.Second):
				t.Fatal("readiness probe did not start")
			}
			done := make(chan error, 1)
			go func() {
				if action == "drain" {
					done <- cfg.Observe(publisher.Event{Type: publisher.EventDraining, PublishRunNumber: 1})
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
	w, ready, _ := automaticWorkers(t, time.Second)
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
	gets := make(chan string, 32)
	w.HTTPTransport = trip(func(r *http.Request) (*http.Response, error) {
		gets <- r.Header.Get(clientruntime.ProbeHeader)
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

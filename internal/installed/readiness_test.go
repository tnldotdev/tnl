package installed

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/policy/visitorscope"
	publisherapp "github.com/tnldotdev/tnl/internal/publisher/app"
	"github.com/tnldotdev/tnl/internal/publisher/httpaccess"
	publisherservice "github.com/tnldotdev/tnl/internal/publisher/service"
	targetplan "github.com/tnldotdev/tnl/internal/publisher/target"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type readinessTransport func(*http.Request) (*http.Response, error)

func (f readinessTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func readinessFixture(t *testing.T, public bool) (*publicationReadiness, controlv1.ServiceRunPreparation, chan Status, context.CancelCauseFunc) {
	t.Helper()
	job, _, _ := fixture(t, "web")
	job.ReadinessPath = "/health"
	service := controlv1.Service{Id: job.ServiceID, Protocol: controlv1.ServiceProtocolHTTP, Endpoint: &controlv1.ServiceEndpoint{Hostname: "web.example", Port: 443, Public: public}}
	ctx, cancel := context.WithCancelCause(t.Context())
	statuses := make(chan Status, 128)
	r := newPublicationReadiness(ctx, cancel, job, service, 3, func(_ context.Context, status Status) error {
		statuses <- status
		return nil
	})
	r.localProbe = func(context.Context, string) bool { return true }
	t.Cleanup(func() {
		cancel(context.Canceled)
		_, _ = r.Close()
	})
	return r, controlv1.ServiceRunPreparation{ServiceId: job.ServiceID, ServiceRunId: "run-one", RunNumber: 1, Hostname: service.Endpoint.Hostname}, statuses, cancel
}

func preparedRun(p controlv1.ServiceRunPreparation) httpaccess.ReadinessRun {
	return httpaccess.ReadinessRun{Subject: visitorscope.Scope{Kind: visitorscope.Service, ID: p.ServiceId}, ID: p.ServiceRunId, Number: uint64(p.RunNumber), Hostname: p.Hostname}
}

func receiveReadinessStatus(t *testing.T, statuses <-chan Status, state JobState, run uint64) Status {
	t.Helper()
	deadline := time.NewTimer(3 * time.Second)
	defer deadline.Stop()
	for {
		select {
		case status := <-statuses:
			if status.State == state && status.RunNumber == run {
				return status
			}
		case <-deadline.C:
			t.Fatalf("missing %s observation for service run %d", state, run)
		}
	}
}

func receiveReadinessSignal(t *testing.T, signal <-chan struct{}) {
	t.Helper()
	select {
	case <-signal:
	case <-time.After(3 * time.Second):
		t.Fatal("readiness worker missed its synchronization boundary")
	}
}

func TestInstalledPublicReadinessRequiresConsumedExactRunProof(t *testing.T) {
	for _, name := range []string{"consumed", "unrelated responder", "different run", "different path", "diagnostic", "bad status", "canceled response"} {
		t.Run(name, func(t *testing.T) {
			_, preparation, _, cancel := readinessFixture(t, true)
			defer cancel(context.Canceled)
			run := preparedRun(preparation)
			proof, err := httpaccess.NewReadinessProof(run, "/health")
			if err != nil {
				t.Fatal(err)
			}
			ctx, stop := context.WithCancel(t.Context())
			defer stop()
			calls := 0
			transport := readinessTransport(func(request *http.Request) (*http.Response, error) {
				calls++
				if calls == 2 {
					stop()
					return nil, ctx.Err()
				}
				if request.URL.String() != "https://web.example/health" || request.Header.Get("Authorization") != "" || request.Header.Get("Cookie") != "" {
					t.Error("probe changed its endpoint or borrowed user credentials")
				}
				consuming := run
				if name == "different run" {
					consuming.ID = "run-two"
				}
				if name == "different path" {
					request.URL.Path = "/other"
				}
				if name != "unrelated responder" {
					proof.Consume(request, consuming)
				}
				response := &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(""))}
				if name == "diagnostic" {
					response.Header.Set("Tnl-Error-Code", "fixture")
				}
				if name == "bad status" {
					response.StatusCode = http.StatusServiceUnavailable
				}
				if name == "canceled response" {
					stop()
				}
				return response, nil
			})
			err = verifyServiceReadiness(ctx, run, "/health", proof, transport)
			expectedCalls := 2
			if name == "consumed" || name == "canceled response" {
				expectedCalls = 1
			}
			if calls != expectedCalls || (err == nil) != (name == "consumed") {
				t.Fatal("unverified endpoint became ready", err, calls)
			}
		})
	}
}

func TestInstalledHeartbeatCallbacksDoNotWaitForStatusPersistence(t *testing.T) {
	r, preparation, _, cancel := readinessFixture(t, false)
	started := make(chan struct{})
	r.observe = func(ctx context.Context, status Status) error {
		if status.State == JobProvisioning {
			close(started)
			<-ctx.Done()
			return ctx.Err()
		}
		return nil
	}
	if err := r.Prepared(preparation); err != nil {
		t.Fatal(err)
	}
	receiveReadinessSignal(t, started)
	callbacks := make(chan struct{})
	go func() {
		r.Observe(publisherservice.RunStatus{Ready: true, TargetHealthy: true})
		r.Healthy(t.Context())
		close(callbacks)
	}()
	receiveReadinessSignal(t, callbacks)
	cancel(context.Canceled)
	if ready, err := r.Close(); ready || err != nil {
		t.Fatal("canceled persistence marked the run ready or failed to join", ready, err)
	}
}

func TestInstalledHeartbeatCallbacksNeverWaitForLocalOrPublicProbes(t *testing.T) {
	r, preparation, statuses, cancel := readinessFixture(t, true)
	localStarted, publicStarted := make(chan struct{}), make(chan struct{})
	localJoined, publicJoined := make(chan struct{}), make(chan struct{})
	r.localProbe = func(ctx context.Context, _ string) bool {
		close(localStarted)
		<-ctx.Done()
		close(localJoined)
		return true
	}
	r.probe = func(ctx context.Context, _ httpaccess.ReadinessRun, _ string, _ *httpaccess.ReadinessProof) error {
		close(publicStarted)
		<-ctx.Done()
		close(publicJoined)
		return ctx.Err()
	}
	if err := r.Prepared(preparation); err != nil {
		t.Fatal(err)
	}
	receiveReadinessSignal(t, localStarted)
	r.Proof(preparedRun(preparation))
	r.Observe(publisherservice.RunStatus{Ready: true, TargetHealthy: true})
	receiveReadinessSignal(t, publicStarted)
	callbacks := make(chan struct{})
	go func() {
		for range 1000 {
			r.Healthy(t.Context())
			r.Observe(publisherservice.RunStatus{Ready: true, TargetHealthy: true})
		}
		close(callbacks)
	}()
	receiveReadinessSignal(t, callbacks)
	cancel(context.Canceled)
	ready, err := r.Close()
	if ready || err != nil {
		t.Fatal("incomplete probes marked the run ready or lost cancellation", ready, err)
	}
	receiveReadinessSignal(t, localJoined)
	receiveReadinessSignal(t, publicJoined)
	for len(statuses) > 0 {
		if status := <-statuses; status.State == JobReady {
			t.Fatal("canceled probe became ready")
		}
	}
}

func TestInstalledReadinessReportsOnlyPreparedVerifiedServiceRun(t *testing.T) {
	for _, public := range []bool{false, true} {
		t.Run(map[bool]string{false: "connector-only", true: "public"}[public], func(t *testing.T) {
			r, preparation, statuses, cancel := readinessFixture(t, public)
			defer cancel(context.Canceled)
			defer r.Close()
			r.probe = func(_ context.Context, run httpaccess.ReadinessRun, path string, proof *httpaccess.ReadinessProof) error {
				if !public {
					t.Error("connector-only HTTP contacted a public endpoint")
				}
				request := httptest.NewRequest(http.MethodGet, "https://"+run.Hostname+path, nil)
				request.Header.Set(publisherapp.ProbeHeader, proof.HeaderValue())
				if !proof.Consume(request, run) {
					return ErrScope
				}
				return nil
			}
			if err := r.Prepared(preparation); err != nil {
				t.Fatal(err)
			}
			if public {
				r.Proof(preparedRun(preparation))
			}
			await(t, func() bool { return r.Healthy(t.Context()) })
			r.Observe(publisherservice.RunStatus{Ready: true, TargetHealthy: true})
			status := receiveReadinessStatus(t, statuses, JobReady, 1)
			if status.Address != "https://web.example" || status.Attempts != 3 {
				t.Fatal("ready observation was not bound to preparation", status)
			}
			cancel(context.Canceled)
			if ready, err := r.Close(); !ready || err != nil {
				t.Fatal("verified run failed to join", ready, err)
			}
		})
	}
}

func TestInstalledReplacementJoinsOldProbeAndRejectsLateSuccess(t *testing.T) {
	r, preparation, statuses, cancel := readinessFixture(t, true)
	defer cancel(context.Canceled)
	defer r.Close()
	started, stopped, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
	defer close(release)
	r.probe = func(ctx context.Context, _ httpaccess.ReadinessRun, _ string, _ *httpaccess.ReadinessProof) error {
		close(started)
		<-ctx.Done()
		close(stopped)
		<-release
		return nil
	}
	if err := r.Prepared(preparation); err != nil {
		t.Fatal(err)
	}
	old := preparedRun(preparation)
	r.Proof(old)
	r.Observe(publisherservice.RunStatus{Ready: true, TargetHealthy: true})
	receiveReadinessSignal(t, started)
	next := preparation
	next.ServiceRunId, next.RunNumber = "run-two", 2
	replaced := make(chan error, 1)
	go func() { replaced <- r.Prepared(next) }()
	receiveReadinessSignal(t, stopped)
	select {
	case err := <-replaced:
		t.Fatal("replacement preceded probe join", err)
	default:
	}
	// release the canceled request after replacement has fenced its run.
	release <- struct{}{}
	if err := <-replaced; err != nil {
		t.Fatal(err)
	}
	if r.Proof(old) != nil {
		t.Fatal("old run received a new proof")
	}
	status := receiveReadinessStatus(t, statuses, JobProvisioning, 2)
	if status.Address != "https://web.example" {
		t.Fatal("prepared endpoint was not observed", status)
	}
	if ready, _ := r.Close(); ready {
		t.Fatal("late success marked a replacement ready")
	}
}

func TestInstalledLocalHTTPHealthUsesCapturedTargetAndPath(t *testing.T) {
	var requests atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		requests.Add(1)
		if request.URL.Path != "/health" || request.Header.Get("Authorization") != "" {
			t.Error("local health ignored its path or borrowed credentials")
		}
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer target.Close()
	r, preparation, _, cancel := readinessFixture(t, false)
	defer cancel(context.Canceled)
	defer r.Close()
	r.localProbe = r.checkTarget
	if err := r.Capture(targetplan.TargetSnapshot{Address: target.URL, Identity: "captured"}); err != nil {
		t.Fatal(err)
	}
	if err := r.Prepared(preparation); err != nil {
		t.Fatal(err)
	}
	await(t, func() bool {
		r.mu.Lock()
		run := r.current
		r.mu.Unlock()
		return run.checked.Load() != 0
	})
	if requests.Load() == 0 || r.Healthy(t.Context()) {
		t.Fatal("a listening but unhealthy HTTP target became ready")
	}
}

func TestInstalledReadinessPreservesObservationAndProbeCleanupFailures(t *testing.T) {
	r, preparation, _, cancel := readinessFixture(t, true)
	defer cancel(context.Canceled)
	observationFailure, cleanupFailure := errors.New("observation failed"), errors.New("probe cleanup failed")
	started := make(chan struct{})
	r.probe = func(ctx context.Context, _ httpaccess.ReadinessRun, _ string, _ *httpaccess.ReadinessProof) error {
		close(started)
		<-ctx.Done()
		return errors.Join(ctx.Err(), cleanupFailure)
	}
	r.observe = func(_ context.Context, status Status) error {
		if status.State == JobTargetUnavailable {
			return observationFailure
		}
		return nil
	}
	if err := r.Prepared(preparation); err != nil {
		t.Fatal(err)
	}
	r.Proof(preparedRun(preparation))
	r.Observe(publisherservice.RunStatus{Ready: true, TargetHealthy: true})
	receiveReadinessSignal(t, started)
	r.Observe(publisherservice.RunStatus{LastCheck: time.Now()})
	select {
	case <-r.ctx.Done():
	case <-time.After(3 * time.Second):
		t.Fatal("observation failure did not cancel the publication")
	}
	_, err := r.Close()
	if !errors.Is(err, observationFailure) || !errors.Is(err, cleanupFailure) {
		t.Fatal("cancellation hid an independent failure", err)
	}
}

func TestInstalledServiceAddressNeverInventsConnectorPorts(t *testing.T) {
	for _, test := range []struct {
		protocol controlv1.ServiceProtocol
		port     int
		address  string
	}{
		{controlv1.ServiceProtocolHTTP, 443, "https://web.example"},
		{controlv1.Tcp, 25432, "web.example:25432"},
		{controlv1.Postgres, 0, ""},
	} {
		t.Run(string(test.protocol), func(t *testing.T) {
			r, preparation, statuses, cancel := readinessFixture(t, false)
			defer cancel(context.Canceled)
			defer r.Close()
			r.service.Protocol, r.service.Endpoint.Port = test.protocol, test.port
			if err := r.Prepared(preparation); err != nil {
				t.Fatal(err)
			}
			if status := receiveReadinessStatus(t, statuses, JobProvisioning, 1); status.Address != test.address {
				t.Fatal("observation invented an endpoint address", status)
			}
		})
	}
}

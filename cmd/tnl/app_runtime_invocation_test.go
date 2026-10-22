package main

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
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/authorityclient"
	"github.com/tnldotdev/tnl/internal/clientruntime"
	"github.com/tnldotdev/tnl/internal/clientserver"
	"github.com/tnldotdev/tnl/internal/clientstate"
	"github.com/tnldotdev/tnl/internal/opaqueid"
	"github.com/tnldotdev/tnl/internal/privateprotocol"
	"github.com/tnldotdev/tnl/internal/publisher"
	nativeauth "github.com/tnldotdev/tnl/internal/publisheridentity/native"
	"github.com/tnldotdev/tnl/internal/publisheridentity/native/publishingtest"
	"github.com/tnldotdev/tnl/internal/testutil"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
	"github.com/zalando/go-keyring"
)

// the handler, registration manager, worker and SQLite journal are real. only
// remote control HTTPS and the publisher transport use the existing fixtures.
func invocationRuntime(t *testing.T) (*appRuntime, privateprotocol.Endpoint, map[string]any, *publishingtest.Fixture) {
	t.Helper()
	f := publishingtest.New(t, testutil.PublishingHooks{})
	original := http.DefaultTransport
	http.DefaultTransport = invocationTransport(func(r *http.Request) (*http.Response, error) {
		if r.URL.Scheme+"://"+r.URL.Host == f.URL {
			return f.HTTP.Transport.RoundTrip(r)
		}
		return original.RoundTrip(r)
	})
	t.Cleanup(func() { http.DefaultTransport = original })
	a, _ := testAppRuntimeWorkers(t, true)
	profile, err := a.state.Server(t.Context(), f.URL)
	if err != nil {
		t.Fatal(err)
	}
	owner, err := f.Owner()
	if err != nil {
		t.Fatal(err)
	}
	authority, err := authorityclient.New(f.URL, f.HTTP, "")
	if err != nil {
		t.Fatal(err)
	}
	_, identity, err := nativeauth.EnsureNamespace(t.Context(), profile, owner, authority, "tm_0000000000000000000001", f.DomainID, f.Namespace)
	if err != nil {
		t.Fatal(err)
	}
	// include uppercase to exercise the opaque invocation key's actual alphabet.
	invocation := "ivk_0123456789ABCDEFGHIJKL"
	endpoint, err := a.capabilities.Issue(privateprotocol.CapabilityRequest{Scope: "invocation", InvocationId: &invocation})
	if err != nil {
		t.Fatal(err)
	}
	body := map[string]any{"version": 1, "invocation_id": invocation, "owner": "0123456789abcdef0123456789abcdef", "pid": os.Getpid(), "target": "http://127.0.0.1:3000", "server_url": f.URL, "publisher_id": identity.ClientId}
	return a, endpoint, body, f
}

type invocationTransport func(*http.Request) (*http.Response, error)

func (f invocationTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func waitInvocation(t *testing.T, a *appRuntime, predicate func(clientruntime.Snapshot) bool) clientruntime.Snapshot {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for {
		snapshot := a.manager.Snapshot()
		if predicate(snapshot) {
			return snapshot
		}
		if time.Now().After(deadline) {
			t.Fatalf("invocation did not reach expected state: services=%+v publications=%+v", snapshot.Services, snapshot.Publications)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func readyInvocation(ctx context.Context, cfg publisher.Config) error {
	route := cfg.AllocatedPublicURL
	for _, event := range []publisher.Event{
		{Type: publisher.EventPublicURLAssigned, PublicURLID: route.Id, Hostname: route.CanonicalHostname},
		{Type: publisher.EventProvisioning, PublishRunNumber: 1},
		{Type: publisher.EventReady, PublishRunNumber: 1, PublicURL: "https://" + route.CanonicalHostname},
	} {
		if err := cfg.Observe(event); err != nil {
			return err
		}
	}
	<-ctx.Done()
	return ctx.Err()
}

func TestInvocationWorkerPublicationAndLimits(t *testing.T) {
	if !testutil.IsolatedPublishingTest(t) {
		return
	}
	a, endpoint, body, f := invocationRuntime(t)
	allocations := make(chan controlv1.AllocateEphemeralPublicURLRequest, 2)
	transport := f.HTTP.Transport
	f.HTTP.Transport = invocationTransport(func(r *http.Request) (*http.Response, error) {
		if r.Method == "POST" && r.URL.Path == "/v1/publisher/public-urls" {
			encoded, err := io.ReadAll(r.Body)
			if err != nil {
				return nil, err
			}
			r.Body = io.NopCloser(bytes.NewReader(encoded))
			var allocation controlv1.AllocateEphemeralPublicURLRequest
			if err := json.Unmarshal(encoded, &allocation); err != nil {
				return nil, err
			}
			allocations <- allocation
		}
		return transport.RoundTrip(r)
	})
	captured := make(chan publisher.Config, 1)
	a.workers.RunPublisher = func(ctx context.Context, cfg publisher.Config) error {
		captured <- cfg
		return readyInvocation(ctx, cfg)
	}
	var registration privateprotocol.Registration
	if err := privateprotocol.Call(t.Context(), endpoint, "POST", "/v1/ad-hoc/register", body, &registration); err != nil {
		t.Fatal(err)
	}
	waitInvocation(t, a, func(s clientruntime.Snapshot) bool {
		for _, service := range s.Services {
			if service.RegistrationID == registration.RegistrationID {
				if service.Failure != "" {
					t.Fatalf("invocation worker failed before publisher: %s", service.Failure)
				}
				return service.Routable
			}
		}
		return false
	})
	cfg := <-captured
	if allocation := <-allocations; allocation.Limits != nil {
		t.Fatalf("default allocation limits=%+v", allocation.Limits)
	}
	if cfg.Service != "" {
		t.Fatalf("invocation key used as configured service name: %q", cfg.Service)
	}
	var snapshot clientruntime.Snapshot
	other, err := a.state.BeginTunnel(t.Context(), clientstate.BeginTunnelOptions{Command: clientstate.TunnelCommandPublish, Server: f.URL, Project: a.project.Root, Target: "3001"})
	if err != nil {
		t.Fatal(err)
	}
	defer other.Finish(context.Background(), nil)
	if err := privateprotocol.Call(t.Context(), endpoint, "GET", "/v1/status", nil, &snapshot); err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Services) != 1 || len(snapshot.Publications) != 1 || snapshot.Publications[0].Service != "" || snapshot.Publications[0].ID != snapshot.Services[0].TunnelID {
		t.Fatalf("scoped invocation journal=%+v", snapshot)
	}
	var repeated privateprotocol.Registration
	if err := privateprotocol.Call(t.Context(), endpoint, "POST", "/v1/ad-hoc/register", body, &repeated); err != nil || repeated != registration || f.Allocations.Load() != 1 {
		t.Fatalf("repeat allocated again: registration=%+v allocations=%d err=%v", repeated, f.Allocations.Load(), err)
	}
	body["limits"] = map[string]any{"requests": 7, "concurrency": 2, "rate": map[string]any{"requests": 3, "per": "4s"}}
	var conflict *privateprotocol.ResponseError
	if err := privateprotocol.Call(t.Context(), endpoint, "POST", "/v1/ad-hoc/register", body, nil); !errors.As(err, &conflict) || conflict.Code != "runtime.owner_conflict" {
		t.Fatalf("changed invocation did not conflict: %v", err)
	}
	if err := privateprotocol.Call(t.Context(), endpoint, "POST", "/v1/unregister", registration, nil); err != nil {
		t.Fatal(err)
	}
	if ids := f.DeletedIDs(); len(ids) != 1 || ids[0] != cfg.AllocatedPublicURL.Id {
		t.Fatalf("cleanup did not join exact allocation: %v", ids)
	}
	invocation, _ := opaqueid.New(opaqueid.InvocationPrefix)
	endpoint, _ = a.capabilities.Issue(privateprotocol.CapabilityRequest{Scope: "invocation", InvocationId: &invocation})
	body["invocation_id"] = invocation
	if err := privateprotocol.Call(t.Context(), endpoint, "POST", "/v1/ad-hoc/register", body, &registration); err != nil {
		t.Fatalf("supported limits rejected: %v", err)
	}
	select {
	case cfg = <-captured:
		if cfg.Limits != (publisher.ApplicationLimits{Requests: 7, Concurrency: 2, RateRequests: 3, RatePer: 4 * time.Second}) {
			t.Fatalf("worker limits=%+v", cfg.Limits)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("limited invocation did not reach publisher")
	}
	allocation := <-allocations
	if allocation.Limits == nil || allocation.Limits.Requests == nil || *allocation.Limits.Requests != 7 || allocation.Limits.Concurrency == nil || *allocation.Limits.Concurrency != 2 || allocation.Limits.Rate == nil || allocation.Limits.Rate.Requests != 3 || allocation.Limits.Rate.Per != "4s" {
		t.Fatalf("allocation lost supported limits: %+v", allocation.Limits)
	}
	if err := privateprotocol.Call(t.Context(), endpoint, "POST", "/v1/ad-hoc/register", body, &repeated); err != nil || repeated != registration || f.Allocations.Load() != 2 {
		t.Fatalf("limited repeat allocated again: registration=%+v allocations=%d err=%v", repeated, f.Allocations.Load(), err)
	}
}

func TestInvocationLimitsValidation(t *testing.T) {
	if !testutil.IsolatedPublishingTest(t) {
		return
	}
	a, endpoint, body, f := invocationRuntime(t)
	a.workers.RunPublisher = readyInvocation
	for _, invalid := range []any{
		map[string]any{"requests": 0}, map[string]any{"requests": -1},
		map[string]any{"concurrency": 0}, map[string]any{"concurrency": -1},
		map[string]any{"rate": map[string]any{"requests": 1, "per": "bad"}},
		map[string]any{"rate": map[string]any{"requests": 1, "per": "0s"}},
		map[string]any{"rate": map[string]any{"requests": 0, "per": "1s"}},
		map[string]any{"rate": map[string]any{"requests": 1}},
	} {
		body["limits"] = invalid
		if err := privateprotocol.Call(t.Context(), endpoint, "POST", "/v1/ad-hoc/register", body, nil); err == nil || f.Allocations.Load() != 0 {
			t.Fatalf("invalid limits allocated: limits=%v allocations=%d err=%v", invalid, f.Allocations.Load(), err)
		}
	}
	body["limits"] = map[string]any{}
	if err := privateprotocol.Call(t.Context(), endpoint, "POST", "/v1/ad-hoc/register", body, nil); err != nil {
		t.Fatalf("empty default limits rejected: %v", err)
	}
}

func TestInvocationRealPublisherAppliesRequestRate(t *testing.T) {
	if !testutil.IsolatedPublishingTest(t) {
		return
	}
	a, endpoint, body, f := invocationRuntime(t)
	var requests atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer target.Close()
	body["target"] = target.URL
	body["limits"] = map[string]any{"rate": map[string]any{"requests": 1, "per": "1h"}, "concurrency": 2}
	var registration privateprotocol.Registration
	if err := privateprotocol.Call(t.Context(), endpoint, "POST", "/v1/ad-hoc/register", body, &registration); err != nil {
		t.Fatal(err)
	}
	snapshot := waitInvocation(t, a, func(s clientruntime.Snapshot) bool {
		for _, service := range s.Services {
			if service.RegistrationID == registration.RegistrationID {
				if service.Failure != "" {
					t.Fatalf("real invocation publisher failed: %s", service.Failure)
				}
				return service.Routable
			}
		}
		return false
	})
	address := ""
	for _, service := range snapshot.Services {
		if service.RegistrationID == registration.RegistrationID {
			address = service.PublicURL
		}
	}
	for _, want := range []int{http.StatusNoContent, http.StatusTooManyRequests} {
		if status, _, err := f.Visit(t.Context(), address); err != nil || status != want {
			t.Fatalf("request limit through real visitor TLS: status=%d want=%d err=%v", status, want, err)
		}
	}
	if requests.Load() != 1 || f.Runs.Load() != 1 || f.Allocations.Load() != 1 {
		t.Fatalf("limit did not protect target: requests=%d runs=%d allocations=%d", requests.Load(), f.Runs.Load(), f.Allocations.Load())
	}
	if err := privateprotocol.Call(t.Context(), endpoint, "POST", "/v1/unregister", registration, nil); err != nil {
		t.Fatal(err)
	}
	if f.Deletions.Load() != 1 {
		t.Fatal("real publisher drain did not join allocation cleanup")
	}
}

func TestInvocationEarlyWorkerFailureCleansAllocation(t *testing.T) {
	if !testutil.IsolatedPublishingTest(t) {
		return
	}
	a, endpoint, body, f := invocationRuntime(t)
	a.AttachPublication = func(_ context.Context, _ clientruntime.Service, cfg *publisher.Config) error {
		cfg.ControlURL = "http://invalid.example"
		return nil
	}
	var registration privateprotocol.Registration
	if err := privateprotocol.Call(t.Context(), endpoint, "POST", "/v1/ad-hoc/register", body, &registration); err != nil {
		t.Fatal(err)
	}
	waitInvocation(t, a, func(s clientruntime.Snapshot) bool {
		for _, service := range s.Services {
			if service.RegistrationID == registration.RegistrationID && service.Failure != "" {
				return true
			}
		}
		return false
	})
	if f.Allocations.Load() != 1 || f.Deletions.Load() != 1 {
		t.Fatalf("early worker failure leaked allocation: allocations=%d deletions=%d", f.Allocations.Load(), f.Deletions.Load())
	}
	_ = a.manager.Unregister(registration.RegistrationID, registration.Owner)
	if f.Deletions.Load() != 1 {
		t.Fatal("cleanup was not exactly once")
	}
}

func TestInvocationCanceledRegistrationCleansAllocation(t *testing.T) {
	if !testutil.IsolatedPublishingTest(t) {
		return
	}
	a, endpoint, body, f := invocationRuntime(t)
	a.workers.RunPublisher = readyInvocation
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	a.AttachPublication = func(context.Context, clientruntime.Service, *publisher.Config) error { cancel(); return nil }
	request := invocationRequest(t, ctx, endpoint, body)
	a.handler().ServeHTTP(httptest.NewRecorder(), request)
	if f.Allocations.Load() != 1 || f.Deletions.Load() != 1 {
		t.Fatalf("canceled registration leaked allocation: allocations=%d deletions=%d", f.Allocations.Load(), f.Deletions.Load())
	}
	for _, service := range a.manager.Snapshot().Services {
		if service.Name == body["invocation_id"] && service.RegistrationID != "" {
			t.Fatal("canceled registration retained ownership")
		}
	}
}

func TestInvocationSetupFailureCleansAllocationAndReservation(t *testing.T) {
	if !testutil.IsolatedPublishingTest(t) {
		return
	}
	a, _, body, f := invocationRuntime(t)
	setupErr := errors.New("publication setup failed")
	a.AttachPublication = func(context.Context, clientruntime.Service, *publisher.Config) error { return setupErr }
	encoded, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	var request privateprotocol.Invocation
	if err := json.Unmarshal(encoded, &request); err != nil {
		t.Fatal(err)
	}
	if _, err := a.invocation(t.Context(), request); !errors.Is(err, setupErr) {
		t.Fatalf("setup cause was lost: %v", err)
	}
	if f.Allocations.Load() != 1 || f.Deletions.Load() != 1 {
		t.Fatalf("setup failure leaked allocation: allocations=%d deletions=%d", f.Allocations.Load(), f.Deletions.Load())
	}
	for _, service := range a.manager.Snapshot().Services {
		if service.Name == request.InvocationId && service.RegistrationID != "" {
			t.Fatal("setup failure retained registration ownership")
		}
	}
	if len(a.prepared) != 0 {
		t.Fatal("setup failure retained worker preparation")
	}
}

func TestAppWorkflowSlowPreparationDoesNotBlockAnotherInvocation(t *testing.T) {
	if !testutil.IsolatedPublishingTest(t) {
		return
	}
	a, endpoint, body, _ := invocationRuntime(t)
	a.workers.RunPublisher = readyInvocation
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	defer unblock()
	firstID := body["invocation_id"].(string)
	a.AttachPublication = func(_ context.Context, service clientruntime.Service, _ *publisher.Config) error {
		if service.Name == firstID {
			close(entered)
			<-release
		}
		return nil
	}
	firstDone := make(chan error, 1)
	go func() {
		firstDone <- privateprotocol.Call(t.Context(), endpoint, "POST", "/v1/ad-hoc/register", body, nil)
	}()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("first preparation never started")
	}
	secondID, _ := opaqueid.New(opaqueid.InvocationPrefix)
	secondEndpoint, err := a.capabilities.Issue(privateprotocol.CapabilityRequest{Scope: "invocation", InvocationId: &secondID})
	if err != nil {
		t.Fatal(err)
	}
	second := make(map[string]any, len(body))
	for k, value := range body {
		second[k] = value
	}
	second["invocation_id"] = secondID
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	var registration privateprotocol.Registration
	secondErr := privateprotocol.Call(ctx, secondEndpoint, "POST", "/v1/ad-hoc/register", second, &registration)
	unblock()
	if err := <-firstDone; err != nil {
		t.Fatal(err)
	}
	if secondErr != nil {
		t.Fatal("unrelated invocation waited for slow preparation", secondErr)
	}
}

func invocationRequest(t *testing.T, ctx context.Context, endpoint privateprotocol.Endpoint, body any) *http.Request {
	t.Helper()
	encoded, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("POST", endpoint.Url+"/v1/ad-hoc/register", bytes.NewReader(encoded)).WithContext(ctx)
	r.RequestURI = "/v1/ad-hoc/register"
	r.RemoteAddr = "127.0.0.1:12345"
	r.URL.Scheme, r.URL.Host = "", ""
	r.Header.Set("Authorization", "Bearer "+endpoint.Capability)
	r.Header.Set("Content-Type", "application/json")
	return r
}

type lostInvocationAck struct{ header http.Header }

func (w *lostInvocationAck) Header() http.Header     { return w.header }
func (*lostInvocationAck) WriteHeader(int)           {}
func (*lostInvocationAck) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }

func TestInvocationLostAcknowledgmentCleansAllocation(t *testing.T) {
	if !testutil.IsolatedPublishingTest(t) {
		return
	}
	a, endpoint, body, f := invocationRuntime(t)
	a.workers.RunPublisher = readyInvocation
	a.handler().ServeHTTP(&lostInvocationAck{header: http.Header{}}, invocationRequest(t, t.Context(), endpoint, body))
	if f.Allocations.Load() != 1 || f.Deletions.Load() != 1 {
		t.Fatalf("lost registration acknowledgment leaked allocation: allocations=%d deletions=%d", f.Allocations.Load(), f.Deletions.Load())
	}
}

func TestInvocationExplicitServerSelection(t *testing.T) {
	if !testutil.IsolatedPublishingTest(t) {
		return
	}
	a, endpoint, body, f := invocationRuntime(t)
	t.Setenv("TNL_SERVER", "")
	keyring.MockInit()
	options := runtimeOptions{Directory: a.project.Root, StateDir: filepath.Join(t.TempDir(), "selection")}
	project, _, err := runtimeProject(t.Context(), options)
	if err != nil {
		t.Fatal(err)
	}
	a.project = project
	a.workers.RunPublisher = readyInvocation
	var registration privateprotocol.Registration
	if err := privateprotocol.Call(t.Context(), endpoint, "POST", "/v1/ad-hoc/register", body, &registration); err != nil {
		t.Fatalf("explicit server rejected against implicit hosted fallback: %v (project server=%v)", err, a.project.Config.Server)
	}
	if err := a.manager.Unregister(registration.RegistrationID, registration.Owner); err != nil {
		t.Fatal(err)
	}
	if err := a.state.SaveServer(t.Context(), clientserver.DefaultURL); err != nil {
		t.Fatal(err)
	}
	selection, err := clientstate.Open(t.Context(), options.StateDir)
	if err != nil {
		t.Fatal(err)
	}
	if err := selection.SaveServer(t.Context(), clientserver.DefaultURL); err != nil {
		t.Fatal(err)
	}
	_ = selection.Close()
	a.project, _, err = runtimeProject(t.Context(), options)
	if err != nil {
		t.Fatal(err)
	}
	if err := privateprotocol.Call(t.Context(), endpoint, "POST", "/v1/ad-hoc/register", body, &registration); err != nil {
		t.Fatalf("explicit server rejected against saved fallback: %v", err)
	}
	if err := a.manager.Unregister(registration.RegistrationID, registration.Owner); err != nil {
		t.Fatal(err)
	}
	configured := clientserver.DefaultURL
	a.project.Config.Server = &configured
	var request privateprotocol.Invocation
	encoded, _ := json.Marshal(body)
	_ = json.Unmarshal(encoded, &request)
	if _, err := a.invocation(t.Context(), request); !errors.Is(err, nativeauth.ErrScope) || f.Allocations.Load() != 2 {
		t.Fatalf("explicit project conflict ignored: err=%v allocations=%d", err, f.Allocations.Load())
	}
	t.Setenv("TNL_SERVER", configured)
	a.project, _, err = runtimeProject(t.Context(), options)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.invocation(t.Context(), request); !errors.Is(err, nativeauth.ErrScope) || f.Allocations.Load() != 2 {
		t.Fatalf("explicit environment conflict ignored: err=%v allocations=%d", err, f.Allocations.Load())
	}
	// actual configured service names retain their strict SQLite boundary.
	if _, err := a.state.BeginTunnel(t.Context(), clientstate.BeginTunnelOptions{Command: clientstate.TunnelCommandPublish, Server: f.URL, Project: a.project.Root, Target: request.Target, Service: request.InvocationId}); err == nil {
		t.Fatal("invocation key accepted as a configured service name")
	}
}

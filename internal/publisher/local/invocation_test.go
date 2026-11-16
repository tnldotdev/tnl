package local

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
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

	"github.com/tnldotdev/tnl/internal/client/auth"
	clientauthority "github.com/tnldotdev/tnl/internal/client/authority"
	clientserver "github.com/tnldotdev/tnl/internal/client/server"
	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/policy/applicationlimits"
	publisherapp "github.com/tnldotdev/tnl/internal/publisher/app"
	publisheridentity "github.com/tnldotdev/tnl/internal/publisher/identity"
	"github.com/tnldotdev/tnl/internal/publisher/identity/publishingtest"
	publisherprotocol "github.com/tnldotdev/tnl/internal/publisher/localapi/protocol"
	"github.com/tnldotdev/tnl/internal/publisher/requestlimit"
	publisherservice "github.com/tnldotdev/tnl/internal/publisher/service"
	"github.com/tnldotdev/tnl/internal/testutil"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
	"github.com/zalando/go-keyring"
)

// the handler, registration manager, worker and SQLite journal are real. only
// remote control HTTPS and the publisher transport use the existing fixtures.
func invocationRuntime(t *testing.T) (*appRuntime, publisherprotocol.Endpoint, map[string]any, *publishingtest.Fixture) {
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
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(target.Close)
	a.AttachPublication = func(_ context.Context, _ publisherapp.Service, cfg *publisherservice.RunConfig) error {
		cfg.HeartbeatInterval = 20 * time.Millisecond
		return nil
	}
	profile, err := a.state.Server(t.Context(), f.URL)
	if err != nil {
		t.Fatal(err)
	}
	owner, err := f.Owner()
	if err != nil {
		t.Fatal(err)
	}
	authority, err := clientauthority.New(f.URL, f.HTTP, "")
	if err != nil {
		t.Fatal(err)
	}
	_, identity, err := publisheridentity.EnsureNamespace(t.Context(), profile, owner, authority, "tm_0000000000000000000001", f.DomainID, f.Namespace)
	if err != nil {
		t.Fatal(err)
	}
	// include uppercase to exercise the opaque invocation key's actual alphabet.
	invocation := "ivk_0123456789ABCDEFGHIJKL"
	endpoint, err := a.capabilities.Issue(publisherprotocol.CapabilityRequest{Scope: "invocation", InvocationId: &invocation})
	if err != nil {
		t.Fatal(err)
	}
	body := map[string]any{"version": 1, "invocation_id": invocation, "owner": "0123456789abcdef0123456789abcdef", "pid": os.Getpid(), "target": target.URL, "server_url": f.URL, "publisher_identity_id": identity.ClientId}
	return a, endpoint, body, f
}

type invocationTransport func(*http.Request) (*http.Response, error)

func (f invocationTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func waitInvocation(t *testing.T, a *appRuntime, predicate func(publisherapp.Snapshot) bool) publisherapp.Snapshot {
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

func TestInvocationWorkerPublicationAndLimits(t *testing.T) {
	if !testutil.IsolatedPublishingTest(t) {
		return
	}
	a, endpoint, body, f := invocationRuntime(t)
	allocations := make(chan controlv1.AllocateServiceRequest, 2)
	transport := f.HTTP.Transport
	f.HTTP.Transport = invocationTransport(func(r *http.Request) (*http.Response, error) {
		if r.Method == "POST" && r.URL.Path == "/v1/publisher/services" {
			encoded, err := io.ReadAll(r.Body)
			if err != nil {
				return nil, err
			}
			r.Body = io.NopCloser(bytes.NewReader(encoded))
			var allocation controlv1.AllocateServiceRequest
			if err := json.Unmarshal(encoded, &allocation); err != nil {
				return nil, err
			}
			allocations <- allocation
		}
		return transport.RoundTrip(r)
	})
	captured := make(chan publisherservice.RunConfig, 1)
	attach := a.AttachPublication
	a.AttachPublication = func(ctx context.Context, service publisherapp.Service, cfg *publisherservice.RunConfig) error {
		if err := attach(ctx, service, cfg); err != nil {
			return err
		}
		captured <- *cfg
		return nil
	}
	var registration publisherprotocol.Registration
	if err := publisherprotocol.Call(t.Context(), endpoint, "POST", "/v1/publications/register", body, &registration); err != nil {
		t.Fatal(err)
	}
	waitInvocation(t, a, func(s publisherapp.Snapshot) bool {
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
	if allocation := <-allocations; allocation.Configuration.Http.Limits != nil || allocation.Configuration.Traffic != nil {
		t.Fatalf("default allocation introduced limits or traffic: %+v", allocation)
	}
	if cfg.ServiceID == "" || cfg.PublisherIdentityID != body["publisher_identity_id"] || cfg.PublisherGrantID == "" || cfg.PublisherKeyID == "" {
		t.Fatalf("invocation lost its actual service or publisher identity: %+v", cfg)
	}
	var snapshot publisherapp.Snapshot
	other, err := a.state.BeginTunnel(t.Context(), clientstate.BeginTunnelOptions{Command: clientstate.TunnelCommandPublish, Server: f.URL, Project: a.project.Root, Target: "3001"})
	if err != nil {
		t.Fatal(err)
	}
	defer other.Finish(context.Background(), nil)
	if err := publisherprotocol.Call(t.Context(), endpoint, "GET", "/v1/status", nil, &snapshot); err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Services) != 1 || len(snapshot.Publications) != 1 || snapshot.Publications[0].Service != "" || snapshot.Publications[0].ID != snapshot.Services[0].TunnelID {
		t.Fatalf("scoped invocation journal=%+v", snapshot)
	}
	var repeated publisherprotocol.Registration
	if err := publisherprotocol.Call(t.Context(), endpoint, "POST", "/v1/publications/register", body, &repeated); err != nil || repeated != registration || f.Allocations.Load() != 1 {
		t.Fatalf("repeat allocated again: registration=%+v allocations=%d err=%v", repeated, f.Allocations.Load(), err)
	}
	body["limits"] = map[string]any{"total": 7, "concurrency": 2, "rate": map[string]any{"count": 3, "per": "4s"}}
	body["require_post_quantum"] = true
	var conflict *publisherprotocol.ResponseError
	if err := publisherprotocol.Call(t.Context(), endpoint, "POST", "/v1/publications/register", body, nil); !errors.As(err, &conflict) || conflict.Code != "runtime.owner_conflict" {
		t.Fatalf("changed invocation did not conflict: %v", err)
	}
	if err := publisherprotocol.Call(t.Context(), endpoint, "POST", "/v1/unregister", registration, nil); err != nil {
		t.Fatal(err)
	}
	if ids := f.DeletedIDs(); len(ids) != 1 || ids[0] != cfg.ServiceID {
		t.Fatalf("cleanup did not join exact allocation: %v", ids)
	}
	invocation, _ := opaqueid.New(opaqueid.InvocationPrefix)
	endpoint, _ = a.capabilities.Issue(publisherprotocol.CapabilityRequest{Scope: "invocation", InvocationId: &invocation})
	body["invocation_id"] = invocation
	if err := publisherprotocol.Call(t.Context(), endpoint, "POST", "/v1/publications/register", body, &registration); err != nil {
		t.Fatalf("supported limits rejected: %v", err)
	}
	select {
	case cfg = <-captured:
		access, err := cfg.Access(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		saved, err := cfg.Control.GetPublisherService(t.Context(), cfg.ServiceID, access)
		if err != nil || !saved.RequirePostQuantum {
			t.Fatal("native invocation lost the public HTTPS requirement", err)
		}
		limits, err := requestlimit.ParseLimits(saved.HttpLimits)
		if err != nil || limits != (applicationlimits.Limits{Requests: 7, Concurrency: 2, RateRequests: 3, RatePer: 4 * time.Second}) {
			t.Fatalf("saved worker limits=%+v err=%v", limits, err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("limited invocation did not reach publisher")
	}
	allocation := <-allocations
	if allocation.Configuration.RequirePostQuantum == nil || !*allocation.Configuration.RequirePostQuantum {
		t.Fatal("native allocation lost the public HTTPS requirement")
	}
	limits, err := requestlimit.ParseLimits(allocation.Configuration.Http.Limits)
	if err != nil || limits != (applicationlimits.Limits{Requests: 7, Concurrency: 2, RateRequests: 3, RatePer: 4 * time.Second}) || allocation.Configuration.Traffic != nil {
		t.Fatalf("allocation lost HTTP limits or confused them with traffic: %+v err=%v", allocation, err)
	}
	if err := publisherprotocol.Call(t.Context(), endpoint, "POST", "/v1/publications/register", body, &repeated); err != nil || repeated != registration || f.Allocations.Load() != 2 {
		t.Fatalf("limited repeat allocated again: registration=%+v allocations=%d err=%v", repeated, f.Allocations.Load(), err)
	}
}

func TestInvocationLimitsValidation(t *testing.T) {
	if !testutil.IsolatedPublishingTest(t) {
		return
	}
	_, endpoint, body, f := invocationRuntime(t)
	for _, invalid := range []any{
		map[string]any{"total": 0}, map[string]any{"total": -1},
		map[string]any{"concurrency": 0}, map[string]any{"concurrency": -1},
		map[string]any{"rate": map[string]any{"count": 1, "per": "bad"}},
		map[string]any{"rate": map[string]any{"count": 1, "per": "0s"}},
		map[string]any{"rate": map[string]any{"count": 0, "per": "1s"}},
		map[string]any{"rate": map[string]any{"count": 1}},
		map[string]any{"rate": map[string]any{"count": 1, "per": "1s", "burst": 0}},
	} {
		body["limits"] = invalid
		if err := publisherprotocol.Call(t.Context(), endpoint, "POST", "/v1/publications/register", body, nil); err == nil || f.Allocations.Load() != 0 {
			t.Fatalf("invalid limits allocated: limits=%v allocations=%d err=%v", invalid, f.Allocations.Load(), err)
		}
	}
	body["limits"] = map[string]any{}
	if err := publisherprotocol.Call(t.Context(), endpoint, "POST", "/v1/publications/register", body, nil); err != nil {
		t.Fatalf("empty default limits rejected: %v", err)
	}
}

func TestInvocationOptionsKeepHTTPBudgetAndTargetSelection(t *testing.T) {
	for _, target := range []string{"http://127.0.0.1:3000", "https://app.example.test:8443"} {
		t.Run(target, func(t *testing.T) {
			request := publisherprotocol.Invocation{InvocationId: "ivk_0123456789ABCDEFGHIJKL", Target: target, RequirePostQuantum: new(true),
				Limits: &controlv1.ProjectHTTPApplicationLimits{Total: new(7), Concurrency: new(2),
					Rate: &controlv1.ProjectApplicationRate{Count: 3, Per: "4s", Burst: new(5)}}}
			options, err := invocationOptions(request)
			if err != nil {
				t.Fatal(err)
			}
			if options.InvocationID != request.InvocationId || options.Target != target || !options.RequirePostQuantum || options.TargetTLS != nil {
				t.Fatal("invocation replaced its target selection or independent target trust", options)
			}
			if options.Limits != (applicationlimits.Limits{Requests: 7, Concurrency: 2, RateRequests: 3, RatePer: 4 * time.Second, RateBurst: 5}) {
				t.Fatal("invocation lost a supported HTTP budget", options.Limits)
			}
		})
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
	body["limits"] = map[string]any{"rate": map[string]any{"count": 1, "per": "1h"}, "concurrency": 2}
	body["access_mode"] = "anonymous"
	var registration publisherprotocol.Registration
	if err := publisherprotocol.Call(t.Context(), endpoint, "POST", "/v1/publications/register", body, &registration); err != nil {
		t.Fatal(err)
	}
	snapshot := waitInvocation(t, a, func(s publisherapp.Snapshot) bool {
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
	if err := publisherprotocol.Call(t.Context(), endpoint, "POST", "/v1/unregister", registration, nil); err != nil {
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
	a.AttachPublication = func(_ context.Context, _ publisherapp.Service, cfg *publisherservice.RunConfig) error {
		cfg.ServiceID = "invalid"
		return nil
	}
	var registration publisherprotocol.Registration
	if err := publisherprotocol.Call(t.Context(), endpoint, "POST", "/v1/publications/register", body, &registration); err != nil {
		t.Fatal(err)
	}
	waitInvocation(t, a, func(s publisherapp.Snapshot) bool {
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

func TestInvocationFailedDeletionRetainsExactCleanupForRetry(t *testing.T) {
	if !testutil.IsolatedPublishingTest(t) {
		return
	}
	a, endpoint, body, f := invocationRuntime(t)
	transport := http.DefaultTransport
	var failing atomic.Bool
	failing.Store(true)
	var attempts atomic.Int32
	var deleted sync.Map
	http.DefaultTransport = invocationTransport(func(r *http.Request) (*http.Response, error) {
		if r.Method == http.MethodDelete && r.URL.Host == strings.TrimPrefix(f.URL, "https://") && strings.HasPrefix(r.URL.Path, "/v1/publisher/services/") {
			attempts.Add(1)
			deleted.Store(r.URL.Path, true)
			if failing.Load() {
				return &http.Response{StatusCode: 503, Header: http.Header{"Content-Type": {"application/problem+json"}}, Body: io.NopCloser(strings.NewReader(`{"code":"unavailable","message":"retry"}`)), Request: r}, nil
			}
		}
		return transport.RoundTrip(r)
	})
	t.Cleanup(func() { http.DefaultTransport = transport })
	var registration publisherprotocol.Registration
	if err := publisherprotocol.Call(t.Context(), endpoint, "POST", "/v1/publications/register", body, &registration); err != nil {
		t.Fatal(err)
	}
	waitInvocation(t, a, func(s publisherapp.Snapshot) bool {
		for _, service := range s.Services {
			if service.RegistrationID == registration.RegistrationID {
				return service.Routable
			}
		}
		return false
	})
	if err := publisherprotocol.Call(t.Context(), endpoint, "POST", "/v1/unregister", registration, nil); err == nil {
		t.Fatal("failed cleanup was reported as success")
	}
	if _, found := a.manager.ServiceForRegistration(registration.RegistrationID); !found {
		t.Fatal("failed cleanup lost registration ownership")
	}
	failing.Store(false)
	if err := publisherprotocol.Call(t.Context(), endpoint, "POST", "/v1/unregister", registration, nil); err != nil {
		t.Fatal(err)
	}
	if f.Allocations.Load() != 1 || f.Deletions.Load() != 1 || attempts.Load() < 2 {
		t.Fatal("cleanup was not retried", attempts.Load())
	}
	count := 0
	deleted.Range(func(_, _ any) bool { count++; return true })
	if count != 1 {
		t.Fatal("cleanup changed allocation identity")
	}
}

func TestInvocationExpiredOrRevokedCleanupRetiresWithoutRetryingItsCapturedKey(t *testing.T) {
	if !testutil.IsolatedPublishingTest(t) {
		return
	}
	a, _, body, f := invocationRuntime(t)
	transport := f.HTTP.Transport
	var denied atomic.Int32
	var attempts atomic.Int32
	f.HTTP.Transport = invocationTransport(func(r *http.Request) (*http.Response, error) {
		if status := denied.Load(); status != 0 && r.URL.Path == "/v1/publisher-token" {
			attempts.Add(1)
			code := "unauthenticated"
			if status == http.StatusForbidden {
				code = "forbidden"
			}
			return &http.Response{
				StatusCode: int(status), Header: http.Header{"Content-Type": {"application/problem+json"}},
				Body: io.NopCloser(strings.NewReader(fmt.Sprintf(`{"type":"about:blank","title":"publisher authority rejected","code":%q,"status":%d}`, code, status))), Request: r,
			}, nil
		}
		return transport.RoundTrip(r)
	})
	defer func() { f.HTTP.Transport = transport }()
	for _, status := range []int32{http.StatusUnauthorized, http.StatusForbidden} {
		denied.Store(0)
		invocation, err := opaqueid.New(opaqueid.InvocationPrefix)
		if err != nil {
			t.Fatal(err)
		}
		endpoint, err := a.capabilities.Issue(publisherprotocol.CapabilityRequest{Scope: "invocation", InvocationId: &invocation})
		if err != nil {
			t.Fatal(err)
		}
		body["invocation_id"] = invocation
		var registration publisherprotocol.Registration
		if err := publisherprotocol.Call(t.Context(), endpoint, "POST", "/v1/publications/register", body, &registration); err != nil {
			t.Fatal(err)
		}
		waitInvocation(t, a, func(s publisherapp.Snapshot) bool {
			for _, service := range s.Services {
				if service.RegistrationID == registration.RegistrationID {
					return service.Routable
				}
			}
			return false
		})
		before := attempts.Load()
		denied.Store(status)
		var response *publisherprotocol.ResponseError
		err = publisherprotocol.Call(t.Context(), endpoint, "POST", "/v1/unregister", registration, nil)
		if !errors.As(err, &response) || response.Code != "runtime.publication_cleanup_failed" {
			t.Fatal("remote authorization loss was not reported with completed local shutdown", err)
		}
		if _, found := a.manager.ServiceForRegistration(registration.RegistrationID); found {
			t.Fatal("terminal cleanup retained a registration")
		}
		if !errors.Is(a.manager.RetirementError(), publisherapp.ErrCleanupPermanent) {
			t.Fatal("owner retirement lost the remote cleanup failure")
		}
		a.manager.Sweep(func(int) bool { return false })
		if attempts.Load() != before+1 || f.Deletions.Load() != 0 {
			t.Fatal("retirement retried captured authority or bypassed deletion authorization", attempts.Load(), f.Deletions.Load())
		}
	}
}

func TestInvocationCleanupUsesCapturedExpiryWithoutReachingControl(t *testing.T) {
	expired := time.Now().Add(-time.Second)
	cleanup := invocationCleanup(func(context.Context) error { t.Fatal("expired cleanup reached control"); return nil }, expired, nil)
	first := cleanup(t.Context())
	if !errors.Is(first, publisherapp.ErrCleanupPermanent) || !errors.Is(first, auth.ErrDeploymentCredential) {
		t.Fatal("expired authority did not retain a terminal deletion failure", first)
	}
	if again := cleanup(t.Context()); again != first {
		t.Fatal("expired cleanup did not retain its exact terminal outcome", again)
	}
	if err := invocationCleanup(nil, expired, nil)(t.Context()); err != nil {
		t.Fatal("saved publication acquired temporary deletion work", err)
	}
}

func TestInvocationCanceledRegistrationCleansAllocation(t *testing.T) {
	if !testutil.IsolatedPublishingTest(t) {
		return
	}
	a, endpoint, body, f := invocationRuntime(t)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	a.AttachPublication = func(context.Context, publisherapp.Service, *publisherservice.RunConfig) error { cancel(); return nil }
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
	a.AttachPublication = func(context.Context, publisherapp.Service, *publisherservice.RunConfig) error { return setupErr }
	encoded, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	var request publisherprotocol.Invocation
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
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	defer unblock()
	firstID := body["invocation_id"].(string)
	a.AttachPublication = func(_ context.Context, service publisherapp.Service, _ *publisherservice.RunConfig) error {
		if service.Name == firstID {
			close(entered)
			<-release
		}
		return nil
	}
	firstDone := make(chan error, 1)
	go func() {
		firstDone <- publisherprotocol.Call(t.Context(), endpoint, "POST", "/v1/publications/register", body, nil)
	}()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("first preparation never started")
	}
	secondID, _ := opaqueid.New(opaqueid.InvocationPrefix)
	secondEndpoint, err := a.capabilities.Issue(publisherprotocol.CapabilityRequest{Scope: "invocation", InvocationId: &secondID})
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
	var registration publisherprotocol.Registration
	secondErr := publisherprotocol.Call(ctx, secondEndpoint, "POST", "/v1/publications/register", second, &registration)
	unblock()
	if err := <-firstDone; err != nil {
		t.Fatal(err)
	}
	if secondErr != nil {
		t.Fatal("unrelated invocation waited for slow preparation", secondErr)
	}
}

func invocationRequest(t *testing.T, ctx context.Context, endpoint publisherprotocol.Endpoint, body any) *http.Request {
	t.Helper()
	encoded, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("POST", endpoint.Url+"/v1/publications/register", bytes.NewReader(encoded)).WithContext(ctx)
	r.RequestURI = "/v1/publications/register"
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
	a.handler().ServeHTTP(&lostInvocationAck{header: http.Header{}}, invocationRequest(t, t.Context(), endpoint, body))
	if f.Allocations.Load() != 1 || f.Deletions.Load() != 1 {
		t.Fatalf("lost registration acknowledgment leaked allocation: allocations=%d deletions=%d", f.Allocations.Load(), f.Deletions.Load())
	}
}

func TestInvocationLostAllocationReplyCleansOriginalDeclarationAfterCancellation(t *testing.T) {
	if !testutil.IsolatedPublishingTest(t) {
		return
	}
	a, _, body, f := invocationRuntime(t)
	body["limits"] = map[string]any{"total": 7}
	encoded, _ := json.Marshal(body)
	var request publisherprotocol.Invocation
	if err := json.Unmarshal(encoded, &request); err != nil {
		t.Fatal(err)
	}
	originalID, originalPublisher := request.InvocationId, request.PublisherIdentityId
	enrollments := f.Enrollments.Load()
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	transport := f.HTTP.Transport
	var declarations []string
	f.HTTP.Transport = invocationTransport(func(r *http.Request) (*http.Response, error) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/publisher/services" {
			return transport.RoundTrip(r)
		}
		data, err := io.ReadAll(r.Body)
		if err != nil {
			return nil, err
		}
		declarations = append(declarations, string(data))
		r.Body = io.NopCloser(bytes.NewReader(data))
		response, err := transport.RoundTrip(r)
		if err == nil && len(declarations) == 1 {
			_ = response.Body.Close()
			*request.Limits.Total = 99
			request.InvocationId, request.PublisherIdentityId = "changed-invocation", "changed-publisher"
			cancel()
			return nil, io.ErrUnexpectedEOF
		}
		return response, err
	})
	defer func() { f.HTTP.Transport = transport }()
	if _, err := a.invocation(ctx, request); !errors.Is(err, context.Canceled) {
		t.Fatal("allocation lost its request cancellation", err)
	}
	if len(declarations) != 2 || declarations[0] != declarations[1] || f.Allocations.Load() != 1 || f.Deletions.Load() != 1 {
		t.Fatal("uncertain allocation changed its invocation or declaration, or leaked cleanup", declarations, f.Allocations.Load(), f.Deletions.Load())
	}
	var captured controlv1.AllocateServiceRequest
	if err := json.Unmarshal([]byte(declarations[0]), &captured); err != nil {
		t.Fatal(err)
	}
	if originalPublisher == "" || captured.InvocationId != originalID || captured.ExpiresAt != nil ||
		captured.Configuration.Http.Limits.Total == nil || *captured.Configuration.Http.Limits.Total != 7 ||
		captured.Configuration.DomainId != nil || captured.Configuration.Hostname != nil ||
		f.Enrollments.Load() != enrollments || f.Runs.Load() != 0 {
		t.Fatal("shared preparation replaced the original namespace scope, expiry, or declaration")
	}
	if len(a.prepared) != 0 {
		t.Fatal("failed allocation retained a worker preparation")
	}
}

func TestInvocationCleanupKeepsIndependentFailureAndRetries(t *testing.T) {
	problem := errors.New("cleanup unavailable")
	attempts := 0
	cleanup := invocationCleanup(func(context.Context) error {
		attempts++
		if attempts == 1 {
			return errors.Join(context.Canceled, problem)
		}
		return nil
	}, time.Time{}, nil)
	if err := cleanup(t.Context()); !errors.Is(err, context.Canceled) || !errors.Is(err, problem) || errors.Is(err, publisherapp.ErrCleanupPermanent) {
		t.Fatal("cleanup suppressed an independent failure or retired a transient attempt", err)
	}
	if err := cleanup(t.Context()); err != nil || attempts != 2 {
		t.Fatal("cleanup did not retain its original retry", err, attempts)
	}
	if err := cleanup(t.Context()); err != nil || attempts != 2 {
		t.Fatal("confirmed cleanup was not terminal", err, attempts)
	}
}

func TestInvocationExplicitServerSelection(t *testing.T) {
	if !testutil.IsolatedPublishingTest(t) {
		return
	}
	a, endpoint, body, f := invocationRuntime(t)
	t.Setenv("TNL_SERVER", "")
	keyring.MockInit()
	options := Options{Directory: a.project.Root, StateDir: filepath.Join(t.TempDir(), "selection")}
	project, _, err := ResolveProject(t.Context(), options)
	if err != nil {
		t.Fatal(err)
	}
	a.project = project
	var registration publisherprotocol.Registration
	if err := publisherprotocol.Call(t.Context(), endpoint, "POST", "/v1/publications/register", body, &registration); err != nil {
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
	a.project, _, err = ResolveProject(t.Context(), options)
	if err != nil {
		t.Fatal(err)
	}
	// deletion retires the original invocation. use a new invocation to prove
	// server selection again, rather than trying to resurrect its allocation.
	invocation, err := opaqueid.New(opaqueid.InvocationPrefix)
	if err != nil {
		t.Fatal(err)
	}
	body["invocation_id"] = invocation
	endpoint, err = a.capabilities.Issue(publisherprotocol.CapabilityRequest{Scope: "invocation", InvocationId: &invocation})
	if err != nil {
		t.Fatal(err)
	}
	if err := publisherprotocol.Call(t.Context(), endpoint, "POST", "/v1/publications/register", body, &registration); err != nil {
		t.Fatalf("explicit server rejected against saved fallback: %v", err)
	}
	if err := a.manager.Unregister(registration.RegistrationID, registration.Owner); err != nil {
		t.Fatal(err)
	}
	configured := clientserver.DefaultURL
	a.project.Config.Server = &configured
	var request publisherprotocol.Invocation
	encoded, _ := json.Marshal(body)
	_ = json.Unmarshal(encoded, &request)
	if _, err := a.invocation(t.Context(), request); !errors.Is(err, publisheridentity.ErrScope) || f.Allocations.Load() != 2 {
		t.Fatalf("explicit project conflict ignored: err=%v allocations=%d", err, f.Allocations.Load())
	}
	t.Setenv("TNL_SERVER", configured)
	a.project, _, err = ResolveProject(t.Context(), options)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.invocation(t.Context(), request); !errors.Is(err, publisheridentity.ErrScope) || f.Allocations.Load() != 2 {
		t.Fatalf("explicit environment conflict ignored: err=%v allocations=%d", err, f.Allocations.Load())
	}
	// actual configured service names retain their strict SQLite boundary.
	if _, err := a.state.BeginTunnel(t.Context(), clientstate.BeginTunnelOptions{Command: clientstate.TunnelCommandPublish, Server: f.URL, Project: a.project.Root, Target: request.Target, Service: request.InvocationId}); err == nil {
		t.Fatal("invocation key accepted as a configured service name")
	}
}

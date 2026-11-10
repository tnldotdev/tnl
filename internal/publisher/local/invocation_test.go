package local

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
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

	clientauthority "github.com/tnldotdev/tnl/internal/client/authority"
	"github.com/tnldotdev/tnl/internal/client/credentialfile"
	clientserver "github.com/tnldotdev/tnl/internal/client/server"
	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/publisher"
	publisherapp "github.com/tnldotdev/tnl/internal/publisher/app"
	publisheridentity "github.com/tnldotdev/tnl/internal/publisher/identity"
	"github.com/tnldotdev/tnl/internal/publisher/identity/publishingtest"
	publisherprotocol "github.com/tnldotdev/tnl/internal/publisher/localapi/protocol"
	"github.com/tnldotdev/tnl/internal/testutil"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
	"github.com/zalando/go-keyring"
)

// the handler, registration manager, worker and SQLite journal are real. only
// remote control HTTPS and the publisher transport use the existing fixtures.
func invocationRuntime(t *testing.T, hooks ...testutil.PublishingHooks) (*appRuntime, publisherprotocol.Endpoint, map[string]any, *publishingtest.Fixture) {
	t.Helper()
	var selected testutil.PublishingHooks
	if len(hooks) != 0 {
		selected = hooks[0]
	}
	f := publishingtest.New(t, selected)
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
	body := map[string]any{"version": 1, "invocation_id": invocation, "owner": "0123456789abcdef0123456789abcdef", "pid": os.Getpid(), "target": "http://127.0.0.1:3000", "server_url": f.URL, "publisher_identity_id": identity.ClientId}
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

func readyInvocation(ctx context.Context, cfg publisher.Config) error {
	publicURL := cfg.AssignedPublicURL
	for _, event := range []publisher.Event{
		{Type: publisher.EventPublicURLAssigned, PublicURLID: publicURL.Id, Hostname: publicURL.CanonicalHostname},
		{Type: publisher.EventProvisioning, PublishRunNumber: 1},
		{Type: publisher.EventReady, PublishRunNumber: 1, PublicURL: "https://" + publicURL.CanonicalHostname},
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
	var registration publisherprotocol.Registration
	if err := publisherprotocol.Call(t.Context(), endpoint, "POST", "/v1/ad-hoc/register", body, &registration); err != nil {
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
	if allocation := <-allocations; allocation.Limits != nil {
		t.Fatalf("default allocation limits=%+v", allocation.Limits)
	}
	if cfg.Service != "" {
		t.Fatalf("invocation key used as configured service name: %q", cfg.Service)
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
	if err := publisherprotocol.Call(t.Context(), endpoint, "POST", "/v1/ad-hoc/register", body, &repeated); err != nil || repeated != registration || f.Allocations.Load() != 1 {
		t.Fatalf("repeat allocated again: registration=%+v allocations=%d err=%v", repeated, f.Allocations.Load(), err)
	}
	body["limits"] = map[string]any{"requests": 7, "concurrency": 2, "rate": map[string]any{"requests": 3, "per": "4s"}}
	body["require_post_quantum"] = true
	var conflict *publisherprotocol.ResponseError
	if err := publisherprotocol.Call(t.Context(), endpoint, "POST", "/v1/ad-hoc/register", body, nil); !errors.As(err, &conflict) || conflict.Code != "runtime.owner_conflict" {
		t.Fatalf("changed invocation did not conflict: %v", err)
	}
	if err := publisherprotocol.Call(t.Context(), endpoint, "POST", "/v1/unregister", registration, nil); err != nil {
		t.Fatal(err)
	}
	if ids := f.DeletedIDs(); len(ids) != 1 || ids[0] != cfg.AssignedPublicURL.Id {
		t.Fatalf("cleanup did not join exact allocation: %v", ids)
	}
	invocation, _ := opaqueid.New(opaqueid.InvocationPrefix)
	endpoint, _ = a.capabilities.Issue(publisherprotocol.CapabilityRequest{Scope: "invocation", InvocationId: &invocation})
	body["invocation_id"] = invocation
	if err := publisherprotocol.Call(t.Context(), endpoint, "POST", "/v1/ad-hoc/register", body, &registration); err != nil {
		t.Fatalf("supported limits rejected: %v", err)
	}
	select {
	case cfg = <-captured:
		if cfg.RequirePostQuantum == nil || !*cfg.RequirePostQuantum || !cfg.AssignedPublicURL.RequirePostQuantum {
			t.Fatal("native invocation lost the public HTTPS requirement")
		}
		if cfg.Limits != (publisher.ApplicationLimits{Requests: 7, Concurrency: 2, RateRequests: 3, RatePer: 4 * time.Second}) {
			t.Fatalf("worker limits=%+v", cfg.Limits)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("limited invocation did not reach publisher")
	}
	allocation := <-allocations
	if allocation.RequirePostQuantum == nil || !*allocation.RequirePostQuantum {
		t.Fatal("native allocation lost the public HTTPS requirement")
	}
	if allocation.Limits == nil || allocation.Limits.Requests == nil || *allocation.Limits.Requests != 7 || allocation.Limits.Concurrency == nil || *allocation.Limits.Concurrency != 2 || allocation.Limits.Rate == nil || allocation.Limits.Rate.Requests != 3 || allocation.Limits.Rate.Per != "4s" {
		t.Fatalf("allocation lost supported limits: %+v", allocation.Limits)
	}
	if err := publisherprotocol.Call(t.Context(), endpoint, "POST", "/v1/ad-hoc/register", body, &repeated); err != nil || repeated != registration || f.Allocations.Load() != 2 {
		t.Fatalf("limited repeat allocated again: registration=%+v allocations=%d err=%v", repeated, f.Allocations.Load(), err)
	}
}

func applicationInvocation(t *testing.T, hooks ...testutil.PublishingHooks) (*appRuntime, publisherprotocol.Endpoint, map[string]any, *publishingtest.Fixture, credentialfile.File, controlv1.PublicURL) {
	t.Helper()
	a, endpoint, body, fixture := invocationRuntime(t, hooks...)
	url, err := fixture.SavedPublicURL(t.Context(), controlv1.App, "http://127.0.0.1:3000")
	if err != nil {
		t.Fatal(err)
	}
	owner, err := fixture.Owner()
	if err != nil {
		t.Fatal(err)
	}
	enrollment, err := owner.CreatePublisherEnrollment(t.Context(), controlv1.CreatePublisherEnrollmentRequest{TeamId: url.TeamId, PublicUrlId: &url.Id, Name: "application", Kind: "installed"})
	if err != nil {
		t.Fatal(err)
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	authority, err := clientauthority.New(fixture.URL, fixture.HTTP, "")
	if err != nil {
		t.Fatal(err)
	}
	identity, err := authority.RedeemPublisherEnrollment(t.Context(), enrollment.EnrollmentKey, public)
	if err != nil {
		t.Fatal(err)
	}
	file, err := credentialfile.New(fixture.URL, identity, private)
	if err != nil {
		t.Fatal(err)
	}
	file.Grants = append(file.Grants, credentialfile.Grant{ID: "pgrant_" + strings.Repeat("V", 22), Operation: controlv1.ApplicationVisit, Kind: "saved_public_url", PublicURLID: &url.Id})
	document, err := json.Marshal(file)
	if err != nil {
		t.Fatal(err)
	}
	delete(body, "publisher_identity_id")
	body["application_credential"], body["resource_id"] = string(document), url.Id
	return a, endpoint, body, fixture, file, url
}

func TestApplicationInvocationUsesExactPublishGrantWithoutAllocatingOrDeletingSavedURL(t *testing.T) {
	if !testutil.IsolatedPublishingTest(t) {
		return
	}
	a, endpoint, body, fixture, file, url := applicationInvocation(t)
	t.Setenv("TNL_PUBLISHER_CREDENTIAL_FILE", "/private/must-not-read.json")
	personal := "https://personal.example"
	a.project.Config.Server = &personal
	captured := make(chan publisher.Config, 1)
	a.workers.RunPublisher = func(ctx context.Context, cfg publisher.Config) error {
		captured <- cfg
		return readyInvocation(ctx, cfg)
	}
	var registration publisherprotocol.Registration
	if err := publisherprotocol.Call(t.Context(), endpoint, "POST", "/v1/ad-hoc/register", body, &registration); err != nil {
		t.Fatal(err)
	}
	waitInvocation(t, a, func(snapshot publisherapp.Snapshot) bool {
		for _, service := range snapshot.Services {
			if service.RegistrationID == registration.RegistrationID {
				return service.Routable
			}
		}
		return false
	})
	cfg := <-captured
	if cfg.ControlURL != file.ControlURL || cfg.PublisherIdentityID != file.ClientID || cfg.Ephemeral || cfg.AssignedPublicURL == nil || cfg.AssignedPublicURL.Id != url.Id || fixture.Allocations.Load() != 0 {
		t.Fatal("application publication changed its exact URL or borrowed namespace allocation")
	}
	snapshot, err := json.Marshal(a.manager.Snapshot())
	if err != nil || strings.Contains(string(snapshot), file.PrivateKey) || strings.Contains(string(snapshot), "application_credential") {
		t.Fatal("application credential entered public observations", err)
	}
	var again publisherprotocol.Registration
	if err := publisherprotocol.Call(t.Context(), endpoint, "POST", "/v1/ad-hoc/register", body, &again); err != nil || again != registration {
		t.Fatal("exact invocation retry changed publication ownership", err)
	}
	if err := publisherprotocol.Call(t.Context(), endpoint, "POST", "/v1/unregister", registration, nil); err != nil {
		t.Fatal(err)
	}
	if fixture.Allocations.Load() != 0 || fixture.Deletions.Load() != 0 {
		t.Fatal("saved publication cleanup deleted a URL or allocated a replacement")
	}
}

func TestApplicationInvocationRejectsWrongOperationSourceAndResourceWithoutFallback(t *testing.T) {
	if !testutil.IsolatedPublishingTest(t) {
		return
	}
	_, endpoint, body, fixture, original, _ := applicationInvocation(t)
	for _, fault := range []string{"visit", "resource", "key", "server", "mixed", "policy", "empty", "null", "missing resource", "outage"} {
		file := original
		file.Grants = append([]credentialfile.Grant(nil), original.Grants...)
		request := make(map[string]any, len(body))
		for key, value := range body {
			request[key] = value
		}
		want := "runtime.credential_denied"
		switch fault {
		case "visit":
			file.Grants = file.Grants[1:]
		case "resource":
			request["resource_id"] = "url_" + strings.Repeat("X", 22)
		case "key":
			raw, _ := base64.RawURLEncoding.DecodeString(file.PrivateKey)
			raw[63] ^= 1
			file.PrivateKey = base64.RawURLEncoding.EncodeToString(raw)
			want = "runtime.credential_invalid"
		case "server":
			request["server_url"] = "https://another.example"
		case "mixed":
			request["publisher_credential_file"] = "/private/must-not-read.json"
			want = "runtime.credential_invalid"
		case "policy":
			request["access_mode"] = "anonymous"
		case "empty", "null":
			want = "runtime.credential_invalid"
		case "missing resource":
			delete(request, "resource_id")
		case "outage":
			fixture.HTTP.Transport = invocationTransport(func(r *http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: 503, Header: http.Header{"Content-Type": []string{"application/problem+json"}}, Body: io.NopCloser(strings.NewReader(`{"type":"about:blank","title":"unavailable","status":503,"code":"unavailable"}`)), Request: r}, nil
			})
			want = "runtime.credential_unavailable"
		}
		document, err := json.Marshal(file)
		if err != nil {
			t.Fatal(err)
		}
		request["application_credential"] = string(document)
		if fault == "empty" {
			request["application_credential"] = ""
		}
		if fault == "null" {
			request["application_credential"] = nil
		}
		var problem *publisherprotocol.ResponseError
		if err := publisherprotocol.Call(t.Context(), endpoint, "POST", "/v1/ad-hoc/register", request, nil); !errors.As(err, &problem) || problem.Code != want || strings.Contains(err.Error(), file.PrivateKey) {
			t.Fatal("application invocation changed authority or exposed its credential", fault, err)
		}
		if fixture.Allocations.Load() != 0 || fixture.Runs.Load() != 0 || fixture.Deletions.Load() != 0 {
			t.Fatal("rejected application authority created publication side effects")
		}
	}
}

func TestApplicationInvocationRealPublisherKeepsSavedURLAfterDrain(t *testing.T) {
	if !testutil.IsolatedPublishingTest(t) {
		return
	}
	applicationRealPublisher(t, false)
}

func TestApplicationPublicationPreparedRealPublisherKeepsSavedURLAfterDrain(t *testing.T) {
	if !testutil.IsolatedPublishingTest(t) {
		return
	}
	applicationRealPublisher(t, true)
}

func applicationRealPublisher(t *testing.T, prepared bool) {
	t.Helper()
	a, endpoint, body, fixture, _, url := applicationInvocation(t)
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("application bytes")) }))
	defer target.Close()
	body["target"] = target.URL
	var registration publisherprotocol.Registration
	if prepared {
		delete(body, "target")
		var assignment publisherprotocol.PublicationAssignment
		if err := publisherprotocol.Call(t.Context(), endpoint, "POST", "/v1/publications/prepare", body, &assignment); err != nil {
			t.Fatal(err)
		}
		if fixture.Runs.Load() != 0 {
			t.Fatal("preparation started a publish run before listener registration")
		}
		registration = publisherprotocol.Registration{Version: 1, RegistrationID: assignment.RegistrationID, Owner: body["owner"].(string), Target: target.URL}
		if err := publisherprotocol.Call(t.Context(), endpoint, "POST", "/v1/publications/register", registration, nil); err != nil {
			t.Fatal(err)
		}
	} else {
		if err := publisherprotocol.Call(t.Context(), endpoint, "POST", "/v1/ad-hoc/register", body, &registration); err != nil {
			t.Fatal(err)
		}
	}
	waitInvocation(t, a, func(snapshot publisherapp.Snapshot) bool {
		for _, service := range snapshot.Services {
			if service.RegistrationID == registration.RegistrationID {
				if service.Failure != "" {
					t.Fatalf("application publisher failed: %s", service.Failure)
				}
				return service.Routable
			}
		}
		return false
	})
	status, payload, err := fixture.Visit(t.Context(), "https://"+url.CanonicalHostname)
	if err != nil || status != http.StatusOK || string(payload) != "application bytes" {
		t.Fatal("saved application publication did not carry real visitor TLS bytes", status, err)
	}
	if err := publisherprotocol.Call(t.Context(), endpoint, "POST", "/v1/unregister", registration, nil); err != nil {
		t.Fatal(err)
	}
	if fixture.Runs.Load() != 1 || fixture.Allocations.Load() != 0 || fixture.Deletions.Load() != 0 {
		t.Fatal("application publication drain changed the saved URL lifecycle")
	}
}

func TestApplicationPublicationPreparationRegistersBeforeReadinessAndJoinsReplacement(t *testing.T) {
	if !testutil.IsolatedPublishingTest(t) {
		return
	}
	a, endpoint, body, fixture, _, url := applicationInvocation(t)
	delete(body, "target")
	first := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(204) }))
	defer first.Close()
	second := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(204) }))
	defer second.Close()
	started := make(chan string, 2)
	draining := make(chan struct{})
	releaseDrain := sync.OnceFunc(func() { close(draining) })
	defer releaseDrain()
	joined := make(chan struct{})
	var attached atomic.Int32
	a.AttachPublication = func(_ context.Context, service publisherapp.Service, cfg *publisher.Config) error {
		if service.Target == "" || cfg.Target != service.Target {
			t.Fatal("prepared publication attached before its target was bound")
		}
		attached.Add(1)
		return nil
	}
	a.workers.RunPublisher = func(ctx context.Context, cfg publisher.Config) error {
		started <- cfg.Target
		<-ctx.Done()
		if cfg.Target == first.URL {
			<-draining
			close(joined)
		}
		return ctx.Err()
	}
	var assignment publisherprotocol.PublicationAssignment
	if err := publisherprotocol.Call(t.Context(), endpoint, "POST", "/v1/publications/prepare", body, &assignment); err != nil {
		t.Fatal(err)
	}
	if assignment.ResourceId != url.Id || assignment.PublicUrl != "https://"+url.CanonicalHostname || assignment.Hostname != url.CanonicalHostname || attached.Load() != 0 {
		t.Fatal("preparation bound a target or changed its saved resource")
	}
	select {
	case <-started:
		t.Fatal("preparation started a publisher before registration")
	default:
	}
	registration := publisherprotocol.Registration{Version: 1, RegistrationID: assignment.RegistrationID, Owner: body["owner"].(string), Target: first.URL}
	if err := publisherprotocol.Call(t.Context(), endpoint, "POST", "/v1/publications/register", registration, nil); err != nil {
		t.Fatal("registration waited for unreported public readiness", err)
	}
	select {
	case target := <-started:
		if target != first.URL {
			t.Fatal("prepared worker used another target")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("registration did not start its worker")
	}
	service, found := a.manager.ServiceForRegistration(assignment.RegistrationID)
	if !found || !service.Registered || service.Routable {
		t.Fatal("registration acknowledgment claimed public readiness")
	}
	replacement := registration
	replacement.Target = second.URL
	replaced := make(chan error, 1)
	go func() {
		replaced <- publisherprotocol.Call(t.Context(), endpoint, "POST", "/v1/publications/register", replacement, nil)
	}()
	select {
	case err := <-replaced:
		t.Fatal("replacement did not join the previous target", err)
	case <-time.After(20 * time.Millisecond):
	}
	releaseDrain()
	if err := <-replaced; err != nil {
		t.Fatal(err)
	}
	<-joined
	select {
	case target := <-started:
		if target != second.URL {
			t.Fatal("replacement did not bind its own target")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("replacement did not start")
	}
	var again publisherprotocol.PublicationAssignment
	if err := publisherprotocol.Call(t.Context(), endpoint, "POST", "/v1/publications/prepare", body, &again); err != nil || again != assignment {
		t.Fatal("preparation retry replaced the current owner's registration", err)
	}
	var stale *publisherprotocol.ResponseError
	if err := publisherprotocol.Call(t.Context(), endpoint, "POST", "/v1/unregister", registration, nil); !errors.As(err, &stale) || stale.Code != "runtime.registration_stale" {
		t.Fatal("old target cleanup stopped its replacement", err)
	}
	if err := publisherprotocol.Call(t.Context(), endpoint, "POST", "/v1/unregister", replacement, nil); err != nil {
		t.Fatal(err)
	}
	if attached.Load() != 2 || fixture.Allocations.Load() != 0 || fixture.Deletions.Load() != 0 {
		t.Fatal("prepared publication changed saved URL lifecycle or attachment ownership")
	}
}

func TestApplicationPublicationPreparationCanCloseBeforeRegistering(t *testing.T) {
	if !testutil.IsolatedPublishingTest(t) {
		return
	}
	a, endpoint, body, fixture, _, _ := applicationInvocation(t)
	delete(body, "target")
	a.workers.RunPublisher = func(context.Context, publisher.Config) error {
		t.Error("unbound publication started a worker")
		return nil
	}
	var assignment publisherprotocol.PublicationAssignment
	if err := publisherprotocol.Call(t.Context(), endpoint, "POST", "/v1/publications/prepare", body, &assignment); err != nil {
		t.Fatal(err)
	}
	if err := publisherprotocol.Call(t.Context(), endpoint, "POST", "/v1/unregister", publisherprotocol.Registration{Version: 1, RegistrationID: assignment.RegistrationID, Owner: body["owner"].(string)}, nil); err != nil {
		t.Fatal(err)
	}
	if fixture.Runs.Load() != 0 || fixture.Allocations.Load() != 0 || fixture.Deletions.Load() != 0 {
		t.Fatal("closing an unbound preparation changed server publication state")
	}
}

func TestApplicationPublicationPreparationRejectsOtherCapabilitiesAndSiblingRegistration(t *testing.T) {
	if !testutil.IsolatedPublishingTest(t) {
		return
	}
	a, endpoint, body, fixture, _, _ := applicationInvocation(t)
	delete(body, "target")
	if err := publisherprotocol.Call(t.Context(), a.capabilities.Owner(), "POST", "/v1/publications/prepare", body, nil); !errors.Is(err, publisherprotocol.ErrForbidden) {
		t.Fatal("owner capability used invocation-only preparation", err)
	}
	serviceName := "web"
	app, err := a.capabilities.Issue(publisherprotocol.CapabilityRequest{Scope: "app", Service: &serviceName})
	if err != nil {
		t.Fatal(err)
	}
	if err := publisherprotocol.Call(t.Context(), app, "POST", "/v1/publications/prepare", body, nil); !errors.Is(err, publisherprotocol.ErrForbidden) {
		t.Fatal("app capability prepared another publication", err)
	}
	other, err := opaqueid.New(opaqueid.InvocationPrefix)
	if err != nil {
		t.Fatal(err)
	}
	sibling, err := a.capabilities.Issue(publisherprotocol.CapabilityRequest{Scope: "invocation", InvocationId: &other})
	if err != nil {
		t.Fatal(err)
	}
	if err := publisherprotocol.Call(t.Context(), sibling, "POST", "/v1/publications/prepare", body, nil); !errors.Is(err, publisherprotocol.ErrForbidden) {
		t.Fatal("sibling invocation prepared another owner's publication", err)
	}
	var assignment publisherprotocol.PublicationAssignment
	if err := publisherprotocol.Call(t.Context(), endpoint, "POST", "/v1/publications/prepare", body, &assignment); err != nil {
		t.Fatal(err)
	}
	registration := publisherprotocol.Registration{Version: 1, RegistrationID: assignment.RegistrationID, Owner: body["owner"].(string), Target: "http://127.0.0.1:3000"}
	var stale *publisherprotocol.ResponseError
	if err := publisherprotocol.Call(t.Context(), sibling, "POST", "/v1/publications/register", registration, nil); !errors.As(err, &stale) || stale.Code != "runtime.registration_stale" {
		t.Fatal("sibling capability registered another owner's listener", err)
	}
	registration.Target = ""
	if err := publisherprotocol.Call(t.Context(), endpoint, "POST", "/v1/unregister", registration, nil); err != nil {
		t.Fatal(err)
	}
	if fixture.Runs.Load() != 0 || fixture.Allocations.Load() != 0 || fixture.Deletions.Load() != 0 {
		t.Fatal("capability rejection changed publication state")
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
		if err := publisherprotocol.Call(t.Context(), endpoint, "POST", "/v1/ad-hoc/register", body, nil); err == nil || f.Allocations.Load() != 0 {
			t.Fatalf("invalid limits allocated: limits=%v allocations=%d err=%v", invalid, f.Allocations.Load(), err)
		}
	}
	body["limits"] = map[string]any{}
	if err := publisherprotocol.Call(t.Context(), endpoint, "POST", "/v1/ad-hoc/register", body, nil); err != nil {
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
	var registration publisherprotocol.Registration
	if err := publisherprotocol.Call(t.Context(), endpoint, "POST", "/v1/ad-hoc/register", body, &registration); err != nil {
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
	a.AttachPublication = func(_ context.Context, _ publisherapp.Service, cfg *publisher.Config) error {
		cfg.ControlURL = "http://invalid.example"
		return nil
	}
	var registration publisherprotocol.Registration
	if err := publisherprotocol.Call(t.Context(), endpoint, "POST", "/v1/ad-hoc/register", body, &registration); err != nil {
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

func TestInvocationCanceledRegistrationCleansAllocation(t *testing.T) {
	if !testutil.IsolatedPublishingTest(t) {
		return
	}
	a, endpoint, body, f := invocationRuntime(t)
	a.workers.RunPublisher = readyInvocation
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	a.AttachPublication = func(context.Context, publisherapp.Service, *publisher.Config) error { cancel(); return nil }
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
	a.AttachPublication = func(context.Context, publisherapp.Service, *publisher.Config) error { return setupErr }
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
	a.workers.RunPublisher = readyInvocation
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	defer unblock()
	firstID := body["invocation_id"].(string)
	a.AttachPublication = func(_ context.Context, service publisherapp.Service, _ *publisher.Config) error {
		if service.Name == firstID {
			close(entered)
			<-release
		}
		return nil
	}
	firstDone := make(chan error, 1)
	go func() {
		firstDone <- publisherprotocol.Call(t.Context(), endpoint, "POST", "/v1/ad-hoc/register", body, nil)
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
	secondErr := publisherprotocol.Call(ctx, secondEndpoint, "POST", "/v1/ad-hoc/register", second, &registration)
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
	options := Options{Directory: a.project.Root, StateDir: filepath.Join(t.TempDir(), "selection")}
	project, _, err := ResolveProject(t.Context(), options)
	if err != nil {
		t.Fatal(err)
	}
	a.project = project
	a.workers.RunPublisher = readyInvocation
	var registration publisherprotocol.Registration
	if err := publisherprotocol.Call(t.Context(), endpoint, "POST", "/v1/ad-hoc/register", body, &registration); err != nil {
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
	if err := publisherprotocol.Call(t.Context(), endpoint, "POST", "/v1/ad-hoc/register", body, &registration); err != nil {
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

package localapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync/atomic"
	"testing"

	clientcontrol "github.com/tnldotdev/tnl/internal/client/control"
	"github.com/tnldotdev/tnl/internal/client/project/meta"
	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	publisherapp "github.com/tnldotdev/tnl/internal/publisher/app"
	publisheridentity "github.com/tnldotdev/tnl/internal/publisher/identity"
	"github.com/tnldotdev/tnl/internal/publisher/identity/credentialfile"
	publisherprotocol "github.com/tnldotdev/tnl/internal/publisher/localapi/protocol"
)

func TestLostStoppedUnregisterReplyReplaysOnlyItsExactScopedBinding(t *testing.T) {
	testLostUnregisterReply(t, false, true)
}

func TestLostPreparedUnregisterReplyReplaysOnlyItsExactAcceptedTarget(t *testing.T) {
	t.Run("success", func(t *testing.T) { testLostUnregisterReply(t, true, false) })
	t.Run("failure", func(t *testing.T) { testLostUnregisterReply(t, true, true) })
}

func testLostUnregisterReply(t *testing.T, prepared, permanent bool) {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	database, err := clientstate.OpenWithOptions(t.Context(), filepath.Join(t.TempDir(), "state"), clientstate.OpenOptions{Protection: clientstate.ProtectionFile})
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	manager, err := publisherapp.New(t.Context(), root, database, []publisherapp.Service{{Name: "web"}, {Name: "api"}}, func(ctx context.Context, _ publisherapp.Service, _ func(uint64, bool) error) error {
		<-ctx.Done()
		return ctx.Err()
	})
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	var cleanup atomic.Int32
	manager.Cleanup = func(service publisherapp.Service) error {
		cleanup.Add(1)
		if prepared && (service.Target != "" || service.Registered) {
			t.Error("prepared-only cleanup acquired a listener target")
		}
		if !permanent {
			return nil
		}
		return errors.Join(publisherapp.ErrCleanupPermanent, errors.New("remote deletion denied"))
	}
	server := httptest.NewUnstartedServer(nil)
	caps, err := publisherprotocol.NewCapabilities("http://" + server.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	web, api := "web", "api"
	endpoint, err := caps.Issue(publisherprotocol.CapabilityRequest{Scope: "app", Service: &web})
	if err != nil {
		t.Fatal(err)
	}
	other, err := caps.Issue(publisherprotocol.CapabilityRequest{Scope: "app", Service: &api})
	if err != nil {
		t.Fatal(err)
	}
	boundary := (&Server{Capabilities: caps, Manager: manager, Prepare: func(_ context.Context, request publisherprotocol.Prepare) (publisherprotocol.Assignment, error) {
		id, err := manager.Reserve(request.Service, request.Owner, request.PID, "")
		return publisherprotocol.Assignment{
			Version: 1, RegistrationID: id, Service: request.Service,
			Project: (meta.Metadata{Version: meta.Version, Services: map[string]meta.Service{}}).Public(true),
		}, err
	}}).Handler()
	var dropped atomic.Bool
	server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/unregister" || dropped.Swap(true) {
			boundary.ServeHTTP(w, r)
			return
		}
		reply := httptest.NewRecorder()
		boundary.ServeHTTP(reply, r)
		expected := http.StatusNoContent
		if permanent {
			expected = http.StatusConflict
		}
		if reply.Code != expected {
			t.Error("wrong completed cleanup acknowledgment", reply.Code)
		}
		connection, _, err := w.(http.Hijacker).Hijack()
		if err != nil {
			t.Error(err)
			return
		}
		_ = connection.Close()
	})
	server.Start()
	defer server.Close()
	owner := "0123456789abcdef0123456789abcdef"
	var id string
	if prepared {
		var assignment publisherprotocol.Assignment
		if err := publisherprotocol.Call(t.Context(), endpoint, "POST", "/v1/prepare", publisherprotocol.Prepare{
			Version: 1, Directory: root, Service: "web", Framework: "python", Owner: owner, PID: 1,
		}, &assignment); err != nil {
			t.Fatal(err)
		}
		if assignment.PublicURL != "" {
			t.Fatal("private HTTP preparation invented a public URL")
		}
		id = assignment.RegistrationID
	} else {
		id, err = manager.Reserve("web", owner, 1, "")
		if err != nil {
			t.Fatal(err)
		}
	}
	registration := publisherprotocol.Registration{Version: 1, RegistrationID: id, Owner: owner, Target: "http://127.0.0.1:3000"}
	if !prepared {
		if err := manager.Register(id, owner, registration.Target, "node"); err != nil {
			t.Fatal(err)
		}
	}
	if err := publisherprotocol.Call(t.Context(), endpoint, "POST", "/v1/unregister", registration, nil); err == nil {
		t.Fatal("fixture did not drop the terminal cleanup acknowledgment")
	}
	if _, found := manager.ServiceForRegistration(id); found {
		t.Fatal("terminal acknowledgment retained a live registration")
	}
	replayCode := ""
	if permanent {
		replayCode = "runtime.publication_cleanup_failed"
	}
	for _, test := range []struct {
		endpoint publisherprotocol.Endpoint
		body     publisherprotocol.Registration
		code     string
	}{
		{endpoint, registration, replayCode},
		{other, registration, "runtime.registration_stale"},
		{endpoint, publisherprotocol.Registration{Version: 1, RegistrationID: id, Owner: "fedcba9876543210fedcba9876543210", Target: registration.Target}, "runtime.registration_stale"},
		{endpoint, publisherprotocol.Registration{Version: 1, RegistrationID: id, Owner: owner, Target: "http://127.0.0.1:4000"}, "runtime.registration_stale"},
		{endpoint, publisherprotocol.Registration{Version: 1, RegistrationID: "reg_00000000000000000000000000000000", Owner: owner, Target: registration.Target}, "runtime.registration_stale"},
		{endpoint, registration, replayCode},
	} {
		var response *publisherprotocol.ResponseError
		err := publisherprotocol.Call(t.Context(), test.endpoint, "POST", "/v1/unregister", test.body, nil)
		if test.code == "" && err == nil {
			continue
		}
		if !errors.As(err, &response) || response.Code != test.code {
			t.Fatal("unregister outcome crossed its scope or lost the cleanup failure", response, err)
		}
	}
	if cleanup.Load() != 1 {
		t.Fatal("replay repeated completed cleanup", cleanup.Load())
	}
}

func TestStoppedPublicationCleanupFailureDoesNotClaimSuccessOrAuthenticationRecovery(t *testing.T) {
	cleanup := errors.New("remote deletion failed")
	for _, cause := range []error{clientcontrol.ErrUnauthenticated, publisherapp.ErrRegistrationStale} {
		recorder := httptest.NewRecorder()
		Problem(recorder, errors.Join(publisherapp.ErrRegistrationStopped, cause, cleanup))
		var problem publisherprotocol.Problem
		if err := json.Unmarshal(recorder.Body.Bytes(), &problem); err != nil {
			t.Fatal(err)
		}
		if recorder.Code != http.StatusConflict || problem.Code != "runtime.publication_cleanup_failed" {
			t.Fatal("joined cleanup failure lost its stopped outcome", recorder.Code, problem)
		}
	}
}

func TestAppCapabilityCannotReplaceAnotherServiceOrSubmitReadiness(t *testing.T) {
	root, _ := filepath.EvalSymlinks(t.TempDir())
	database, err := clientstate.OpenWithOptions(t.Context(), filepath.Join(t.TempDir(), "state"), clientstate.OpenOptions{Protection: clientstate.ProtectionFile})
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	manager, err := publisherapp.New(t.Context(), root, database, []publisherapp.Service{{Name: "web"}, {Name: "api"}}, func(ctx context.Context, _ publisherapp.Service, _ func(uint64, bool) error) error {
		<-ctx.Done()
		return ctx.Err()
	})
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	server := httptest.NewUnstartedServer(nil)
	capabilities, err := publisherprotocol.NewCapabilities("http://" + server.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	boundary := &Server{Capabilities: capabilities, Manager: manager, Database: database, Project: root, AppService: func(name string) bool { return name == "web" || name == "api" }}
	server.Config.Handler = boundary.Handler()
	server.Start()
	defer server.Close()
	name := "web"
	var app publisherprotocol.Endpoint
	if err := publisherprotocol.Call(t.Context(), capabilities.Owner(), "POST", "/v1/capabilities", publisherprotocol.CapabilityRequest{Scope: "app", Service: &name}, &app); err != nil {
		t.Fatal(err)
	}
	owner := "0123456789abcdef0123456789abcdef"
	id, err := manager.Reserve("api", owner, 1, "https://api.example")
	if err != nil {
		t.Fatal(err)
	}
	registration := publisherprotocol.Registration{Version: 1, RegistrationID: id, Owner: owner, Target: "http://127.0.0.1:3000"}
	if err := publisherprotocol.Call(t.Context(), app, "POST", "/v1/register", registration, nil); err == nil {
		t.Fatal("app capability replaced another service")
	}
	if err := publisherprotocol.Call(t.Context(), app, "POST", "/v1/check", publisherprotocol.Check{}, nil); !errors.Is(err, publisherprotocol.ErrForbidden) {
		t.Fatalf("app checked readiness: %v", err)
	}
	if err := publisherprotocol.Call(t.Context(), capabilities.Owner(), "POST", "/v1/observe", publisherapp.Observation{Ready: true}, nil); err == nil {
		t.Fatal("client authored readiness was accepted")
	}
	var snapshot publisherapp.Snapshot
	if err := publisherprotocol.Call(t.Context(), app, "GET", "/v1/status", nil, &snapshot); err != nil || len(snapshot.Services) != 1 || snapshot.Services[0].Name != "web" {
		t.Fatalf("scoped snapshot=%+v err=%v", snapshot.Services, err)
	}
}

func TestNamedLeaseClientReacquiresAfterOwnerReplacement(t *testing.T) {
	var acquired, renewed, closed atomic.Int32
	makeOwner := func() publisherprotocol.Endpoint {
		server := httptest.NewUnstartedServer(nil)
		capabilities, err := publisherprotocol.NewCapabilities("http://" + server.Listener.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		mux := http.NewServeMux()
		mux.HandleFunc("POST /v1/leases", func(w http.ResponseWriter, r *http.Request) {
			var request publisherprotocol.Lease
			if err := publisherprotocol.Decode(w, r, &request); err != nil {
				t.Error(err)
				w.WriteHeader(400)
				return
			}
			acquired.Add(1)
			publisherprotocol.Write(w, 200, publisherprotocol.Registration{Version: 1, RegistrationID: "reg_" + capabilities.Owner().OwnerId, Owner: request.Owner, Target: "127.0.0.1:5432"})
		})
		mux.HandleFunc("POST /v1/renew", func(w http.ResponseWriter, r *http.Request) { renewed.Add(1); w.WriteHeader(204) })
		mux.HandleFunc("POST /v1/unregister", func(w http.ResponseWriter, r *http.Request) { closed.Add(1); w.WriteHeader(204) })
		server.Config.Handler = capabilities.Handler(mux)
		server.Start()
		t.Cleanup(server.Close)
		return capabilities.Owner()
	}
	endpoint := makeOwner()
	client := &LeaseClient{Resolve: func(context.Context) (publisherprotocol.Endpoint, error) { return endpoint, nil }, Request: publisherprotocol.Lease{Service: "db", Owner: "0123456789abcdef0123456789abcdef", Pid: 1}}
	_, first, err := client.Renew(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := client.Renew(t.Context()); err != nil {
		t.Fatal(err)
	}
	endpoint = makeOwner()
	_, next, err := client.Renew(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if first.RegistrationID == next.RegistrationID || acquired.Load() != 2 || renewed.Load() != 1 {
		t.Fatal("replacement owner did not receive a fresh lease")
	}
	if err := client.Close(t.Context()); err != nil {
		t.Fatal(err)
	}
	if closed.Load() != 1 {
		t.Fatal("current lease was not stopped")
	}
}

func TestAdHocRegisterAcceptsDefaultOrOneExplicitPublisher(t *testing.T) {
	server := httptest.NewUnstartedServer(nil)
	caps, err := publisherprotocol.NewCapabilities("http://" + server.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	id, err := opaqueid.New(opaqueid.InvocationPrefix)
	if err != nil {
		t.Fatal(err)
	}
	endpoint, err := caps.Issue(publisherprotocol.CapabilityRequest{Scope: "invocation", InvocationId: &id})
	if err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int32
	server.Config.Handler = (&Server{Capabilities: caps, Invocation: func(_ context.Context, request publisherprotocol.Invocation) (publisherprotocol.Registration, error) {
		calls.Add(1)
		if request.PublisherCredentialFile == "/private/missing.json" {
			return publisherprotocol.Registration{}, credentialfile.ErrInvalid
		}
		if request.PublisherCredentialFile == "" && request.PublisherIdentityId == "" {
			return publisherprotocol.Registration{}, publisheridentity.ErrSetupRequired
		}
		return publisherprotocol.Registration{Version: 1}, nil
	}}).Handler()
	server.Start()
	defer server.Close()
	request := publisherprotocol.Invocation{Version: 1, InvocationId: id, Owner: "0123456789abcdef0123456789abcdef", Pid: 1, Target: "http://127.0.0.1:3000"}
	for _, test := range []struct{ file, id, code string }{
		{"", "", "runtime.publisher_setup_required"},
		{"/private/missing.json", "", "runtime.publisher_credential_file_invalid"},
		{"/private/publisher.json", "", ""},
		{"", "pub_0123456789abcdefghijkl", ""},
		{"/private/publisher.json", "pub_0123456789abcdefghijkl", "runtime.forbidden"},
		{"relative/publisher.json", "", "runtime.publisher_credential_file_invalid"},
	} {
		request.PublisherCredentialFile, request.PublisherIdentityId = test.file, test.id
		err := publisherprotocol.Call(t.Context(), endpoint, "POST", "/v1/publications/register", request, nil)
		if test.code == "" && err != nil {
			t.Fatalf("file=%q id=%q: %v", test.file, test.id, err)
		}
		if test.code != "" {
			if errors.Is(err, publisherprotocol.ErrForbidden) && test.code == "runtime.forbidden" {
				continue
			}
			var response *publisherprotocol.ResponseError
			if !errors.As(err, &response) || response.Code != test.code {
				t.Fatalf("file=%q id=%q: got %v, want %s", test.file, test.id, err, test.code)
			}
		}
	}
	if calls.Load() != 4 {
		t.Fatalf("invalid selections reached the invocation: %d", calls.Load())
	}
	var retired *publisherprotocol.ResponseError
	if err := publisherprotocol.Call(t.Context(), endpoint, "POST", "/v1/ad-hoc/register", request, nil); !errors.As(err, &retired) || retired.Status != 404 {
		t.Fatalf("retired registration endpoint is still served: %v", err)
	}
	legacy := map[string]any{"version": 1, "invocation_id": id, "owner": request.Owner, "pid": 1, "target": request.Target, "enrollment_key": "old-secret"}
	var response *publisherprotocol.ResponseError
	if err := publisherprotocol.Call(t.Context(), endpoint, "POST", "/v1/publications/register", legacy, nil); !errors.As(err, &response) || response.Code != "runtime.request_invalid" || calls.Load() != 4 {
		t.Fatalf("legacy enrollment key reached the native publisher: %v", err)
	}
}

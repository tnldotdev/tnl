package localpublisher

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/tnldotdev/tnl/internal/clientruntime"
	"github.com/tnldotdev/tnl/internal/clientstate"
	"github.com/tnldotdev/tnl/internal/opaqueid"
	"github.com/tnldotdev/tnl/internal/privateprotocol"
	"github.com/tnldotdev/tnl/internal/publisheridentity/credentialfile"
	nativeauth "github.com/tnldotdev/tnl/internal/publisheridentity/native"
)

func TestAppCapabilityCannotReplaceAnotherServiceOrSubmitReadiness(t *testing.T) {
	root, _ := filepath.EvalSymlinks(t.TempDir())
	database, err := clientstate.OpenWithOptions(t.Context(), filepath.Join(t.TempDir(), "state"), clientstate.OpenOptions{Protection: clientstate.ProtectionFile})
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	manager, err := clientruntime.New(t.Context(), root, database, []clientruntime.Service{{Name: "web"}, {Name: "api"}}, func(ctx context.Context, _ clientruntime.Service, _ func(uint64, bool) error) error {
		<-ctx.Done()
		return ctx.Err()
	})
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	server := httptest.NewUnstartedServer(nil)
	capabilities, err := privateprotocol.NewCapabilities("http://" + server.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	boundary := &Server{Capabilities: capabilities, Manager: manager, Database: database, Project: root, AppService: func(name string) bool { return name == "web" || name == "api" }}
	server.Config.Handler = boundary.Handler()
	server.Start()
	defer server.Close()
	name := "web"
	var app privateprotocol.Endpoint
	if err := privateprotocol.Call(t.Context(), capabilities.Owner(), "POST", "/v1/capabilities", privateprotocol.CapabilityRequest{Scope: "app", Service: &name}, &app); err != nil {
		t.Fatal(err)
	}
	owner := "0123456789abcdef0123456789abcdef"
	id, err := manager.Reserve("api", owner, 1, "https://api.example")
	if err != nil {
		t.Fatal(err)
	}
	registration := privateprotocol.Registration{Version: 1, RegistrationID: id, Owner: owner, Target: "http://127.0.0.1:3000"}
	if err := privateprotocol.Call(t.Context(), app, "POST", "/v1/register", registration, nil); err == nil {
		t.Fatal("app capability replaced another service")
	}
	if err := privateprotocol.Call(t.Context(), app, "POST", "/v1/check", privateprotocol.Check{}, nil); !errors.Is(err, privateprotocol.ErrForbidden) {
		t.Fatalf("app checked readiness: %v", err)
	}
	if err := privateprotocol.Call(t.Context(), capabilities.Owner(), "POST", "/v1/observe", clientruntime.Observation{Ready: true}, nil); err == nil {
		t.Fatal("client authored readiness was accepted")
	}
	var snapshot clientruntime.Snapshot
	if err := privateprotocol.Call(t.Context(), app, "GET", "/v1/status", nil, &snapshot); err != nil || len(snapshot.Services) != 1 || snapshot.Services[0].Name != "web" {
		t.Fatalf("scoped snapshot=%+v err=%v", snapshot.Services, err)
	}
}

func TestNamedLeaseClientReacquiresAfterOwnerReplacement(t *testing.T) {
	var acquired, renewed, closed atomic.Int32
	makeOwner := func() privateprotocol.Endpoint {
		server := httptest.NewUnstartedServer(nil)
		capabilities, err := privateprotocol.NewCapabilities("http://" + server.Listener.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		mux := http.NewServeMux()
		mux.HandleFunc("POST /v1/leases", func(w http.ResponseWriter, r *http.Request) {
			var request privateprotocol.Lease
			if err := privateprotocol.Decode(w, r, &request); err != nil {
				t.Error(err)
				w.WriteHeader(400)
				return
			}
			acquired.Add(1)
			privateprotocol.Write(w, 200, privateprotocol.Registration{Version: 1, RegistrationID: "reg_" + capabilities.Owner().OwnerId, Owner: request.Owner, Target: "127.0.0.1:5432"})
		})
		mux.HandleFunc("POST /v1/renew", func(w http.ResponseWriter, r *http.Request) { renewed.Add(1); w.WriteHeader(204) })
		mux.HandleFunc("POST /v1/unregister", func(w http.ResponseWriter, r *http.Request) { closed.Add(1); w.WriteHeader(204) })
		server.Config.Handler = capabilities.Handler(mux)
		server.Start()
		t.Cleanup(server.Close)
		return capabilities.Owner()
	}
	endpoint := makeOwner()
	client := &LeaseClient{Resolve: func(context.Context) (privateprotocol.Endpoint, error) { return endpoint, nil }, Request: privateprotocol.Lease{Service: "db", Owner: "0123456789abcdef0123456789abcdef", Pid: 1}}
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
	caps, err := privateprotocol.NewCapabilities("http://" + server.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	id, err := opaqueid.New(opaqueid.InvocationPrefix)
	if err != nil {
		t.Fatal(err)
	}
	endpoint, err := caps.Issue(privateprotocol.CapabilityRequest{Scope: "invocation", InvocationId: &id})
	if err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int32
	server.Config.Handler = (&Server{Capabilities: caps, Invocation: func(_ context.Context, request privateprotocol.Invocation) (privateprotocol.Registration, error) {
		calls.Add(1)
		if request.PublisherFile == "/private/missing.json" {
			return privateprotocol.Registration{}, credentialfile.ErrInvalid
		}
		if request.PublisherFile == "" && request.PublisherId == "" {
			return privateprotocol.Registration{}, nativeauth.ErrSetupRequired
		}
		return privateprotocol.Registration{Version: 1}, nil
	}}).Handler()
	server.Start()
	defer server.Close()
	request := privateprotocol.Invocation{Version: 1, InvocationId: id, Owner: "0123456789abcdef0123456789abcdef", Pid: 1, Target: "http://127.0.0.1:3000"}
	for _, test := range []struct{ file, id, code string }{
		{"", "", "runtime.publisher_setup_required"},
		{"/private/missing.json", "", "runtime.publisher_file_invalid"},
		{"/private/publisher.json", "", ""},
		{"", "pub_0123456789abcdefghijkl", ""},
		{"/private/publisher.json", "pub_0123456789abcdefghijkl", "runtime.forbidden"},
		{"relative/publisher.json", "", "runtime.publisher_file_invalid"},
	} {
		request.PublisherFile, request.PublisherId = test.file, test.id
		err := privateprotocol.Call(t.Context(), endpoint, "POST", "/v1/ad-hoc/register", request, nil)
		if test.code == "" && err != nil {
			t.Fatalf("file=%q id=%q: %v", test.file, test.id, err)
		}
		if test.code != "" {
			if errors.Is(err, privateprotocol.ErrForbidden) && test.code == "runtime.forbidden" {
				continue
			}
			var response *privateprotocol.ResponseError
			if !errors.As(err, &response) || response.Code != test.code {
				t.Fatalf("file=%q id=%q: got %v, want %s", test.file, test.id, err, test.code)
			}
		}
	}
	if calls.Load() != 4 {
		t.Fatalf("invalid selections reached the invocation: %d", calls.Load())
	}
	legacy := map[string]any{"version": 1, "invocation_id": id, "owner": request.Owner, "pid": 1, "target": request.Target, "enrollment_key": "old-secret"}
	var response *privateprotocol.ResponseError
	if err := privateprotocol.Call(t.Context(), endpoint, "POST", "/v1/ad-hoc/register", legacy, nil); !errors.As(err, &response) || response.Code != "runtime.request_invalid" || calls.Load() != 4 {
		t.Fatalf("legacy enrollment key reached the native publisher: %v", err)
	}
}

package local

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/client/filelock"
	clientproject "github.com/tnldotdev/tnl/internal/client/project"
	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/observability"
	"github.com/tnldotdev/tnl/internal/publisher/app"
	publisherprotocol "github.com/tnldotdev/tnl/internal/publisher/localapi/protocol"
	"github.com/tnldotdev/tnl/internal/security/credentials"
	authorityv1 "github.com/tnldotdev/tnl/pkg/api/control/authority/v1"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func processFixture(t *testing.T) (clientproject.Project, *clientstate.Database, []byte, string) {
	t.Helper()
	clientstate.UseMemoryKeychainForTesting()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	project := clientproject.Project{Root: root, Config: config.TNL{Services: config.Services{"web": {}}}}
	state, err := clientstate.Open(t.Context(), filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = state.Close() })
	project, err = project.BindLocalIdentity(t.Context(), state)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, _, err := project.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	path, err := publisherprotocol.DescriptorPath(state.Root(), project.Root)
	if err != nil {
		t.Fatal(err)
	}
	return project, state, snapshot, path
}

func startProcess(t *testing.T, project clientproject.Project, state *clientstate.Database, snapshot []byte, path string) (publisherprotocol.Endpoint, func() error) {
	t.Helper()
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() {
		done <- Serve(ctx, Options{Directory: project.Root, StateDir: state.Root(), Snapshot: bytes.NewReader(snapshot)})
	}()
	stop := sync.OnceValue(func() error {
		cancel()
		select {
		case err := <-done:
			return err
		case <-time.After(5 * time.Second):
			return errors.New("local publisher did not join shutdown")
		}
	})
	t.Cleanup(func() {
		if err := stop(); err != nil {
			t.Error(err)
		}
	})
	wait, finish := context.WithTimeout(t.Context(), 5*time.Second)
	defer finish()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		if endpoint, err := publisherprotocol.ReadEndpoint(path); err == nil && Available(wait, endpoint) {
			return endpoint, stop
		}
		select {
		case err := <-done:
			done <- err
			t.Fatalf("local publisher exited before publishing its descriptor: %v", err)
		case <-wait.Done():
			t.Fatal("local publisher did not publish a healthy descriptor")
		case <-ticker.C:
		}
	}
}

func assertProcessStopped(t *testing.T, state *clientstate.Database, project clientproject.Project, cursor string) {
	t.Helper()
	snapshot, err := app.ReadSnapshotFrom(t.Context(), state, project.Root)
	if err != nil {
		t.Fatal(err)
	}
	events, err := app.EventsAfterFrom(t.Context(), state, project.Root, cursor)
	if err != nil || len(events) == 0 || events[len(events)-1].Type != "runtime.stopped" {
		t.Fatalf("shutdown did not finish the manager journal: %+v, %v", events, err)
	}
	for _, service := range snapshot.Services {
		if service.RegistrationID != "" || service.Registered || service.Routable || service.Ready {
			t.Fatalf("shutdown retained a live registration: %+v", service)
		}
	}
}

func TestAppWorkflowProcessShutdownReleasesOwnershipAndPendingRegistration(t *testing.T) {
	project, state, _, path := processFixture(t)
	const hostname = "web.developer.example.test"
	token, _, _, err := credentials.NewAccessToken()
	if err != nil {
		t.Fatal(err)
	}
	// pending preparation now realizes the selected private service. this
	// control boundary must not receive publication or publisher enrollment.
	control := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path != "/v1/discovery" && r.Header.Get("Authorization") != "Bearer "+token.String() {
			t.Error("pending preparation lost its control credential")
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		var response any
		switch r.Method + " " + r.URL.Path {
		case "GET /v1/discovery":
			response = controlv1.ControlDiscovery{ManagedUrlMode: "simple", Authentication: controlv1.AuthenticationFacts{
				Methods: []controlv1.AuthenticationFactsMethods{controlv1.Oidc},
				Oidc:    &controlv1.OIDCAuthenticationFacts{Issuer: "https://identity.example", LoginFlow: controlv1.DeviceCode},
			}}
		case "GET /v1/identity":
			response = authorityv1.IdentityContext{PersonalTeamId: "team_1", Memberships: []authorityv1.Membership{
				{TeamId: "team_1", MemberSlug: "developer", ManagedLabel: "developer"},
			}}
		case "GET /v1/teams/team_1":
			response = authorityv1.Team{Id: "team_1", DisplayName: "developer", Kind: authorityv1.Personal, DefaultDomainId: "domain_1", ManagedLabel: "developer"}
		case "GET /v1/teams/team_1/domains":
			response = authorityv1.DomainPage{Domains: []authorityv1.Domain{
				{Id: "domain_1", CanonicalDomain: "example.test", Kind: authorityv1.Managed, State: authorityv1.DomainStateReady},
			}}
		case "PUT /v1/projects/" + project.LocalPublicationIdentity().Key + "/local-services/web":
			var request controlv1.RealizeLocalProjectServiceRequest
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
				t.Error(err)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			if request.TeamId != "team_1" || request.SourceFingerprint != project.LocalPublicationIdentity().Fingerprint ||
				request.WorktreeKey != project.LocalWorktreeKey() ||
				request.Configuration.Name == nil || *request.Configuration.Name != "web" ||
				request.Configuration.Protocol == nil || *request.Configuration.Protocol != controlv1.ServiceProtocolHTTP ||
				request.Configuration.Target != "app" || request.Configuration.Public != nil && *request.Configuration.Public {
				t.Error("pending preparation changed its private app declaration")
			}
			response = controlv1.LocalProjectService{Service: "web", WorktreeKey: request.WorktreeKey, ServiceId: "svc_0123456789abcdefghijkl",
				Hostname: new(hostname),
				Metadata: &controlv1.ServiceMetadata{Protocol: controlv1.ServiceProtocolHTTP, TrustRevision: 1,
					Endpoint: &controlv1.ServiceEndpoint{Hostname: hostname, Port: 443, Public: false}}}
		default:
			t.Errorf("pending preparation requested unrelated work: %s %s", r.Method, r.URL)
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if err := json.NewEncoder(w).Encode(response); err != nil {
			t.Error(err)
		}
	}))
	t.Cleanup(control.Close)
	project.Config.Server = &control.URL
	t.Setenv("TNL_SERVER", control.URL)
	t.Setenv("TNL_ACCESS_TOKEN", token.String())
	original := http.DefaultTransport
	http.DefaultTransport = control.Client().Transport
	t.Cleanup(func() { http.DefaultTransport = original })
	snapshot, _, err := project.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	initial, err := app.ReadSnapshotFrom(t.Context(), state, project.Root)
	if err != nil {
		t.Fatal(err)
	}
	endpoint, stop := startProcess(t, project, state, snapshot, path)
	_, digest, err := project.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if err := publisherprotocol.Call(t.Context(), endpoint, "GET", "/v1/health?configuration_digest="+digest, nil, nil); err != nil {
		t.Fatal(err)
	}
	name := "web"
	var scoped publisherprotocol.Endpoint
	if err := publisherprotocol.Call(t.Context(), endpoint, "POST", "/v1/capabilities", publisherprotocol.CapabilityRequest{Scope: "app", Service: &name}, &scoped); err != nil {
		t.Fatal(err)
	}
	var assignment publisherprotocol.Assignment
	if err := publisherprotocol.Call(t.Context(), scoped, "POST", "/v1/prepare", publisherprotocol.Prepare{Version: 1, Directory: project.Root, Service: name, Owner: strings.Repeat("a", 32), PID: os.Getpid(), Framework: publisherprotocol.FrameworkNode}, &assignment); err != nil {
		t.Fatal(err)
	}
	selected := assignment.Project.Services[name]
	if assignment.RegistrationID == "" || assignment.Service != name || assignment.Hostname != hostname ||
		assignment.PublicURL != "" || len(assignment.Project.Services) != 1 || !assignment.Project.Dev ||
		selected.Protocol != "http" || selected.Namespace != "developer.example.test" || selected.Hostname != hostname ||
		selected.URL != "https://"+hostname || selected.Port != 443 || selected.Public {
		t.Fatalf("process did not prepare its configured app: %+v", assignment)
	}
	var pending app.Snapshot
	if err := publisherprotocol.Call(t.Context(), scoped, "GET", "/v1/status", nil, &pending); err != nil {
		t.Fatal(err)
	}
	if len(pending.Services) != 1 || pending.Services[0].RegistrationID != assignment.RegistrationID ||
		pending.Services[0].Registered || pending.Services[0].Routable || pending.Services[0].Ready ||
		pending.Services[0].RunNumber != 0 || pending.Services[0].PublicURL != "" {
		t.Fatalf("process did not retain exactly its pending private reservation: %+v", pending.Services)
	}
	contender, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	if err := Serve(contender, Options{Directory: project.Root, StateDir: state.Root(), Snapshot: bytes.NewReader(snapshot)}); err != nil {
		t.Fatal(err)
	}
	current, err := publisherprotocol.ReadEndpoint(path)
	if err != nil || current.OwnerId != endpoint.OwnerId {
		t.Fatalf("competing owner replaced the live descriptor: %+v, %v", current, err)
	}
	if err := stop(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("shutdown retained its descriptor: %v", err)
	}
	if Available(t.Context(), endpoint) {
		t.Fatal("shutdown retained its HTTP listener")
	}
	lock, err := filelock.Acquire(path+".lock", filelock.Nonblocking, os.Geteuid())
	if err != nil {
		t.Fatalf("joined shutdown retained its ownership lock: %v", err)
	}
	if err := lock.Close(); err != nil {
		t.Fatal(err)
	}
	assertProcessStopped(t, state, project, initial.Cursor)
	replacement, stopReplacement := startProcess(t, project, state, snapshot, path)
	if replacement.OwnerId == endpoint.OwnerId || replacement.Capability == endpoint.Capability {
		t.Fatal("replacement owner reused the old capability identity")
	}
	if err := stopReplacement(); err != nil {
		t.Fatal(err)
	}
}

func TestAppWorkflowProcessStartupFailureReleasesLockAndStopsManager(t *testing.T) {
	project, state, snapshot, path := processFixture(t)
	initial, err := app.ReadSnapshotFrom(t.Context(), state, project.Root)
	if err != nil {
		t.Fatal(err)
	}
	// a preexisting directory forces descriptor installation to fail after the
	// listener and manager have been constructed.
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	var recorded time.Time
	ctx = observability.WithShutdownDeadline(ctx, func(until time.Time) time.Time {
		recorded = until
		return until
	})
	if err := Serve(ctx, Options{Directory: project.Root, StateDir: state.Root(), Snapshot: bytes.NewReader(snapshot)}); err == nil {
		t.Fatal("startup accepted an unusable descriptor path")
	}
	if parent, _ := ctx.Deadline(); !recorded.Equal(parent) {
		t.Fatal("local process did not hand its earlier parent stop budget to final flushing", recorded, parent)
	}
	assertProcessStopped(t, state, project, initial.Cursor)
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	_, stop := startProcess(t, project, state, snapshot, path)
	if err := stop(); err != nil {
		t.Fatal(err)
	}
}

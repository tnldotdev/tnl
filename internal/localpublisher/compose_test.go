package localpublisher

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tnldotdev/tnl/internal/clientruntime"
	"github.com/tnldotdev/tnl/internal/clientstate"
	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/privateprotocol"
	"github.com/tnldotdev/tnl/internal/projectconfig"
	"github.com/tnldotdev/tnl/internal/publishertarget"
)

type composeRunner func(context.Context, []byte, ...string) ([]byte, error)

func (f composeRunner) Run(ctx context.Context, data []byte, args ...string) ([]byte, error) {
	return f(ctx, data, args...)
}

func encodeCompose(t *testing.T, value any) []byte {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestComposeSetupRestoresHostWorktreeAndImplicitTargets(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	host, err := projectconfig.ResolveWorktree(t.Context(), root)
	if err != nil {
		t.Fatal(err)
	}
	host = projectconfig.ApplyWorktreeHashSalt(host, root, [32]byte{1})
	var serialized projectconfig.Worktree
	if err := json.Unmarshal(encodeCompose(t, host), &serialized); err != nil {
		t.Fatal(err)
	}
	containerLabel, explicit := "container-salt", "explicit-project"
	project := projectconfig.Project{Root: "/project", Worktree: projectconfig.Worktree{Label: projectconfig.WorktreeLabel{FullLabel: containerLabel}}, Config: config.TNL{Services: config.Services{
		"db":       {Target: &config.ServiceTarget{Type: "compose", Project: &containerLabel}},
		"explicit": {Target: &config.ServiceTarget{Type: "compose", Project: &explicit}},
	}}}
	setup := ComposeSetup{ProjectRoot: "/project", Placement: publishertarget.Placement{ProjectRoot: root, PrimaryRoot: host.PrimaryCheckoutRoot(), Worktree: serialized}}
	updated, err := setup.Apply(project)
	if err != nil {
		t.Fatal(err)
	}
	if updated.Worktree.PrimaryCheckoutRoot() != host.PrimaryCheckoutRoot() || updated.Config.Services["db"].Target.Project == nil || *updated.Config.Services["db"].Target.Project != host.Label.FullLabel || *updated.Config.Services["explicit"].Target.Project != explicit {
		t.Fatal("compose owner changed the host worktree or explicit target project")
	}
}

func TestComposeExecQueryNeverExportsOwnerCredential(t *testing.T) {
	server := httptest.NewUnstartedServer(nil)
	caps, err := privateprotocol.NewCapabilities("http://" + server.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	server.Config.Handler = caps.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/health" {
			w.WriteHeader(204)
			return
		}
		var query privateprotocol.CapabilityRequest
		if err := privateprotocol.Decode(w, r, &query); err != nil {
			t.Error(err)
			w.WriteHeader(400)
			return
		}
		endpoint, err := caps.Issue(query)
		if err != nil {
			t.Error(err)
			w.WriteHeader(400)
			return
		}
		privateprotocol.Write(w, 200, endpoint)
	}))
	server.Start()
	defer server.Close()
	for _, body := range []string{`{"scope":"owner"}`, `{"scope":"app","service":"web"}`} {
		input := encodeCompose(t, ComposeQuery{Method: "POST", Path: "/v1/capabilities", Body: json.RawMessage(body)})
		var output bytes.Buffer
		err := ServeComposeQuery(t.Context(), caps.Owner(), bytes.NewReader(input), &output)
		if body == `{"scope":"owner"}` && err == nil {
			t.Fatal("exported owner capability")
		}
		if body != `{"scope":"owner"}` && err != nil {
			t.Fatal(err)
		}
		if strings.Contains(output.String(), caps.Owner().Capability) {
			t.Fatal("owner credential appeared in exec output")
		}
	}
}

func TestComposeBoundaryChecksAuthorityNetworkAndCapability(t *testing.T) {
	t.Setenv("DOCKER_HOST", "unix:///var/run/docker.sock")
	t.Setenv("DOCKER_CONTEXT", "")
	owner := publishertarget.Container{ID: strings.Repeat("a", 64)}
	owner.State.Running = true
	owner.Config.Labels = map[string]string{publishertarget.WorktreeLabel: "tree-123456"}
	owner.NetworkSettings.Networks = map[string]publishertarget.Network{"private": {NetworkID: "private", IPAddress: "172.20.0.2"}}
	app := publishertarget.Container{ID: strings.Repeat("b", 64)}
	app.State.Running = true
	app.Config.Labels = map[string]string{publishertarget.WorktreeLabel: "tree-123456", "com.docker.compose.project": "fixture", "com.docker.compose.project.config_files": "/host/compose.yaml", "com.docker.compose.project.working_dir": "/host", "com.docker.compose.oneoff": "False"}
	app.NetworkSettings.Networks = map[string]publishertarget.Network{"private": {NetworkID: "private", IPAddress: "172.20.0.3"}}
	docker := composeRunner(func(_ context.Context, _ []byte, args ...string) ([]byte, error) {
		if args[1] == "ls" {
			return []byte(owner.ID + "\n" + app.ID), nil
		}
		if args[len(args)-1] == owner.ID {
			return encodeCompose(t, []publishertarget.Container{owner}), nil
		}
		return encodeCompose(t, []publishertarget.Container{app}), nil
	})
	b := ComposeBoundary{Docker: docker, Placement: publishertarget.Placement{OwnerID: owner.ID, NetworkID: "private", ProjectRoot: "/host", Worktree: projectconfig.Worktree{Label: projectconfig.WorktreeLabel{FullLabel: "tree-123456"}}}, Project: "fixture", File: "/host/compose.yaml", Service: "publisher", Port: 8123}
	caps, err := privateprotocol.NewCapabilities("http://127.0.0.1:8123")
	if err != nil {
		t.Fatal(err)
	}
	name := "web"
	endpoint, err := caps.Issue(privateprotocol.CapabilityRequest{Scope: "app", Service: &name})
	if err != nil {
		t.Fatal(err)
	}
	handler := b.Handler(caps, caps.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if privateprotocol.Grant(r).Scope != "app" || *privateprotocol.Grant(r).Service != "web" {
			t.Error("capability scope lost")
		}
		w.WriteHeader(204)
	})))
	for _, test := range []struct {
		name, authority, peer, capability, origin string
		status                                    int
	}{
		{"current app", "publisher:8123", "172.20.0.3:5000", endpoint.Capability, "", 204},
		{"wrong authority", "foreign:8123", "172.20.0.3:5000", endpoint.Capability, "", 401},
		{"loopback authority from network", "127.0.0.1:8123", "172.20.0.3:5000", endpoint.Capability, "", 401},
		{"foreign network", "publisher:8123", "172.21.0.3:5000", endpoint.Capability, "", 401},
		{"missing capability", "publisher:8123", "172.20.0.3:5000", "", "", 401},
		{"browser origin", "publisher:8123", "172.20.0.3:5000", endpoint.Capability, "https://example.com", 401},
	} {
		t.Run(test.name, func(t *testing.T) {
			r := httptest.NewRequest("GET", "/v1/health", nil)
			r.Host, r.RemoteAddr = test.authority, test.peer
			r.Header.Set("Authorization", "Bearer "+test.capability)
			if test.origin != "" {
				r.Header.Set("Origin", test.origin)
			}
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, r)
			if w.Code != test.status {
				t.Fatalf("status=%d, want %d", w.Code, test.status)
			}
		})
	}
	app.Config.Labels["com.docker.compose.project.config_files"] = "/host/compose.yaml,/host/.tnl/compose.generated.yaml"
	r := httptest.NewRequest("GET", "/v1/health", nil)
	r.Host, r.RemoteAddr = "publisher:8123", "172.20.0.3:5000"
	r.Header.Set("Authorization", "Bearer "+endpoint.Capability)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	if w.Code != 204 {
		t.Fatalf("generated override app was rejected: %d", w.Code)
	}
	app.Config.Labels["com.docker.compose.project.config_files"] += ",/host/foreign.yaml"
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	if w.Code != 401 {
		t.Fatalf("foreign Compose override was accepted: %d", w.Code)
	}
	app.Config.Labels["com.docker.compose.project.config_files"] = "/host/compose.yaml"
	app.Config.Labels[publishertarget.WorktreeLabel] = "foreign"
	r = httptest.NewRequest("GET", "/v1/health", nil)
	r.Host, r.RemoteAddr = "publisher:8123", "172.20.0.3:5000"
	r.Header.Set("Authorization", "Bearer "+endpoint.Capability)
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	if w.Code != 401 {
		t.Fatal("reused IP inherited previous worktree authorization")
	}
}

func TestComposeDescriptorAtomicRotationAndSymlinkRejection(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "private", "endpoint.json")
	var previous privateprotocol.Endpoint
	for range 2 {
		caps, err := privateprotocol.NewCapabilities("http://127.0.0.1:8123")
		if err != nil {
			t.Fatal(err)
		}
		name := "web"
		endpoint, err := caps.Issue(privateprotocol.CapabilityRequest{Scope: "app", Service: &name})
		if err != nil {
			t.Fatal(err)
		}
		endpoint.Url = "http://publisher:8123"
		if err := writeComposeEndpoint(path, endpoint, endpoint.Url); err != nil {
			t.Fatal(err)
		}
		file, err := os.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		var read privateprotocol.Endpoint
		err = json.NewDecoder(file).Decode(&read)
		file.Close()
		if err != nil || read.OwnerId != endpoint.OwnerId || read.Capability == previous.Capability {
			t.Fatalf("rotation failed: %v", err)
		}
		info, err := os.Stat(path)
		if err != nil || info.Mode().Perm() != 0600 {
			t.Fatal("descriptor is not private")
		}
		previous = endpoint
	}
	outside := filepath.Join(root, "elsewhere")
	if err := os.Mkdir(outside, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "symlink")); err != nil {
		t.Fatal(err)
	}
	if err := writeComposeEndpoint(filepath.Join(root, "symlink", "endpoint.json"), previous, previous.Url); err == nil {
		t.Fatal("followed descriptor directory symlink")
	}
}

func TestComposeExecQueryRejectsTraversalAndTrailingJSON(t *testing.T) {
	for _, input := range []string{
		`{"method":"GET","path":"/v1/../credentials"}`,
		`{"method":"GET","path":"/v1/%2e%2e/credentials"}`,
		`{"method":"GET","path":"http://foreign/v1/health"}`,
		`{"method":"GET","path":"/v1/health"}{}`,
		`{"method":"GET","path":"/v1/health","owner_capability":"secret"}`,
	} {
		if err := ServeComposeQuery(t.Context(), privateprotocol.Endpoint{}, strings.NewReader(input), io.Discard); err == nil {
			t.Fatalf("accepted %s", input)
		}
	}
}

func TestComposeBridgeUsesTheSameOwnerForScopedAppsAndNamedCLI(t *testing.T) {
	t.Setenv("DOCKER_HOST", "unix:///var/run/docker.sock")
	t.Setenv("DOCKER_CONTEXT", "")
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	db, err := clientstate.OpenWithOptions(t.Context(), filepath.Join(t.TempDir(), "state"), clientstate.OpenOptions{Protection: clientstate.ProtectionFile})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	manager, err := clientruntime.New(t.Context(), root, db, []clientruntime.Service{{Name: "web"}, {Name: "db", ServiceProtocol: "redis"}}, func(ctx context.Context, _ clientruntime.Service, _ func(uint64, bool) error) error {
		<-ctx.Done()
		return ctx.Err()
	})
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	server := httptest.NewUnstartedServer(nil)
	caps, err := privateprotocol.NewCapabilities("http://" + server.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	server.Config.Handler = (&Server{Capabilities: caps, Database: db, Manager: manager, Project: root, AppService: func(name string) bool { return name == "web" }}).Handler()
	server.Start()
	defer server.Close()
	container := publishertarget.Container{ID: strings.Repeat("a", 64)}
	container.State.Running = true
	container.Config.Labels = map[string]string{publishertarget.WorktreeLabel: "tree-123456", "com.docker.compose.project": "fixture", "com.docker.compose.service": "publisher", "com.docker.compose.oneoff": "False", "com.docker.compose.project.config_files": "/host/compose.yaml", "com.docker.compose.project.working_dir": "/host"}
	docker := composeRunner(func(ctx context.Context, input []byte, args ...string) ([]byte, error) {
		for _, arg := range args {
			if strings.Contains(arg, caps.Owner().Capability) {
				t.Error("owner credential exported as an argument")
			}
		}
		if args[0] == "container" {
			return encodeCompose(t, []publishertarget.Container{container}), nil
		}
		if args[7] == "ps" {
			return []byte(container.ID), nil
		}
		var output bytes.Buffer
		if err := ServeComposeQuery(ctx, caps.Owner(), bytes.NewReader(input), &output); err != nil {
			return nil, err
		}
		if strings.Contains(output.String(), caps.Owner().Capability) {
			t.Error("owner credential exported from exec")
		}
		return output.Bytes(), nil
	})
	owner := ComposeOwner{Docker: docker, HostRoot: "/host", Project: "fixture", File: "/host/compose.yaml", Service: "publisher", ContainerRoot: "/project", Worktree: projectconfig.Worktree{Label: projectconfig.WorktreeLabel{FullLabel: "tree-123456"}}}
	endpoint, bridge, err := owner.Bridge(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer bridge.Close()
	var all clientruntime.Snapshot
	if err := privateprotocol.Call(t.Context(), endpoint, "GET", "/v1/status", nil, &all); err != nil || len(all.Services) != 2 {
		t.Fatalf("owner snapshot=%+v err=%v", all, err)
	}
	name := "web"
	var app privateprotocol.Endpoint
	if err := privateprotocol.Call(t.Context(), endpoint, "POST", "/v1/capabilities", privateprotocol.CapabilityRequest{Scope: "app", Service: &name}, &app); err != nil {
		t.Fatal(err)
	}
	if app.Url != endpoint.Url || app.Capability == caps.Owner().Capability {
		t.Fatal("app endpoint escaped the scoped host bridge")
	}
	var scoped clientruntime.Snapshot
	if err := privateprotocol.Call(t.Context(), app, "GET", "/v1/status", nil, &scoped); err != nil || len(scoped.Services) != 1 || scoped.Services[0].Name != "web" {
		t.Fatalf("app snapshot=%+v err=%v", scoped, err)
	}
	if err := privateprotocol.Call(t.Context(), app, "POST", "/v1/capabilities", privateprotocol.CapabilityRequest{Scope: "app", Service: &name}, nil); err != privateprotocol.ErrForbidden {
		t.Fatalf("app minted another capability: %v", err)
	}
}

func TestComposeEndpointRotationRejectsSharedOwnerState(t *testing.T) {
	owner := publishertarget.Container{ID: strings.Repeat("a", 64)}
	owner.State.Running = true
	owner.Config.Labels = map[string]string{publishertarget.WorktreeLabel: "tree-123456"}
	owner.Mounts = []publishertarget.Mount{{Type: "volume", Name: "owner-state", Destination: "/state", RW: true}}
	docker := composeRunner(func(_ context.Context, _ []byte, args ...string) ([]byte, error) {
		if args[1] == "inspect" {
			return encodeCompose(t, []publishertarget.Container{owner}), nil
		}
		return []byte(owner.ID + "\n" + strings.Repeat("b", 64)), nil
	})
	boundary := ComposeBoundary{Docker: docker, Placement: publishertarget.Placement{OwnerID: owner.ID, Worktree: projectconfig.Worktree{Label: projectconfig.WorktreeLabel{FullLabel: "tree-123456"}}}, StateRoot: "/state/private"}
	if err := WriteComposeAppEndpoints(t.Context(), boundary, nil, nil); err == nil {
		t.Fatal("publisher state was not private to its container")
	}
}

func TestComposeDatabaseOnlyOwnerAllowsNoAppDescriptorsAndRejectsPublishedAPI(t *testing.T) {
	t.Setenv("DOCKER_HOST", "unix:///var/run/docker.sock")
	t.Setenv("DOCKER_CONTEXT", "")
	owner := publishertarget.Container{ID: strings.Repeat("a", 64)}
	owner.State.Running = true
	owner.Config.Labels = map[string]string{publishertarget.WorktreeLabel: "tree-123456", "com.docker.compose.project": "fixture", "com.docker.compose.service": "publisher", "com.docker.compose.oneoff": "False", "com.docker.compose.project.config_files": "/host/compose.yaml", "com.docker.compose.project.working_dir": "/host"}
	owner.NetworkSettings.Networks = map[string]publishertarget.Network{"private": {NetworkID: "private"}}
	docker := composeRunner(func(_ context.Context, _ []byte, args ...string) ([]byte, error) {
		if args[0] == "compose" {
			return []byte(owner.ID), nil
		}
		if args[0] == "network" {
			return []byte(`[{"Id":"private","Driver":"bridge","Scope":"local","Labels":{"tnl.worktree":"tree-123456"}}]`), nil
		}
		return encodeCompose(t, []publishertarget.Container{owner}), nil
	})
	setup := ComposeSetup{Placement: publishertarget.Placement{OwnerID: owner.ID, NetworkID: "private", ProjectRoot: "/host", Worktree: projectconfig.Worktree{Label: projectconfig.WorktreeLabel{FullLabel: "tree-123456"}}}, Project: "fixture", File: "/host/compose.yaml", Service: "publisher", ProjectRoot: "/project", Port: 8123}
	if err := setup.WriteApps(t.Context(), docker, "/state/private", nil); err != nil {
		t.Fatalf("database-only owner required app descriptors: %v", err)
	}
	owner.NetworkSettings.Ports = map[string][]publishertarget.Binding{"8123/tcp": {{HostIP: "127.0.0.1", HostPort: "48123"}}}
	if err := setup.Validate(t.Context(), docker); err == nil {
		t.Fatal("private owner API was allowed to publish a host binding")
	}
}

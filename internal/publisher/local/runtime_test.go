package local

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	clientproject "github.com/tnldotdev/tnl/internal/client/project"
	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	"github.com/tnldotdev/tnl/internal/config"
	publisherapp "github.com/tnldotdev/tnl/internal/publisher/app"
	publisherprotocol "github.com/tnldotdev/tnl/internal/publisher/localapi/protocol"
)

func TestPublicationOwnerBypassesConfigurationAndIsolatesLocalApps(t *testing.T) {
	directory, state := t.TempDir(), filepath.Join(t.TempDir(), "state")
	if err := os.WriteFile(filepath.Join(directory, "tnl.config.ts"), []byte(`throw new Error("must not evaluate")`), 0600); err != nil {
		t.Fatal(err)
	}
	options := Options{Directory: directory, StateDir: state, Publications: true}
	project, root, err := ResolveProject(t.Context(), options)
	if err != nil {
		t.Fatal(err)
	}
	if project.Root == directory || project.Selection.Path != "" || project.Worktree.Root != "" || len(project.Config.Services) != 0 || !strings.HasPrefix(project.Root, filepath.Join(root, "runtime")+string(filepath.Separator)) {
		t.Fatal("publication adopted local configuration or Git")
	}
	repeated, again, err := ResolveProject(t.Context(), options)
	if err != nil || repeated.Root != project.Root || again != root {
		t.Fatal("publication owner identity changed", err)
	}
	snapshot, _, err := project.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	child, _, err := ResolveProject(t.Context(), Options{Directory: project.Root, StateDir: root, Snapshot: bytes.NewReader(snapshot)})
	if err != nil || child.Root != project.Root {
		t.Fatal("child lost private snapshot", err)
	}
	if _, err := Endpoint(t.Context(), options, "web", ""); err == nil {
		t.Fatal("configuration-free owner selected a local app")
	}
}

func testAppRuntime(t *testing.T) (*appRuntime, publisherprotocol.Endpoint) {
	t.Helper()
	return testAppRuntimeWorkers(t, false)
}

func testAppRuntimeWorkers(t *testing.T, realWorkers bool, defaultProtection ...bool) (*appRuntime, publisherprotocol.Endpoint) {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	options := clientstate.OpenOptions{Protection: clientstate.ProtectionFile}
	if len(defaultProtection) != 0 && defaultProtection[0] {
		options.Protection = ""
	}
	state, err := clientstate.OpenWithOptions(t.Context(), filepath.Join(t.TempDir(), "state"), options)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = state.Close() })
	a := &appRuntime{state: state, project: clientproject.Project{Root: root, Config: config.TNL{Services: config.Services{"web": {}, "api": {}}}}, prepared: map[string]appPreparation{}}
	a.workers = &publisherapp.Workers{Database: state, Configure: a.workerConfiguration}
	run := func(ctx context.Context, _ publisherapp.Service, observe func(uint64, bool) error) error {
		if err := observe(1, true); err != nil {
			return err
		}
		<-ctx.Done()
		return ctx.Err()
	}
	if realWorkers {
		run = a.workers.Run
	}
	a.manager, err = publisherapp.New(t.Context(), root, state, publisherapp.ConfiguredServices(a.project), run)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(a.manager.Close)
	a.workers.Manager = a.manager
	a.manager.Cleanup = a.cleanupPreparation
	server := httptest.NewUnstartedServer(nil)
	a.capabilities, err = publisherprotocol.NewCapabilities("http://" + server.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	server.Config.Handler = a.handler()
	server.Start()
	t.Cleanup(server.Close)
	return a, a.capabilities.Owner()
}

func TestRuntimeStatusIsAuthenticatedScopedAndDoesNotProbe(t *testing.T) {
	a, owner := testAppRuntime(t)
	name := "web"
	app, err := a.capabilities.Issue(publisherprotocol.CapabilityRequest{Scope: "app", Service: &name})
	if err != nil {
		t.Fatal(err)
	}
	a.manager.RecordFailure("api", "runtime.preparation_failed")
	var snapshot publisherapp.Snapshot
	if err := publisherprotocol.Call(t.Context(), app, http.MethodGet, "/v1/status", nil, &snapshot); err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Services) != 1 || snapshot.Services[0].Name != "web" || snapshot.Services[0].Ready {
		t.Fatalf("scoped status=%+v", snapshot.Services)
	}
	if err := publisherprotocol.Call(t.Context(), app, "POST", "/v1/check", publisherprotocol.Check{}, &snapshot); err != publisherprotocol.ErrForbidden {
		t.Fatalf("app ran owner readiness: %v", err)
	}
	if err := publisherprotocol.Call(t.Context(), owner, "GET", "/v1/status", nil, &snapshot); err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Services) != 2 || snapshot.Cursor == "" {
		t.Fatalf("owner snapshot=%+v", snapshot)
	}
	if _, err := json.Marshal(snapshot); err != nil {
		t.Fatal(err)
	}
}

func TestHTTPRuntimeDoesNotCreatePublicURLsForServices(t *testing.T) {
	protocol := "postgres"
	address := config.Target("127.0.0.1:5432")
	project := clientproject.Project{Config: config.TNL{Services: config.Services{"web": {}, "orders": {Protocol: &protocol, Target: &config.ServiceTarget{Type: "address", Address: &address}}}}}
	services := publisherapp.ConfiguredServices(project)
	if len(services) != 2 || services[0].Name != "orders" || services[0].ServiceProtocol != "postgres" || services[0].PublicURL != "" || services[1].PublicURL != "" {
		t.Fatalf("services=%+v", services)
	}
}

func TestAppServiceSelectionUsesNameNotDirectoryInference(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	nested := filepath.Join(root, "nested")
	if err := os.Mkdir(nested, 0700); err != nil {
		t.Fatal(err)
	}
	p := clientproject.Project{Root: root, Config: config.TNL{Services: config.Services{"web": {}}}}
	if name, err := p.AppService(nested, ""); err != nil || name != "web" {
		t.Fatalf("single app selection = %q, %v", name, err)
	}
	p.Config.Services["api"] = config.Service{}
	if _, err := p.AppService(nested, ""); err == nil {
		t.Fatal("selected an app from its directory when multiple are configured")
	}
	if name, err := p.AppService(nested, "api"); err != nil || name != "api" {
		t.Fatalf("explicit app selection = %q, %v", name, err)
	}
}

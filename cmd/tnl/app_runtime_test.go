package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/clientruntime"
	"github.com/tnldotdev/tnl/internal/clientstate"
	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/localpublisher"
	"github.com/tnldotdev/tnl/internal/projectconfig"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

type observedRuntime struct {
	manager *clientruntime.Manager
	project projectConfiguration
}

func testAppRuntime(t *testing.T) (*observedRuntime, string, <-chan uint64) {
	t.Helper()
	t.Setenv("XDG_RUNTIME_DIR", t.TempDir())
	project, _ := filepath.EvalSymlinks(t.TempDir())
	state, _ := filepath.EvalSymlinks(t.TempDir())
	if err := os.Chmod(state, 0700); err != nil {
		t.Fatal(err)
	}
	a := &observedRuntime{project: projectConfiguration{Project: projectconfig.Project{Root: project, Config: config.TNL{Services: config.Services{"api": {}, "web": {}}}, RelativeServiceDirectories: map[string]string{"api": ".", "web": "."}}}}
	var run atomic.Uint64
	started := make(chan uint64, 4)
	manager, err := clientruntime.New(t.Context(), project, state, configuredRuntimeServices(a.project), func(ctx context.Context, _ clientruntime.Service, observe func(uint64, bool) error) error {
		number := run.Add(1)
		if err := observe(number, true); err != nil {
			return err
		}
		started <- number
		<-ctx.Done()
		return ctx.Err()
	})
	if err != nil {
		t.Fatal(err)
	}
	a.manager = manager
	t.Cleanup(manager.Close)
	key, err := runtimeKey(project, state)
	if err != nil {
		t.Fatal(err)
	}
	handler := localpublisher.Handler(a.project.Project, nil, manager, nil, nil)
	server, _, err := localpublisher.StartAPI(key, handler, "127.0.0.1:0", "", configuredRuntimeServices(a.project)...)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := localpublisher.StopAPI(context.Background(), server, key); err != nil {
			t.Error(err)
		}
	})
	return a, state, started
}

func TestAppStatusRejectsPublisherWithStaleLocalCredential(t *testing.T) {
	a, state, started := testAppRuntime(t)
	id, err := a.manager.Reserve("api", "owner", os.Getpid(), "https://api.example")
	if err != nil {
		t.Fatal(err)
	}
	if err := a.manager.Register(id, "owner", "http://127.0.0.1:1234", "node"); err != nil {
		t.Fatal(err)
	}
	<-started
	key, err := runtimeKey(a.project.Root, state)
	if err != nil {
		t.Fatal(err)
	}
	path := runtimeTCPEndpointPath(key)
	previous, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.WriteFile(path, previous, 0o600) })
	endpoint, err := readRuntimeTCPEndpoint(key)
	if err != nil {
		t.Fatal(err)
	}
	endpoint.Credential = "stale-credential"
	if err := writeRuntimeTCPEndpoint(path, endpoint); err != nil {
		t.Fatal(err)
	}
	snapshot, err := readAppSnapshot(t.Context(), a.project, state)
	if err != nil || snapshot.Services[0].Registered || snapshot.Services[0].Routable || snapshot.Services[0].Failure != "runtime.manager_unavailable" {
		t.Fatalf("status trusted a stale endpoint: %+v, %v", snapshot, err)
	}
}

func TestRuntimeEndpointReturnsPathWithoutStartingPublisher(t *testing.T) {
	t.Setenv("TNL_CONFIG", "")
	project, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(project, "tnl.json"), []byte(`{"version":1,"tnl":{"services":{"web":{"target":{"type":"app"}}}}}`), 0600); err != nil {
		t.Fatal(err)
	}
	state := filepath.Join(t.TempDir(), "state")
	var output bytes.Buffer
	if err := run(t.Context(), []string{"--no-telemetry", "runtime", "endpoint", "--directory", project, "--state-dir", state}, &output, io.Discard); err != nil {
		t.Fatal(err)
	}
	selected, root, err := runtimeProject(t.Context(), runtimeOptions{Directory: project, StateDir: state})
	if err != nil {
		t.Fatal(err)
	}
	key, err := runtimeKey(selected.Root, root)
	if err != nil {
		t.Fatal(err)
	}
	var endpoint struct {
		Version int    `json:"version"`
		Path    string `json:"path"`
	}
	if err := json.Unmarshal(output.Bytes(), &endpoint); err != nil || endpoint.Version != 1 || endpoint.Path != runtimeTCPEndpointPath(key) {
		t.Fatalf("runtime endpoint = %s, %v", output.String(), err)
	}
	if runtimeAvailable(t.Context(), key) {
		t.Fatal("endpoint lookup started the local publisher")
	}
	if _, err := os.Stat(endpoint.Path); !os.IsNotExist(err) {
		t.Fatalf("endpoint lookup started the local publisher: %v", err)
	}
	for _, test := range []struct {
		args []string
		path string
	}{
		{[]string{"--app", "--service", "web"}, runtimeAppEndpointPath(key, "web")},
		{[]string{"--app"}, runtimeAppEndpointPath(key, "web")},
		{[]string{"--ad-hoc"}, runtimeAdHocEndpointPath(key)},
	} {
		output.Reset()
		args := append([]string{"--no-telemetry", "runtime", "endpoint", "--directory", project, "--state-dir", state}, test.args...)
		if err := run(t.Context(), args, &output, io.Discard); err != nil {
			t.Fatal(err)
		}
		var selected struct {
			Path string `json:"path"`
		}
		if err := json.Unmarshal(output.Bytes(), &selected); err != nil || selected.Path != test.path {
			t.Fatalf("scoped publisher endpoint = %s, want %s: %v", output.String(), test.path, err)
		}
	}
}

func TestDatabaseServicesWaitForPublicReadinessWithoutHTTPProbe(t *testing.T) {
	a, stateDir, _ := testAppRuntime(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	protocol := "postgres"
	target := config.Target(listener.Addr().String())
	project := a.project
	project.Config.Services["orders"] = config.Service{Publish: &config.Publish{Protocol: &protocol, Target: &target}}
	project.RelativeServiceDirectories["orders"] = "."
	services := configuredRuntimeServices(project)
	if len(services) != 2 || services[0].Name != "api" || services[1].Name != "web" {
		t.Fatalf("app registrations = %#v", services)
	}
	database, err := clientstate.Open(t.Context(), stateDir)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	tunnel, err := database.BeginTunnel(t.Context(), clientstate.BeginTunnelOptions{Command: clientstate.TunnelCommandPublish, Server: "https://server.example", Target: listener.Addr().String(), Project: project.Root, Service: "orders", ServiceProtocol: controlv1.Postgres})
	if err != nil {
		t.Fatal(err)
	}
	defer tunnel.Finish(context.Background(), nil)
	if err := tunnel.SetPublicURL(t.Context(), "url_0123456789abcdefghijkl", "orders.example"); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	probe := func(context.Context, clientruntime.Service) clientruntime.Observation {
		t.Fatal("database service sent an HTTP readiness probe")
		return clientruntime.Observation{}
	}
	publicReady := true
	tcpProbe := func(_ context.Context, service clientruntime.Service, passthrough bool) error {
		if service.PublicURL != "orders.example:15432" || service.ServiceProtocol != "postgres" || passthrough {
			t.Errorf("public TCP probe used the wrong run or protocol: %+v, passthrough=%t", service, passthrough)
		}
		if !publicReady {
			return errors.New("public visitor path unavailable")
		}
		return nil
	}
	flags := waitCommand{Service: []string{"orders"}, Timeout: 500 * time.Millisecond, Output: "json"}
	if err := runAppWaitWithProbe(t.Context(), project, stateDir, flags, &output, probe, tcpProbe); err == nil {
		t.Fatal("unready database publication passed wait")
	}
	if err := tunnel.SetReady(t.Context(), "orders.example:15432", 1); err != nil {
		t.Fatal(err)
	}
	output.Reset()
	flags.Timeout = 2 * time.Second
	if err := runAppWaitWithProbe(t.Context(), project, stateDir, flags, &output, probe, tcpProbe); err != nil {
		t.Fatal(err)
	}
	var snapshot clientruntime.Snapshot
	if err := json.Unmarshal(output.Bytes(), &snapshot); err != nil || len(snapshot.Services) != 1 || !snapshot.Services[0].Ready || snapshot.Services[0].PublicURL != "orders.example:15432" || snapshot.Services[0].ServiceProtocol != protocol || snapshot.Services[0].TunnelID != tunnel.ID() {
		t.Fatalf("database wait = %s, %v", output.String(), err)
	}
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	output.Reset()
	if err := runAppWaitWithProbe(t.Context(), project, stateDir, flags, &output, probe, tcpProbe); err != nil {
		t.Fatalf("private target dial changed public readiness: %v", err)
	}
	publicReady = false
	output.Reset()
	flags.Timeout = 500 * time.Millisecond
	if err := runAppWaitWithProbe(t.Context(), project, stateDir, flags, &output, probe, tcpProbe); err == nil {
		t.Fatal("wait passed with an unavailable public visitor path")
	}
	if err := os.WriteFile(filepath.Join(project.Root, "tnl.json"), []byte(`{"version":1,"tnl":{"services":{"web":{"target":{"type":"app"}},"orders":{"protocol":"postgres","target":{"type":"address","address":"`+string(target)+`"}}}}}`), 0600); err != nil {
		t.Fatal(err)
	}
	output.Reset()
	if err := runStatus(t.Context(), statusCommand{StateDir: stateDir, Project: project.Root, Output: "human"}, &output); err != nil || !strings.Contains(output.String(), "orders routable") || !strings.Contains(output.String(), "orders.example:15432") {
		t.Fatalf("database status = %s, %v", output.String(), err)
	}
}

func TestNamedHTTPServiceChecksConfiguredHTTPReadiness(t *testing.T) {
	a, state, started := testAppRuntime(t)
	service := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/health" {
			response.WriteHeader(http.StatusNotFound)
		}
	}))
	defer service.Close()
	address := config.Target(service.URL)
	a.project.Config.Services["orders"] = config.Service{Target: &config.ServiceTarget{Type: "address", Address: &address}, Readiness: &config.Readiness{Path: "/health"}}
	a.project.RelativeServiceDirectories["orders"] = "."
	if err := a.manager.Configure(configuredRuntimeServices(a.project)); err != nil {
		t.Fatal(err)
	}
	id, err := a.manager.Reserve("orders", "cli-owner", os.Getpid(), "https://orders.example")
	if err != nil {
		t.Fatal(err)
	}
	if err := a.manager.RegisterNamed(id, "cli-owner", service.URL); err != nil {
		t.Fatal(err)
	}
	<-started
	if err := a.manager.Started(id, "tun_named_http"); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	var calls int
	probe := func(ctx context.Context, current clientruntime.Service) clientruntime.Observation {
		calls++
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, service.URL+current.Readiness.Path, nil)
		if err != nil {
			t.Error(err)
			return clientruntime.Observation{}
		}
		response, err := http.DefaultClient.Do(request)
		if err != nil {
			t.Error(err)
			return clientruntime.Observation{}
		}
		response.Body.Close()
		return clientruntime.Observation{RegistrationID: current.RegistrationID, PublishRunNumber: current.PublishRunNumber, CheckedAt: time.Now(), Readiness: current.Readiness, Ready: response.StatusCode == http.StatusOK}
	}
	if err := runAppWaitWithProbe(t.Context(), a.project, state, waitCommand{Service: []string{"orders"}, Timeout: 2 * time.Second, Output: "json"}, &output, probe); err != nil {
		t.Fatal(err)
	}
	var snapshot clientruntime.Snapshot
	if err := json.Unmarshal(output.Bytes(), &snapshot); err != nil || calls == 0 || len(snapshot.Services) != 1 || !snapshot.Services[0].Ready || snapshot.Services[0].Observation == nil || snapshot.Services[0].Observation.Readiness.Path != "/health" {
		t.Fatalf("HTTP readiness = %+v, %v", snapshot, err)
	}
}

func TestWaitAlwaysChecksFreshResponsesAndKeepsFailingPublicationsRunning(t *testing.T) {
	a, state, started := testAppRuntime(t)
	id, err := a.manager.Reserve("api", "owner", 1, "https://api.example")
	if err != nil {
		t.Fatal(err)
	}
	if err := a.manager.Register(id, "owner", "http://127.0.0.1:1234", "node"); err != nil {
		t.Fatal(err)
	}
	run := <-started
	a.manager.Observe(clientruntime.Observation{RegistrationID: id, PublishRunNumber: run, Ready: true, CheckedAt: time.Now(), Readiness: clientruntime.Readiness{Path: "/"}})
	var calls atomic.Int32
	probe := func(_ context.Context, service clientruntime.Service) clientruntime.Observation {
		calls.Add(1)
		return clientruntime.Observation{RegistrationID: service.RegistrationID, PublishRunNumber: service.PublishRunNumber, CheckedAt: time.Now(), Status: 503, Reason: "runtime.probe_rejected", Readiness: service.Readiness}
	}
	var output bytes.Buffer
	err = runAppWaitWithProbe(t.Context(), a.project, state, waitCommand{Service: []string{"api"}, Timeout: 20 * time.Millisecond, Output: "json"}, &output, probe)
	if reason, _, ok := failure.Describe(err); !ok || reason != failure.AppReadinessTimeout || calls.Load() == 0 {
		t.Fatalf("fresh wait = %v, probes=%d", err, calls.Load())
	}
	service := a.manager.Snapshot().Services[0]
	if !service.Registered || !service.Routable || service.Ready {
		t.Fatalf("failed check stopped publication or reused readiness: %#v", service)
	}
	var result clientruntime.Snapshot
	if err := json.Unmarshal(output.Bytes(), &result); err != nil || len(result.Services) != 1 || result.Services[0].Ready {
		t.Fatalf("wait output = %s, %v", output.String(), err)
	}
	output.Reset()
	err = runAppWaitWithProbe(t.Context(), a.project, state, waitCommand{Timeout: 10 * time.Millisecond, Output: "json"}, &output, func(_ context.Context, s clientruntime.Service) clientruntime.Observation {
		return clientruntime.Observation{RegistrationID: s.RegistrationID, PublishRunNumber: s.PublishRunNumber, CheckedAt: time.Now(), Ready: true, Readiness: s.Readiness}
	})
	if err == nil {
		t.Fatal("wait did not include the unregistered configured web service")
	}
	if err := json.Unmarshal(output.Bytes(), &result); err != nil || len(result.Services) != 2 {
		t.Fatalf("all-service wait = %s, %v", output.String(), err)
	}
}

func TestWaitDiscardsAResponseFromAReplacedRegistrationRun(t *testing.T) {
	a, state, started := testAppRuntime(t)
	id, err := a.manager.Reserve("api", "owner", 1, "https://api.example")
	if err != nil {
		t.Fatal(err)
	}
	if err := a.manager.Register(id, "owner", "http://127.0.0.1:1234", "node"); err != nil {
		t.Fatal(err)
	}
	<-started
	calls := 0
	var output bytes.Buffer
	err = runAppWaitWithProbe(t.Context(), a.project, state, waitCommand{Service: []string{"api"}, Timeout: 2 * time.Second, Output: "json"}, &output, func(_ context.Context, s clientruntime.Service) clientruntime.Observation {
		calls++
		if calls == 1 {
			if err := a.manager.Register(id, "owner", "http://127.0.0.1:1235", "node"); err != nil {
				t.Error(err)
			}
			<-started
		}
		return clientruntime.Observation{RegistrationID: s.RegistrationID, PublishRunNumber: s.PublishRunNumber, CheckedAt: time.Now(), Ready: true, Readiness: s.Readiness}
	})
	if err != nil || calls != 2 {
		t.Fatalf("replacement wait = %v, checks=%d, output=%s", err, calls, output.String())
	}
}

func TestWatchResumeAndExpiredCursor(t *testing.T) {
	a, state, _ := testAppRuntime(t)
	a.manager.RecordFailure("api", "runtime.preparation_failed")
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
	defer cancel()
	var output bytes.Buffer
	if err := runAppWatch(ctx, a.project, state, watchCommand{Output: "ndjson"}, &output); err != nil {
		t.Fatal(err)
	}
	var initial struct {
		Type     string                 `json:"type"`
		Snapshot clientruntime.Snapshot `json:"snapshot"`
	}
	if err := json.Unmarshal(bytes.TrimSpace(output.Bytes()), &initial); err != nil || initial.Type != "snapshot" || len(initial.Snapshot.Services) != 2 {
		t.Fatalf("watch snapshot = %s, %v", output.String(), err)
	}
	if _, err := a.manager.Reserve("api", "owner", 1, "https://api.example"); err != nil {
		t.Fatal(err)
	}
	output.Reset()
	ctx2, cancel2 := context.WithTimeout(t.Context(), 20*time.Millisecond)
	defer cancel2()
	if err := runAppWatch(ctx2, a.project, state, watchCommand{After: initial.Snapshot.Cursor, Output: "ndjson"}, &output); err != nil {
		t.Fatal(err)
	}
	var event clientruntime.Event
	if err := json.Unmarshal(bytes.TrimSpace(output.Bytes()), &event); err != nil || event.Type != "service.prepared" {
		t.Fatalf("resume = %s, %v", output.String(), err)
	}
	if err := runAppWatch(t.Context(), a.project, state, watchCommand{After: "9999", Output: "ndjson"}, &output); !errors.Is(err, clientruntime.ErrCursorExpired) {
		t.Fatalf("future cursor = %v", err)
	}
}

func TestStatusIncludesConfiguredUnregisteredServicesAndRecentFailures(t *testing.T) {
	a, state, _ := testAppRuntime(t)
	data := `{"version":1,"tnl":{"services":{"api":{},"web":{}}}}`
	if err := os.WriteFile(filepath.Join(a.project.Root, "tnl.json"), []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	a.manager.RecordFailure("web", string(failure.Authentication))
	var output bytes.Buffer
	if err := runStatus(t.Context(), statusCommand{StateDir: state, Project: a.project.Root, Output: "json"}, &output); err != nil {
		t.Fatal(err)
	}
	var result struct {
		Cursor   string                  `json:"cursor"`
		Services []clientruntime.Service `json:"services"`
	}
	if err := json.Unmarshal(output.Bytes(), &result); err != nil || len(result.Services) != 2 || result.Services[1].Failure != string(failure.Authentication) || result.Services[1].Registered || result.Cursor != a.manager.Snapshot().Cursor {
		t.Fatalf("status = %s, %v", output.String(), err)
	}
	output.Reset()
	if err := runStatus(t.Context(), statusCommand{StateDir: state, Project: a.project.Root, Output: "human"}, &output); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "web not registered") || !strings.Contains(output.String(), "recent failure") {
		t.Fatalf("human status = %s", output.String())
	}
}

func TestWatchResumesDatabaseAndAppEventsWithOneCursor(t *testing.T) {
	a, stateDir, _ := testAppRuntime(t)
	protocol := "postgres"
	project := a.project
	project.Config.Services["orders"] = config.Service{Publish: &config.Publish{Protocol: &protocol}}
	project.RelativeServiceDirectories["orders"] = "."
	database, err := clientstate.Open(t.Context(), stateDir)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	var output bytes.Buffer
	initialCtx, cancel := context.WithTimeout(t.Context(), 200*time.Millisecond)
	defer cancel()
	if err := runAppWatch(initialCtx, project, stateDir, watchCommand{Output: "ndjson"}, &output); err != nil {
		t.Fatal(err)
	}
	var initial struct {
		Type     string                 `json:"type"`
		Snapshot clientruntime.Snapshot `json:"snapshot"`
	}
	if err := json.Unmarshal(bytes.TrimSpace(output.Bytes()), &initial); err != nil || initial.Type != "snapshot" || len(initial.Snapshot.Services) != 3 || !strings.Contains(initial.Snapshot.Cursor, ":") || initial.Snapshot.Services[1].Name != "orders" {
		t.Fatalf("mixed watch snapshot = %s, %v", output.String(), err)
	}
	tunnel, err := database.BeginTunnel(t.Context(), clientstate.BeginTunnelOptions{Command: clientstate.TunnelCommandPublish, Server: "https://server.example", Target: "127.0.0.1:5432", Project: project.Root, Service: "orders", ServiceProtocol: controlv1.Postgres})
	if err != nil {
		t.Fatal(err)
	}
	defer tunnel.Finish(context.Background(), nil)
	if err := tunnel.SetPublicURL(t.Context(), "url_0123456789abcdefghijkl", "orders.example"); err != nil {
		t.Fatal(err)
	}
	if err := tunnel.SetReady(t.Context(), "orders.example:15432", 1); err != nil {
		t.Fatal(err)
	}
	output.Reset()
	resumeCtx, stopResume := context.WithTimeout(t.Context(), 200*time.Millisecond)
	defer stopResume()
	if err := runAppWatch(resumeCtx, project, stateDir, watchCommand{After: initial.Snapshot.Cursor, Output: "ndjson"}, &output); err != nil {
		t.Fatal(err)
	}
	var events []clientruntime.Event
	for _, line := range strings.Split(strings.TrimSpace(output.String()), "\n") {
		var event clientruntime.Event
		if err := json.Unmarshal([]byte(line), &event); err != nil {
			t.Fatal(err)
		}
		events = append(events, event)
	}
	if len(events) != 3 || events[2].Type != "service.publication" || events[2].Service == nil || events[2].Service.PublicURL != "orders.example:15432" || !events[2].Service.Routable || events[2].Cursor != strings.Split(initial.Snapshot.Cursor, ":")[0]+":3" {
		t.Fatalf("database watch events = %#v", events)
	}
	if _, err := a.manager.Reserve("api", "owner", 1, "https://api.example"); err != nil {
		t.Fatal(err)
	}
	if err := tunnel.Finish(t.Context(), nil); err != nil {
		t.Fatal(err)
	}
	output.Reset()
	resumeCtx2, stopResume2 := context.WithTimeout(t.Context(), 200*time.Millisecond)
	defer stopResume2()
	if err := runAppWatch(resumeCtx2, project, stateDir, watchCommand{After: events[2].Cursor, Output: "ndjson"}, &output); err != nil {
		t.Fatal(err)
	}
	preparedCursor, _, err := parseWatchCursor(events[2].Cursor)
	if err != nil {
		t.Fatal(err)
	}
	previous, err := clientruntime.ParseCursor(preparedCursor)
	if err != nil {
		t.Fatal(err)
	}
	next := strconv.FormatUint(previous+1, 10)
	if !strings.Contains(output.String(), `"cursor":"`+next+`:3","type":"service.prepared"`) || !strings.Contains(output.String(), `"cursor":"`+next+`:4","type":"service.stopped"`) {
		t.Fatalf("interleaved watch resume = %s", output.String())
	}
	if err := runAppWatch(t.Context(), project, stateDir, watchCommand{After: "0:9999", Output: "ndjson"}, &output); !errors.Is(err, clientstate.ErrTunnelCursorExpired) {
		t.Fatalf("future database cursor = %v", err)
	}
}

func TestWatchDatabaseOnlyProjectWithoutAppRuntime(t *testing.T) {
	protocol := "mysql"
	project := projectConfiguration{Project: projectconfig.Project{Root: t.TempDir(), Config: config.TNL{Services: config.Services{"warehouse": {Publish: &config.Publish{Protocol: &protocol}}}}, RelativeServiceDirectories: map[string]string{"warehouse": "."}}}
	stateDir := filepath.Join(t.TempDir(), "state")
	database, err := clientstate.Open(t.Context(), stateDir)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	ctx, cancel := context.WithTimeout(t.Context(), 200*time.Millisecond)
	defer cancel()
	var output bytes.Buffer
	if err := runAppWatch(ctx, project, stateDir, watchCommand{Output: "ndjson"}, &output); err != nil {
		t.Fatal(err)
	}
	var initial struct {
		Snapshot clientruntime.Snapshot `json:"snapshot"`
	}
	if err := json.Unmarshal(bytes.TrimSpace(output.Bytes()), &initial); err != nil || initial.Snapshot.Cursor != "0:0" || len(initial.Snapshot.Services) != 1 || initial.Snapshot.Services[0].Name != "warehouse" || initial.Snapshot.Services[0].Registered {
		t.Fatalf("database-only watch snapshot = %s, %v", output.String(), err)
	}
	tunnel, err := database.BeginTunnel(t.Context(), clientstate.BeginTunnelOptions{Command: clientstate.TunnelCommandPublish, Server: "https://server.example", Target: "127.0.0.1:3306", Project: project.Root, Service: "warehouse", ServiceProtocol: controlv1.Mysql})
	if err != nil {
		t.Fatal(err)
	}
	defer tunnel.Finish(context.Background(), nil)
	output.Reset()
	ctx, cancel = context.WithTimeout(t.Context(), 200*time.Millisecond)
	defer cancel()
	if err := runAppWatch(ctx, project, stateDir, watchCommand{After: initial.Snapshot.Cursor, Output: "ndjson"}, &output); err != nil {
		t.Fatal(err)
	}
	var event clientruntime.Event
	if err := json.Unmarshal(bytes.TrimSpace(output.Bytes()), &event); err != nil || event.Cursor != "0:1" || event.Type != "service.starting" || event.Service == nil || event.Service.ServiceProtocol != "mysql" {
		t.Fatalf("database-only event = %s, %v", output.String(), err)
	}
}

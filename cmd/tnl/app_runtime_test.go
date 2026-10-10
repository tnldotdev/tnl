package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/clientruntime"
	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/projectconfig"
)

func testAppRuntime(t *testing.T) (*appRuntime, string, <-chan uint64) {
	t.Helper()
	t.Setenv("XDG_RUNTIME_DIR", t.TempDir())
	project, _ := filepath.EvalSymlinks(t.TempDir())
	state, _ := filepath.EvalSymlinks(t.TempDir())
	if err := os.Chmod(state, 0700); err != nil {
		t.Fatal(err)
	}
	a := &appRuntime{project: projectConfiguration{Project: projectconfig.Project{Root: project, Config: config.TNL{Services: config.Services{"api": {}, "web": {}}}, RelativeServiceDirectories: map[string]string{"api": ".", "web": "."}}}, prepared: map[string]appPreparation{}}
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
	socket, err := runtimeSocket(project, state)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: a.handler()}
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() { _ = server.Close() })
	return a, state, started
}

func TestRuntimeAddressReturnsSocketWithoutStartingPublisher(t *testing.T) {
	t.Setenv("TNL_CONFIG", "")
	project, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(project, "tnl.json"), []byte(`{"version":1,"tnl":{"services":{"web":{"directory":"."}}}}`), 0600); err != nil {
		t.Fatal(err)
	}
	state := filepath.Join(t.TempDir(), "state")
	var output bytes.Buffer
	if err := runRuntimeAddress(t.Context(), runtimeOptions{Directory: project, StateDir: state}, &output); err != nil {
		t.Fatal(err)
	}
	var address struct {
		Version int    `json:"version"`
		Socket  string `json:"socket"`
	}
	if err := json.Unmarshal(output.Bytes(), &address); err != nil || address.Version != 1 || address.Socket == "" {
		t.Fatalf("runtime address = %s, error %v", output.String(), err)
	}
	if runtimeAvailable(t.Context(), address.Socket) {
		t.Fatal("address lookup started the local publisher")
	}
}

func TestRuntimeAddressWorksWithoutProjectConfiguration(t *testing.T) {
	t.Setenv("TNL_CONFIG", "")
	directory := t.TempDir()
	state := filepath.Join(t.TempDir(), "state")
	var output bytes.Buffer
	if err := runRuntimeAddress(t.Context(), runtimeOptions{Directory: directory, StateDir: state}, &output); err != nil {
		t.Fatal(err)
	}
	var address struct {
		Version int    `json:"version"`
		Socket  string `json:"socket"`
	}
	if err := json.Unmarshal(output.Bytes(), &address); err != nil || address.Version != 1 || address.Socket == "" || runtimeAvailable(t.Context(), address.Socket) {
		t.Fatalf("unconfigured runtime address = %#v, %v", address, err)
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

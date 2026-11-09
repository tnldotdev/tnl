package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	clientproject "github.com/tnldotdev/tnl/internal/client/project"
	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/failure"
	publisherapp "github.com/tnldotdev/tnl/internal/publisher/app"
)

func TestWaitDoesNotTreatOldSnapshotAsFreshOwnerCheck(t *testing.T) {
	project := projectConfiguration{Project: clientproject.Project{Root: t.TempDir(), Config: config.TNL{Services: config.Services{"web": {}}}}}
	var output bytes.Buffer
	err := runAppWait(t.Context(), project, filepath.Join(t.TempDir(), "state"), waitCommand{Timeout: 10 * time.Millisecond, Output: "json"}, &output)
	if err == nil {
		t.Fatal("wait succeeded without an owner check")
	}
	var result struct {
		State     string `json:"state"`
		CheckedBy string `json:"checked_by"`
		Services  []struct {
			Ready bool `json:"ready"`
		} `json:"services"`
	}
	if decodeErr := json.Unmarshal(output.Bytes(), &result); decodeErr != nil {
		t.Fatal(decodeErr)
	}
	if result.State != "timed out" || result.CheckedBy != "local publisher process unavailable" || len(result.Services) != 1 || result.Services[0].Ready {
		t.Fatalf("wait=%s", output.String())
	}
}

func TestAppWorkflowStandaloneStatusWaitAndWatchNeedNoConfiguration(t *testing.T) {
	project, state, manager, _ := observationFixture(t, true)
	project.Config.Services = nil
	if err := manager.Configure(nil); err != nil {
		t.Fatal(err)
	}
	name := "ivk_" + strings.Repeat("A", 22)
	if err := manager.AddService(publisherapp.Service{Name: name, Directory: ".", ServiceProtocol: "http", Readiness: publisherapp.Readiness{Path: "/"}}); err != nil {
		t.Fatal(err)
	}
	id, err := manager.Reserve(name, "owner", os.Getpid(), "https://app.example")
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.Register(id, "owner", "http://127.0.0.1:3000", "node"); err != nil {
		t.Fatal(err)
	}
	waitObservationFixture(t, manager, func(s publisherapp.Snapshot) bool { return len(s.Services) == 1 && s.Services[0].Routable })
	var checks atomic.Int32
	installObservationChecks(t, project, state, manager, func(_ context.Context, names []string) (publisherapp.Snapshot, error) {
		if !slices.Equal(names, []string{name}) {
			t.Errorf("standalone wait selected another publication: %v", names)
		}
		checks.Add(1)
		snapshot := manager.Snapshot()
		snapshot.Services[0].Ready = true
		return snapshot, nil
	})
	t.Chdir(project.Root)
	var status bytes.Buffer
	if err := runStatus(t.Context(), statusCommand{Output: statusOutputJSON, Scope: "local", StateDir: state.Root(), Project: project.Root, Configuration: project}, &status); err != nil {
		t.Fatal(err)
	}
	var result statusResult
	if err := json.Unmarshal(status.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if len(result.Projects) != 1 || result.Projects[0].Local == nil || len(result.Projects[0].Local.Snapshot.Services) != 1 || result.Projects[0].Local.Snapshot.Services[0].Name != name {
		t.Fatalf("status dropped standalone publication: %s", &status)
	}
	for _, selection := range [][]string{nil, {name}} {
		var output bytes.Buffer
		flags := cli{Wait: waitCommand{StateDir: state.Root(), Service: selection, Timeout: time.Second, Output: "json"}}
		if err := runAppObservation(t.Context(), flags, "wait", &output); err != nil {
			t.Fatalf("standalone wait failed: %v\n%s", err, &output)
		}
		var result struct {
			State    string
			Services []publisherapp.Service
		}
		if err := json.Unmarshal(output.Bytes(), &result); err != nil {
			t.Fatal(err)
		}
		if result.State != "ready" || len(result.Services) != 1 || result.Services[0].Name != name || !result.Services[0].Ready {
			t.Fatalf("standalone wait did not use fresh selected facts: %s", &output)
		}
	}
	if checks.Load() != 2 {
		t.Fatal("wait used cached readiness", checks.Load())
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	watch := &cancelObservationOutput{cancel: cancel}
	if err := runAppObservation(ctx, cli{Watch: watchCommand{StateDir: state.Root(), Output: "ndjson"}}, "watch", watch); err != nil {
		t.Fatal(err)
	}
	var initial struct {
		Type     string
		Snapshot publisherapp.Snapshot
	}
	if err := json.Unmarshal(watch.Bytes(), &initial); err != nil {
		t.Fatal(err)
	}
	if initial.Type != "snapshot" || len(initial.Snapshot.Services) != 1 || initial.Snapshot.Services[0].Name != name || initial.Snapshot.Cursor == "" {
		t.Fatalf("watch lost standalone snapshot: %s", watch)
	}
	if err := manager.Unregister(id, "owner"); err != nil {
		t.Fatal(err)
	}
	ctx, cancelResume := context.WithCancel(t.Context())
	defer cancelResume()
	resume := &cancelObservationOutput{cancel: cancelResume}
	if err := runAppObservation(ctx, cli{Watch: watchCommand{StateDir: state.Root(), After: initial.Snapshot.Cursor, Output: "ndjson"}}, "watch", resume); err != nil {
		t.Fatal(err)
	}
	var event publisherapp.Event
	if err := json.NewDecoder(resume).Decode(&event); err != nil {
		t.Fatal(err)
	}
	if event.Cursor == initial.Snapshot.Cursor || event.Service == nil || event.Service.Name != name {
		t.Fatal("standalone watch did not resume exclusively from its native cursor")
	}
}

type cancelObservationOutput struct {
	bytes.Buffer
	cancel context.CancelFunc
}

func (w *cancelObservationOutput) Write(value []byte) (int, error) {
	n, err := w.Buffer.Write(value)
	w.cancel()
	return n, err
}

func TestAppWorkflowStandaloneWaitNeverAcceptsEmptyOrCachedReadiness(t *testing.T) {
	project := projectConfiguration{Project: clientproject.Project{Root: t.TempDir()}}
	root := filepath.Join(t.TempDir(), "state")
	for _, selected := range [][]string{nil, {"ivk_" + strings.Repeat("A", 22)}} {
		var output bytes.Buffer
		err := runAppWait(t.Context(), project, root, waitCommand{Service: selected, Timeout: 10 * time.Millisecond, Output: "json"}, &output)
		if reason, ok := failure.ReasonOf(err); !ok || reason != failure.AppReadinessTimeout {
			t.Fatal("empty standalone wait lost timeout classification", err)
		}
		if !strings.Contains(output.String(), `"state":"timed out"`) {
			t.Fatalf("empty standalone wait claimed readiness: %s", &output)
		}
	}
}

func TestAppWorkflowStandaloneFreshEmptyOwnerCannotReportReady(t *testing.T) {
	project, state, manager, _ := observationFixture(t, true)
	project.Config.Services = nil
	if err := manager.Configure(nil); err != nil {
		t.Fatal(err)
	}
	var checks atomic.Int32
	installObservationChecks(t, project, state, manager, func(context.Context, []string) (publisherapp.Snapshot, error) {
		checks.Add(1)
		return manager.Snapshot(), nil
	})
	var output bytes.Buffer
	err := runAppWait(t.Context(), project, state.Root(), waitCommand{Timeout: 100 * time.Millisecond, Output: "json"}, &output)
	if reason, ok := failure.ReasonOf(err); !ok || reason != failure.AppReadinessTimeout || checks.Load() == 0 {
		t.Fatal("empty fresh owner passed readiness or was not checked", checks.Load(), err)
	}
}

func TestAppWorkflowStandaloneWaitCapturesFirstRegistrationFromFreshOwner(t *testing.T) {
	project, state, manager, _ := observationFixture(t, true)
	project.Config.Services = nil
	if err := manager.Configure(nil); err != nil {
		t.Fatal(err)
	}
	name := "ivk_" + strings.Repeat("A", 22)
	var checks atomic.Int32
	installObservationChecks(t, project, state, manager, func(context.Context, []string) (publisherapp.Snapshot, error) {
		checks.Add(1)
		// the caller's durable snapshot had no targets. the live owner already
		// has its first invocation and returns a fresh check for that exact key.
		snapshot := manager.Snapshot()
		snapshot.Services = []publisherapp.Service{{Name: name, RegistrationID: "reg_current", Registered: true, Routable: true, Ready: true}}
		return snapshot, nil
	})
	var output bytes.Buffer
	if err := runAppWait(t.Context(), project, state.Root(), waitCommand{Timeout: time.Second, Output: "json"}, &output); err != nil {
		t.Fatal(err)
	}
	var result struct {
		State    string
		Services []publisherapp.Service
	}
	if err := json.Unmarshal(output.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if checks.Load() != 1 || result.State != "ready" || len(result.Services) != 1 || result.Services[0].Name != name {
		t.Fatalf("wait lost a newly discovered exact invocation: %s", &output)
	}
}

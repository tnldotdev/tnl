package local

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	clientproject "github.com/tnldotdev/tnl/internal/client/project"
	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/publisher/app"
	publisherprotocol "github.com/tnldotdev/tnl/internal/publisher/localapi/protocol"
	"github.com/zalando/go-keyring"
)

func processFixture(t *testing.T) (clientproject.Project, *clientstate.Database, []byte, string) {
	t.Helper()
	keyring.MockInit()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	project := clientproject.Project{Root: root, Config: config.TNL{Services: config.Services{"web": {}}}}
	snapshot, _, err := project.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	state, err := clientstate.Open(t.Context(), filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = state.Close() })
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
	project, state, snapshot, path := processFixture(t)
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
	if assignment.RegistrationID == "" || assignment.Service != name {
		t.Fatalf("process did not prepare its configured app: %+v", assignment)
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
	if err := Serve(ctx, Options{Directory: project.Root, StateDir: state.Root(), Snapshot: bytes.NewReader(snapshot)}); err == nil {
		t.Fatal("startup accepted an unusable descriptor path")
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

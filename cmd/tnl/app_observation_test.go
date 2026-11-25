package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	clientproject "github.com/tnldotdev/tnl/internal/client/project"
	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/failure"
	publisherapp "github.com/tnldotdev/tnl/internal/publisher/app"
)

func TestWaitDoesNotTreatOldSnapshotAsFreshOwnerCheck(t *testing.T) {
	for _, name := range []string{"empty state", "saved ready"} {
		t.Run(name, func(t *testing.T) {
			testWaitWithoutOwner(t, name == "saved ready")
		})
	}
}

func testWaitWithoutOwner(t *testing.T, seedReady bool) {
	t.Helper()
	project := projectConfiguration{Project: clientproject.Project{Root: t.TempDir(), Config: config.TNL{Services: config.Services{"web": {}}}}}
	state, err := clientstate.Open(t.Context(), filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := state.Close(); err != nil {
			t.Error(err)
		}
	})
	if seedReady {
		old, err := publisherapp.ReadSnapshotFrom(t.Context(), state, project.Root)
		if err != nil {
			t.Fatal(err)
		}
		old.Services = []publisherapp.Service{{
			Name: "web", Directory: project.Root, RegistrationID: "old-registration", Target: "http://127.0.0.1:3000",
			Registered: true, Routable: true, Ready: true, RunNumber: 7,
			Observation: &publisherapp.Observation{RegistrationID: "old-registration", RunNumber: 7,
				CheckedAt: time.Now().Add(-time.Hour), Status: 204, Ready: true},
		}}
		if err := publisherapp.CommitSnapshot(t.Context(), state, &old, "service.readiness", nil); err != nil {
			t.Fatal(err)
		}
		saved, err := publisherapp.ReadSnapshotFrom(t.Context(), state, project.Root)
		if err != nil || len(saved.Services) != 1 || !saved.Services[0].Ready || saved.Services[0].Observation == nil {
			t.Fatal("fixture did not persist old readiness", saved, err)
		}
	}
	var output bytes.Buffer
	err = runAppWait(t.Context(), project, state.Root(), waitCommand{Timeout: 10 * time.Millisecond, Output: "json"}, &output)
	if reason, _ := failure.ReasonOf(err); reason != failure.AppReadinessTimeout || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("old readiness without an owner did not time out with its original cause", err)
	}
	var result struct {
		State     string `json:"state"`
		CheckedBy string `json:"checked_by"`
		Services  []struct {
			Registered  bool                      `json:"registered"`
			Routable    bool                      `json:"routable"`
			Ready       bool                      `json:"ready"`
			Observation *publisherapp.Observation `json:"observation"`
			Failure     string                    `json:"failure"`
		} `json:"services"`
	}
	if decodeErr := json.Unmarshal(output.Bytes(), &result); decodeErr != nil {
		t.Fatalf("decode wait result: %v; command error: %v; output: %q", decodeErr, err, output.String())
	}
	if result.State != "timed out" || result.CheckedBy != "local publisher process unavailable" || len(result.Services) != 1 || result.Services[0].Ready {
		t.Fatalf("wait=%s", output.String())
	}
	if service := result.Services[0]; service.Registered || service.Routable || service.Observation != nil || service.Failure != "runtime.manager_unavailable" {
		t.Fatalf("wait presented saved readiness as current: %s", output.String())
	}
}

func TestWaitHumanShowsOnlyCheckedServiceResults(t *testing.T) {
	snapshot := publisherapp.Snapshot{Services: []publisherapp.Service{
		{Name: "accounts", Project: "/project", Registered: true, Routable: true, Ready: true, RunNumber: 123, PublicURL: "https://accounts.example.test"},
		{Name: "database", ServiceProtocol: "postgres", Registered: true, Routable: true, Ready: true, Target: "localhost:5432"},
	}}
	var output bytes.Buffer
	if err := writeAppWait(&output, "human", snapshot, "ready", "selected local publisher process (fresh public-path check)"); err != nil {
		t.Fatal(err)
	}
	if got := output.String(); got != "accounts: ready  https://accounts.example.test\ndatabase: ready (target checked; no public URL)\n" {
		t.Fatalf("public and private readiness:\n%s", got)
	}
	snapshot.Services = []publisherapp.Service{{Name: "accounts", Failure: "runtime.manager_unavailable"}}
	output.Reset()
	if err := writeAppWait(&output, "human", snapshot, "timed out", "local publisher process unavailable"); err != nil {
		t.Fatal(err)
	}
	if got := output.String(); got != "Timed out waiting for readiness.\naccounts: readiness not confirmed\nLast error: the local tnl process is unavailable\n" {
		t.Fatalf("unknown readiness at timeout:\n%s", got)
	}
}

func TestWatchReportsOnlyChangesAndNDJSONRetainsEveryEvent(t *testing.T) {
	s := publisherapp.Service{Name: "accounts", Registered: true, Routable: true, Ready: true, PublicURL: "https://accounts.example.test", RunNumber: 19}
	events := []publisherapp.Event{
		{Cursor: "first", Type: "runtime.restarted", Snapshot: &publisherapp.Snapshot{Services: []publisherapp.Service{{Name: "unrelated", Directory: "/private/worktree"}}}},
		{Cursor: "second", Type: "service.registered", Service: &s},
		{Cursor: "third", Type: "service.readiness", Service: &s},
		{Cursor: "fourth", Type: "service.readiness", Service: &s},
		{Cursor: "fifth", Type: "service.unregistered", Service: &s},
		{Cursor: "sixth", Type: "publication.changed", Publication: &clientstate.TunnelInfo{State: clientstate.TunnelStateDraining, ID: "tunnel-private"}},
	}
	var human, ndjson bytes.Buffer
	watch := make(humanWatch)
	for _, e := range events {
		if err := watch.writeEvent(&human, "human", e); err != nil {
			t.Fatal(err)
		}
		if err := watch.writeEvent(&ndjson, "ndjson", e); err != nil {
			t.Fatal(err)
		}
	}
	want := "Local tnl process restarted.\naccounts: registered\naccounts: ready  https://accounts.example.test\naccounts: unregistered\npublication: draining\n"
	if human.String() != want {
		t.Fatalf("watch:\n%s\nwant:\n%s", &human, want)
	}
	lines := strings.Split(strings.TrimSuffix(ndjson.String(), "\n"), "\n")
	if len(lines) != len(events) {
		t.Fatalf("NDJSON dropped events: %s", &ndjson)
	}
	for i, e := range events {
		encoded, err := json.Marshal(e)
		if err != nil || lines[i] != string(encoded) {
			t.Fatalf("NDJSON event %d: %s", i, lines[i])
		}
	}
}

func TestWatchSnapshotDistinguishesTwoPublicationsOfOneService(t *testing.T) {
	app := publisherapp.Service{Name: "web", TunnelID: "tunnel-new", Registered: true, Routable: true, Ready: true, PublicURL: "https://new.example"}
	old := clientstate.TunnelInfo{ID: "tunnel-old", Service: "web", State: clientstate.TunnelStateStale, PublicURL: "https://old.example"}
	watch := make(humanWatch)
	var output bytes.Buffer
	if err := watch.writeSnapshot(&output, publisherapp.Snapshot{Services: []publisherapp.Service{app}, Publications: []clientstate.TunnelInfo{
		old, {ID: app.TunnelID, Service: app.Name, PublicURL: app.PublicURL, State: clientstate.TunnelStateReady},
	}}); err != nil {
		t.Fatal(err)
	}
	for _, e := range []publisherapp.Event{{Type: "service.readiness", Service: &app}, {Type: "publication.changed", Publication: &old}} {
		if err := watch.writeEvent(&output, "human", e); err != nil {
			t.Fatal(err)
		}
	}
	want := "web: ready  https://new.example\nweb publication: stale  https://old.example\n"
	if got := output.String(); got != want {
		t.Fatalf("snapshot and first events:\n%swant:\n%s", got, want)
	}
}

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"path/filepath"
	"slices"
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
	err = runAppWait(t.Context(), project, state.Root(), waitCommand{Timeout: 10 * time.Millisecond, Output: "json"}, &output, nil)
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
		if err := watch.writeEvent(&human, "human", e, false); err != nil {
			t.Fatal(err)
		}
		if err := watch.writeEvent(&ndjson, "ndjson", e, false); err != nil {
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
		if err := watch.writeEvent(&output, "human", e, false); err != nil {
			t.Fatal(err)
		}
	}
	want := "web: ready  https://new.example\nweb publication: stale  https://old.example\n"
	if got := output.String(); got != want {
		t.Fatalf("snapshot and first events:\n%swant:\n%s", got, want)
	}
}

func TestWaitOnlyAcceptsFreshObservationsOfTheCurrentRun(t *testing.T) {
	started := time.Now()
	definition := publisherapp.Service{Name: "accounts", Readiness: publisherapp.Readiness{Path: "/ready"}, ServiceProtocol: "http"}
	for _, tc := range []struct {
		name   string
		change func(*publisherapp.Service)
		ready  bool
		source string
	}{
		{"current private", nil, true, "selected local publisher process (fresh target check)"},
		{"current public", func(s *publisherapp.Service) { s.PublicURL = "https://accounts.example" }, true, "selected local publisher process (fresh public-path check)"},
		{"old check", func(s *publisherapp.Service) { s.Observation.CheckedAt = started.Add(-time.Millisecond) }, false, ""},
		{"old run", func(s *publisherapp.Service) { s.RunNumber++ }, false, ""},
		{"old registration", func(s *publisherapp.Service) { s.RegistrationID = "replaced" }, false, ""},
		{"old readiness rule", func(s *publisherapp.Service) { s.Readiness.Path = "/other" }, false, ""},
		{"no observation", func(s *publisherapp.Service) { s.Observation = nil }, false, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			service := definition
			service.RegistrationID, service.RunNumber = "active", 2
			service.Registered, service.Routable, service.Ready = true, true, true
			service.Observation = &publisherapp.Observation{CheckedAt: started.Add(time.Millisecond), Ready: true, RegistrationID: "active", RunNumber: 2, Readiness: definition.Readiness}
			if tc.change != nil {
				tc.change(&service)
			}
			got, source := waitObservations([]publisherapp.Service{definition}, []publisherapp.Service{service}, started)
			if len(got) != 1 || got[0].Ready != tc.ready || (got[0].Observation != nil) != tc.ready || (tc.source != "" && source != tc.source) {
				t.Fatalf("ready=%t, source=%q, observation=%+v; want ready=%t, source=%q", got[0].Ready, source, got[0].Observation, tc.ready, tc.source)
			}
		})
	}
}

func TestAppObservationArguments(t *testing.T) {
	f := &cli{}
	a := commandApp{flags: f}
	wait := a.newWaitCommand()
	if err := wait.ParseFlags([]string{"accounts", "--service", "web", "api"}); err != nil {
		t.Fatal(err)
	}
	if err := wait.Args(wait, wait.Flags().Args()); err != nil || !slices.Equal(f.Wait.Service, []string{"web", "accounts", "api"}) {
		t.Fatalf("wait service selection = %v, %v", f.Wait.Service, err)
	}

	watch := a.newWatchCommand()
	if err := watch.ParseFlags([]string{"accounts", "--count", "1", "--timeout", "30s"}); err != nil {
		t.Fatal(err)
	}
	if err := watch.Args(watch, watch.Flags().Args()); err != nil || f.Watch.Service != "accounts" || f.Watch.Count != 1 || f.Watch.Timeout != 30*time.Second {
		t.Fatalf("watch options = %+v, %v", f.Watch, err)
	}
	for _, args := range [][]string{
		{"wait", "--service="},
		{"wait", ""},
		{"wait", "--timeout=0"},
		{"watch", "accounts", "api"},
		{"watch", "accounts", "--service=api"},
		{"watch", "--service="},
		{"watch", ""},
		{"watch", "--after="},
		{"watch", "--count=0"},
		{"watch", "--count=-1"},
		{"watch", "--timeout=0"},
		{"watch", "--timeout=-1s"},
	} {
		var stdout, stderr bytes.Buffer
		err := run(t.Context(), args, &stdout, &stderr)
		if reason, _ := failure.ReasonOf(err); reason != failure.InvalidCommand || stdout.Len() != 0 {
			t.Errorf("%v: expected invalid arguments with no output, got %v, %q", args, err, stdout.String())
		}
	}
}

type watchOutputFunc func([]byte) (int, error)

func (f watchOutputFunc) Write(p []byte) (int, error) { return f(p) }

func observationJournal(t *testing.T) (projectConfiguration, *clientstate.Database) {
	t.Helper()
	project := projectConfiguration{Project: clientproject.Project{Root: t.TempDir(), Config: config.TNL{Services: config.Services{"accounts": {}, "api": {}}}}}
	state, err := clientstate.Open(t.Context(), filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = state.Close() })
	return project, state
}

func commitObservationEvent(t *testing.T, state *clientstate.Database, snapshot *publisherapp.Snapshot, name, kind string) string {
	t.Helper()
	var service *publisherapp.Service
	if name != "" {
		service = new(publisherapp.Service{Name: name})
	}
	if err := publisherapp.CommitSnapshot(t.Context(), state, snapshot, kind, service); err != nil {
		t.Fatal(err)
	}
	return snapshot.Cursor
}

func TestWatchCountsMatchingEventsAfterSnapshotAndResumesExclusively(t *testing.T) {
	project, state := observationJournal(t)
	before, err := publisherapp.ReadSnapshotFrom(t.Context(), state, project.Root)
	if err != nil {
		t.Fatal(err)
	}
	snapshot := before
	var output bytes.Buffer
	var first, second string
	writer := watchOutputFunc(func(p []byte) (int, error) {
		if output.Len() == 0 {
			// the initial snapshot is already captured. all events below are
			// in the first poll, so returning exactly at the count is observable.
			commitObservationEvent(t, state, &snapshot, "api", "service.registered")
			commitObservationEvent(t, state, &snapshot, "", "runtime.restarted")
			first = commitObservationEvent(t, state, &snapshot, "accounts", "service.registered")
			second = commitObservationEvent(t, state, &snapshot, "accounts", "service.readiness")
		}
		return output.Write(p)
	})
	flags := watchCommand{Service: "accounts", Count: 1, Timeout: 2 * time.Second, Output: "ndjson"}
	if err := runAppWatch(t.Context(), project, state.Root(), flags, writer); err != nil {
		t.Fatal(err)
	}
	decoder := json.NewDecoder(&output)
	var initial publisherapp.Event
	if err := decoder.Decode(&initial); err != nil || initial.Type != "snapshot" || initial.Snapshot == nil || initial.Snapshot.Cursor != before.Cursor ||
		len(initial.Snapshot.Services) != 1 || initial.Snapshot.Services[0].Name != "accounts" {
		t.Fatalf("unexpected initial snapshot: %+v, %v", initial, err)
	}
	var event publisherapp.Event
	if err := decoder.Decode(&event); err != nil || event.Cursor != first || event.Service == nil || event.Service.Name != "accounts" {
		t.Fatalf("unexpected matching event: %+v, %v", event, err)
	}
	if err := decoder.Decode(new(publisherapp.Event)); !errors.Is(err, io.EOF) {
		t.Fatal("watch emitted more than one matching event", err)
	}

	output.Reset()
	flags.After = event.Cursor
	if err := runAppWatch(t.Context(), project, state.Root(), flags, &output); err != nil {
		t.Fatal(err)
	}
	event = publisherapp.Event{}
	if err := json.Unmarshal(output.Bytes(), &event); err != nil || event.Cursor != second {
		t.Fatalf("resume did not return exactly the next event: %q, %v", output.String(), err)
	}
}

func TestWatchTimeoutPreservesPartialStreamAndCursorScope(t *testing.T) {
	project, state := observationJournal(t)
	snapshot, err := publisherapp.ReadSnapshotFrom(t.Context(), state, project.Root)
	if err != nil {
		t.Fatal(err)
	}
	after := snapshot.Cursor
	lastMatch := commitObservationEvent(t, state, &snapshot, "accounts", "service.registered")
	commitObservationEvent(t, state, &snapshot, "api", "service.registered")
	flags := watchCommand{After: after, Service: "accounts", Count: 2, Timeout: 500 * time.Millisecond, Output: "ndjson"}
	var output bytes.Buffer
	err = runAppWatch(t.Context(), project, state.Root(), flags, &output)
	if reason, _ := failure.ReasonOf(err); reason != failure.AppWatchTimeout || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("partial watch must time out: %v", err)
	}
	var event publisherapp.Event
	if err := json.Unmarshal(output.Bytes(), &event); err != nil || event.Cursor != lastMatch {
		t.Fatalf("timeout lost or added events: %q, %v", output.String(), err)
	}
	otherProject, otherState := observationJournal(t)
	for _, wrongScope := range []struct {
		project projectConfiguration
		root    string
	}{{otherProject, state.Root()}, {project, otherState.Root()}} {
		output.Reset()
		err := runAppWatch(t.Context(), wrongScope.project, wrongScope.root, flags, &output)
		if reason, _ := failure.ReasonOf(err); reason != failure.AppCursorExpired || output.Len() != 0 {
			t.Fatalf("wrong scope did not expire cursor: %v, %q", err, output.String())
		}
	}
}

func TestWatchCountHumanEmitsRepeatedMatchingEvents(t *testing.T) {
	project, state := observationJournal(t)
	snapshot, err := publisherapp.ReadSnapshotFrom(t.Context(), state, project.Root)
	if err != nil {
		t.Fatal(err)
	}
	after := snapshot.Cursor
	for range 2 {
		commitObservationEvent(t, state, &snapshot, "accounts", "service.registered")
	}
	var output bytes.Buffer
	if err := runAppWatch(t.Context(), project, state.Root(), watchCommand{After: after, Count: 2, Timeout: time.Second}, &output); err != nil {
		t.Fatal(err)
	}
	if got := output.String(); got != "accounts: registered\naccounts: registered\n" {
		t.Fatalf("counted watch silently dropped an event: %q", got)
	}
}

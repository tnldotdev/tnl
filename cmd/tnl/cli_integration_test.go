package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/clientstate"
	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/inspection"
	"github.com/tnldotdev/tnl/internal/opaqueid"
	"github.com/tnldotdev/tnl/internal/projectconfig"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

func TestBackgroundDispatchDoesNotOpenForegroundState(t *testing.T) {
	root := t.TempDir()
	t.Chdir(root)
	ordinaryState := filepath.Join(root, "ordinary-state")
	var output, diagnostics bytes.Buffer
	err := run(t.Context(), []string{"--config", "missing.yml", "publish", "3000", "--bg", "--server", "https://control.example", "--state-dir", ordinaryState}, &output, &diagnostics,
		func(string) telemetryReporter {
			t.Fatal("background dispatch selected foreground telemetry")
			return nil
		})
	if err == nil || strings.Contains(err.Error(), "missing.yml") || strings.Contains(err.Error(), "command is required") {
		t.Fatalf("background dispatch = %v", err)
	}
	if _, err := os.Stat(ordinaryState); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("background dispatch opened foreground state: %v", err)
	}
	if output.Len() != 0 || diagnostics.Len() != 0 {
		t.Fatalf("invalid background selection prompted or printed: %q, %q", output.String(), diagnostics.String())
	}
}

func TestEnrolledDispatchRejectsMixedAuthorityBeforeSignIn(t *testing.T) {
	var output, diagnostics bytes.Buffer
	root := filepath.Join(t.TempDir(), "state")
	err := runPublish(t.Context(), publishCommand{EnrollmentKey: "-", PublisherID: "pub_example", Output: publishOutputHuman, remoteFlags: remoteFlags{StateDir: root}}, &output, &diagnostics)
	if reason, ok := failure.ReasonOf(err); !ok || reason != failure.InvalidTunnelFlags {
		t.Fatalf("mixed enrollment selection = %v", err)
	}
	if _, err := os.Stat(root); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("mixed enrollment selection opened state: %v", err)
	}
	if strings.Contains(diagnostics.String(), "sign in") || strings.Contains(diagnostics.String(), "login token") {
		t.Fatalf("mixed enrollment selection prompted: %s", diagnostics.String())
	}
}

func TestConfiguredAppPublicationDoesNotRequireAnAddress(t *testing.T) {
	root := t.TempDir()
	project := projectConfiguration{Project: projectconfig.Project{Root: root, Worktree: namedTestWorktree(root, "shop"), Config: config.TNL{Services: config.Services{"web": {Target: &config.ServiceTarget{Type: "app"}}}}}}
	flags := publishCommand{Target: "web"}
	if err := project.applyPublish(&flags); err != nil {
		t.Fatal(err)
	}
	if flags.Service != "web" || flags.Target != "" || flags.project.Root != root || flags.Protocol != "http" {
		t.Fatalf("app publication selection = %+v", flags)
	}
}

func TestConfigRejectsRemovedPublicFields(t *testing.T) {
	for _, body := range []string{
		`{"services":{"web":{"directory":"."}}}`,
		`{"publish":{"target":3000}}`,
		`{"readiness":{"path":"/health"}}`,
		`{"services":{"web":{"publish":{"target":3000}}}}`,
		`{"services":{"web":{"paths":{"/api":"api"}},"api":{}}}`,
		`{"tunnel":{"limits":{"requests":10}}}`,
		`{"tunnel":{"limits":{"rate":{"requests":2,"per":"1m"}}}}`,
	} {
		t.Run(body, func(t *testing.T) {
			root := t.TempDir()
			path := filepath.Join(root, "tnl.json")
			if err := os.WriteFile(path, []byte(`{"version":1,"tnl":`+body+`}`), 0o600); err != nil {
				t.Fatal(err)
			}
			_, err := loadProjectConfigurationWithSalt(t.Context(), cli{ConfigPath: path}, [32]byte{})
			if reason, ok := failure.ReasonOf(err); !ok || reason != failure.ProjectConfigInvalid {
				t.Fatalf("removed configuration accepted: %v", err)
			}
		})
	}
}

type visitorListStub struct {
	pages   map[string]controlv1.AvailablePublicURLPage
	teams   []string
	cursors []string
}

func (s *visitorListStub) ListAvailablePublicURLs(_ context.Context, team, cursor string) (controlv1.AvailablePublicURLPage, error) {
	s.teams = append(s.teams, team)
	s.cursors = append(s.cursors, cursor)
	return s.pages[cursor], nil
}

func TestVisitorURLListFiltersWithoutTeamMembership(t *testing.T) {
	teamID, err := opaqueid.New(opaqueid.TeamPrefix)
	if err != nil {
		t.Fatal(err)
	}
	next := "second"
	first := controlv1.AvailablePublicURL{Id: "first", TeamId: teamID, TeamName: "studio"}
	second := controlv1.AvailablePublicURL{Id: "second", TeamId: "other", TeamName: "another"}
	for _, team := range []string{"", "studio", teamID} {
		stub := &visitorListStub{pages: map[string]controlv1.AvailablePublicURLPage{
			"":   {PublicUrls: []controlv1.AvailablePublicURL{first}, NextCursor: &next},
			next: {PublicUrls: []controlv1.AvailablePublicURL{second}},
		}}
		items, err := visitorURLList(t.Context(), stub, team)
		if err != nil {
			t.Fatal(err)
		}
		want := []controlv1.AvailablePublicURL{first}
		if team == "" {
			want = append(want, second)
		}
		if !reflect.DeepEqual(items, want) || !reflect.DeepEqual(stub.cursors, []string{"", next}) {
			t.Fatalf("team %q: items=%+v, cursors=%v", team, items, stub.cursors)
		}
		serverFilter := ""
		if team == teamID {
			serverFilter = teamID
		}
		if !reflect.DeepEqual(stub.teams, []string{serverFilter, serverFilter}) {
			t.Fatalf("team %q leaked a name into the team-ID filter: %v", team, stub.teams)
		}
	}
}

func TestVisitorURLListRejectsCursorCycles(t *testing.T) {
	first, second := "first", "second"
	stub := &visitorListStub{pages: map[string]controlv1.AvailablePublicURLPage{
		"": {NextCursor: &first}, first: {NextCursor: &second}, second: {NextCursor: &first},
	}}
	if _, err := visitorURLList(t.Context(), stub, ""); err == nil {
		t.Fatal("visitor inventory cursor cycle was accepted")
	}
}

func TestSummaryRecorderKeepsHTTPAndDatabaseResults(t *testing.T) {
	root := t.TempDir()
	state, err := clientstate.OpenWithOptions(t.Context(), filepath.Join(root, "state"), clientstate.OpenOptions{Protection: clientstate.ProtectionFile})
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	tunnel, err := state.BeginTunnel(t.Context(), clientstate.BeginTunnelOptions{Command: clientstate.TunnelCommandPublish, Server: "https://control.example", Target: "3000", Project: root})
	if err != nil {
		t.Fatal(err)
	}
	defer tunnel.Finish(context.Background(), nil)
	retention, budget := config.Duration(time.Hour), config.ByteSize(1<<20)
	recorder, err := newInspectionRecorder(t.Context(), tunnel, root, "", config.InspectionSummary, &config.Inspection{Retention: &retention, MaxBytes: &budget})
	if err != nil {
		t.Fatal(err)
	}
	observe := summaryObservation(recorder)
	now := time.Now()
	observe(inspection.Summary{Protocol: "http", ReceivedAt: now, Method: "GET", Path: "/orders", Status: 503, Result: inspection.ResultError, Duration: 2 * time.Millisecond, Origin: "local_service"})
	observe(inspection.Summary{Protocol: "mysql", ReceivedAt: now.Add(time.Millisecond), Operation: inspection.OperationExecute, Result: inspection.ResultError, SQLState: "HY000", MySQLErrorCode: 1045, Rows: 1, ResultSets: 2, Duration: 3 * time.Millisecond, Origin: "tnl"})
	recorder.Close()
	_, shared, err := inspectionRoots(t.Context(), root)
	if err != nil {
		t.Fatal(err)
	}
	items, err := state.ListInspections(t.Context(), clientstate.InspectionFilter{Project: root, SharedProject: shared, Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 2 || items[0].Protocol != controlv1.Mysql || items[0].MySQLErrorCode != 1045 || items[0].ResultSets != 2 || items[0].Result != inspection.ResultError || items[1].Protocol != controlv1.Http || items[1].Origin != "local_service" || items[1].Method != "GET" || items[1].Path != "/orders" || items[1].Status != 503 || items[1].Result != "" {
		t.Fatalf("recorded summaries = %+v", items)
	}
}

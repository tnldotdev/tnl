package main

import (
	"bytes"
	"context"
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/tnldotdev/tnl/internal/clientruntime"
	"github.com/tnldotdev/tnl/internal/clientstate"
	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/projectconfig"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

func TestStatusSnapshotIncludesDirectAndNamedPublicationCursor(t *testing.T) {
	root := filepath.Join(t.TempDir(), "state")
	state, err := clientstate.Open(t.Context(), root)
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	projectRoot, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	project := projectConfiguration{Project: projectconfig.Project{Root: projectRoot, Config: config.TNL{Services: config.Services{"web": {}}}}}
	for _, service := range []string{"", "web"} {
		tunnel, err := state.BeginTunnel(t.Context(), clientstate.BeginTunnelOptions{Command: clientstate.TunnelCommandPublish, Server: "https://control.example", Project: projectRoot, Service: service, Target: "http://127.0.0.1:3000", ServiceProtocol: controlv1.PublicURLServiceProtocol("http")})
		if err != nil {
			t.Fatal(err)
		}
		defer tunnel.Finish(context.Background(), nil)
	}
	var output bytes.Buffer
	if err := runStatus(t.Context(), statusCommand{Output: "json", Scope: "local", StateDir: root, Project: projectRoot, Configuration: project}, &output); err != nil {
		t.Fatal(err)
	}
	var result statusResult
	if err := json.Unmarshal(output.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if len(result.Projects) != 1 || result.Projects[0].Local == nil || result.Projects[0].Server != nil {
		t.Fatalf("status=%s", output.String())
	}
	snapshot := result.Projects[0].Local.Snapshot
	if len(snapshot.Publications) != 2 || len(snapshot.Services) != 1 || snapshot.Cursor == "" {
		t.Fatalf("status=%s", output.String())
	}
	events, err := clientruntime.EventsAfterFrom(t.Context(), state, projectRoot, snapshot.Cursor)
	if err != nil || len(events) != 0 {
		t.Fatalf("status cursor is not native exclusive cursor: %v", err)
	}
}

func TestStatusAllKeepsIndependentProjectCursors(t *testing.T) {
	root := filepath.Join(t.TempDir(), "state")
	state, err := clientstate.Open(t.Context(), root)
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	for range 2 {
		project, _ := filepath.EvalSymlinks(t.TempDir())
		if _, err := state.ReadRuntimeSnapshot(t.Context(), project); err != nil {
			t.Fatal(err)
		}
	}
	var output bytes.Buffer
	if err := runStatus(t.Context(), statusCommand{Output: "json", Scope: "local", StateDir: root, All: true}, &output); err != nil {
		t.Fatal(err)
	}
	var all statusResult
	if err := json.Unmarshal(output.Bytes(), &all); err != nil {
		t.Fatal(err)
	}
	if len(all.Projects) != 2 || all.Projects[0].Local.Snapshot.Cursor == all.Projects[1].Local.Snapshot.Cursor {
		t.Fatalf("project cursors=%s", output.String())
	}
}

func TestStatusKeepsLocalFactsWhenControlIsUnavailable(t *testing.T) {
	root := filepath.Join(t.TempDir(), "state")
	project := t.TempDir()
	var output bytes.Buffer
	if err := runStatus(t.Context(), statusCommand{Output: statusOutputJSON, Scope: "both", StateDir: root, Project: project, Configuration: projectConfiguration{Project: projectconfig.Project{Root: project}}, ServerURL: "https://127.0.0.1:1"}, &output); err != nil {
		t.Fatal(err)
	}
	var result statusResult
	if err := json.Unmarshal(output.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if len(result.Projects) != 1 || result.Projects[0].Local == nil || !result.Projects[0].Local.Available || result.Projects[0].Server == nil || result.Projects[0].Server.Available || result.Projects[0].Server.Reason == "" {
		t.Fatalf("status=%s", output.String())
	}
	if result.Projects[0].Local.Snapshot.Cursor == "" || result.Projects[0].Server.CheckedAt.IsZero() {
		t.Fatalf("missing source timestamps/cursor: %s", output.String())
	}
}

func TestStatusDefaultsToBothAndKeepsLocalFactsWithAnUnreachableServer(t *testing.T) {
	project := t.TempDir()
	var output bytes.Buffer
	if err := runStatus(t.Context(), statusCommand{Output: statusOutputJSON, StateDir: filepath.Join(t.TempDir(), "state"), Project: project, Configuration: projectConfiguration{Project: projectconfig.Project{Root: project}}, ServerURL: "https://127.0.0.1:1"}, &output); err != nil {
		t.Fatal(err)
	}
	var result statusResult
	if err := json.Unmarshal(output.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.Scope != "both" || len(result.Projects) != 1 || result.Projects[0].Local == nil || result.Projects[0].Server == nil || result.Projects[0].Server.Available {
		t.Fatalf("offline default status = %s", output.String())
	}
}

func TestServerInventoryOnlyShowsThisProjectsIDsAndDoesNotGuessRunState(t *testing.T) {
	open := "run_ours"
	items := statusURLsForProject([]controlv1.PublicURL{
		{Id: "url_other", CanonicalHostname: "other.example"},
		{Id: "url_ours", CanonicalHostname: "ours.example", LifecycleState: controlv1.Enabled, OpenPublishRunId: &open},
	}, map[string]bool{"url_ours": true})
	if len(items) != 1 || items[0].Hostname != "ours.example" || items[0].OpenRunID != open || items[0].RunState != "unavailable (control has no publish run status read)" {
		t.Fatalf("scoped server inventory = %+v", items)
	}
}

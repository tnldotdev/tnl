package main

import (
	"bytes"
	"context"
	"encoding/json"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	clientproject "github.com/tnldotdev/tnl/internal/client/project"
	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	"github.com/tnldotdev/tnl/internal/config"
	publisherapp "github.com/tnldotdev/tnl/internal/publisher/app"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
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
	project := projectConfiguration{Project: clientproject.Project{Root: projectRoot, Config: config.TNL{Services: config.Services{"web": {}}}}}
	for _, service := range []string{"", "web"} {
		tunnel, err := state.BeginTunnel(t.Context(), clientstate.BeginTunnelOptions{Command: clientstate.TunnelCommandPublish, Server: "https://control.example", Project: projectRoot, Service: service, Target: "http://127.0.0.1:3000", ServiceProtocol: controlv1.ServiceProtocolHTTP})
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
	output.Reset()
	if err := runStatus(t.Context(), statusCommand{Service: "web", Output: "json", Scope: "local", StateDir: root, Project: projectRoot, Configuration: project}, &output); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(output.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	local := result.Projects[0].Local
	if len(local.Snapshot.Publications) != 1 || local.Snapshot.Publications[0].Service != "web" ||
		local.Tunnels.Summary.Total != 1 || len(local.Tunnels.Tunnels) != 1 || local.Tunnels.Tunnels[0].Service != "web" {
		t.Fatalf("service filter mixed direct and named publications: %s", &output)
	}
	events, err := publisherapp.EventsAfterFrom(t.Context(), state, projectRoot, snapshot.Cursor)
	if err != nil || len(events) != 0 {
		t.Fatalf("status cursor is not native exclusive cursor: %v", err)
	}
}

func TestStatusServiceSelectsAppliedBindingsByNameAndInventoryByID(t *testing.T) {
	id := "svc_web"
	project := projectStatus{Server: &statusServer{
		Applied:  &controlv1.AppliedProjectConfiguration{Services: []controlv1.AppliedProjectService{{Service: "web", ServiceId: &id}, {Service: "other"}}},
		Services: []statusServerService{{ServiceID: id, Name: "web-myworktree"}, {ServiceID: "svc_other", Name: "other"}},
	}}
	project.Server.selectService("web", clientstate.TunnelSnapshot{})
	if s := project.Server; s.Applied != nil || len(s.AppliedServices) != 1 || s.AppliedServices[0].Service != "web" ||
		len(s.Services) != 1 || s.Services[0].ServiceID != id {
		t.Fatalf("filtered status = %+v", s)
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
	state, err := clientstate.Open(t.Context(), root)
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	tunnel, err := state.BeginTunnel(t.Context(), clientstate.BeginTunnelOptions{
		Command: clientstate.TunnelCommandPublish, Server: "https://127.0.0.1:1", Project: project,
		ServiceID: "svc_0123456789abcdefghijkl", Target: "http://127.0.0.1:3000",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer tunnel.Finish(context.Background(), nil)
	var output bytes.Buffer
	if err := runStatus(t.Context(), statusCommand{Output: statusOutputJSON, Scope: "both", StateDir: root, Project: project, Configuration: projectConfiguration{Project: clientproject.Project{Root: project}}, ServerURL: "https://127.0.0.1:1"}, &output); err != nil {
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
	if len(result.Projects[0].Local.Tunnels.Tunnels) != 1 || result.Projects[0].Local.Tunnels.Tunnels[0].ServiceID != "svc_0123456789abcdefghijkl" ||
		result.Projects[0].Server.Reason != "control API or signed-in session unavailable" {
		t.Fatalf("offline status lost the local service or skipped its server read: %s", output.String())
	}
}

func TestStatusDefaultsToBothAndKeepsLocalFactsWithAnUnreachableServer(t *testing.T) {
	project := t.TempDir()
	var output bytes.Buffer
	if err := runStatus(t.Context(), statusCommand{Output: statusOutputJSON, StateDir: filepath.Join(t.TempDir(), "state"), Project: project, Configuration: projectConfiguration{Project: clientproject.Project{Root: project}}, ServerURL: "https://127.0.0.1:1"}, &output); err != nil {
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

func TestStatusServicesForProjectPreservesFactsWithoutGuessingLifecycle(t *testing.T) {
	created := time.Date(2026, time.November, 14, 12, 0, 0, 0, time.UTC)
	run, number := "sr_0123456789abcdefghijkl", int64(37)
	httpEndpoint := &controlv1.ServiceEndpoint{Hostname: "web.example.test", Public: true, Port: 443}
	connectorEndpoint := &controlv1.ServiceEndpoint{Hostname: "database.example.test", Public: false, Port: 0}
	reservedEndpoint := &controlv1.ServiceEndpoint{Hostname: "reserved.example.test", Public: false, Port: 15432}
	services := []controlv1.ServiceSummary{
		{Id: "svc_other", Name: "other"},
		{Id: "svc_web", Name: "web", Protocol: controlv1.ServiceProtocolHTTP, Enabled: true, CreatedAt: created, Endpoint: httpEndpoint, ServiceRunId: &run, RunNumber: &number},
		{Id: "svc_database", Name: "database", Protocol: controlv1.Postgres, Enabled: true, CreatedAt: created, Endpoint: connectorEndpoint},
		{Id: "svc_reserved", Name: "reserved", Protocol: controlv1.Postgres, CreatedAt: created, Endpoint: reservedEndpoint},
		{Id: "svc_no_endpoint", Name: "no-endpoint", Protocol: controlv1.Tcp, Enabled: true, CreatedAt: created},
		{Id: "svc_web", Name: "duplicate"},
	}
	ids := map[string]bool{"svc_web": true, "svc_database": true, "svc_reserved": true, "svc_no_endpoint": true, "svc_not_visible": true}
	items := statusServicesForProject(services, ids)
	want := []statusServerService{
		{ServiceID: "svc_web", Name: "web", Protocol: controlv1.ServiceProtocolHTTP, Enabled: true, CreatedAt: created, Endpoint: httpEndpoint,
			ServiceRunID: &run, RunNumber: &number, PublisherObservation: "ready_publisher_hint"},
		{ServiceID: "svc_database", Name: "database", Protocol: controlv1.Postgres, Enabled: true, CreatedAt: created, Endpoint: connectorEndpoint, PublisherObservation: "no_ready_publisher_observed"},
		{ServiceID: "svc_reserved", Name: "reserved", Protocol: controlv1.Postgres, CreatedAt: created, Endpoint: reservedEndpoint, PublisherObservation: "no_ready_publisher_observed"},
		{ServiceID: "svc_no_endpoint", Name: "no-endpoint", Protocol: controlv1.Tcp, Enabled: true, CreatedAt: created, PublisherObservation: "no_ready_publisher_observed"},
	}
	if !reflect.DeepEqual(items, want) || !reflect.DeepEqual(ids, map[string]bool{"svc_not_visible": true}) {
		t.Fatalf("scoped service inventory = %+v, remaining IDs = %v", items, ids)
	}
}

func TestStatusServiceJSONUsesFreshV1ServiceFacts(t *testing.T) {
	run, number := "sr_fixture", int64(37)
	services := statusServicesForProject([]controlv1.ServiceSummary{
		{Id: "svc_ready", ServiceRunId: &run, RunNumber: &number, Endpoint: &controlv1.ServiceEndpoint{Hostname: "web.example.test", Port: 443}},
		{Id: "svc_saved", Protocol: controlv1.Postgres, Endpoint: &controlv1.ServiceEndpoint{Hostname: "database.example.test", Port: 0}},
	}, map[string]bool{"svc_ready": true, "svc_saved": true})
	encoded, err := json.Marshal(statusResult{SchemaVersion: 1, Scope: "server", Projects: []projectStatus{{Project: "/project",
		Server: &statusServer{Available: true, Services: services},
	}}})
	if err != nil {
		t.Fatal(err)
	}
	var decoded struct {
		SchemaVersion int `json:"schema_version"`
		Projects      []struct {
			Server map[string]json.RawMessage `json:"server"`
		} `json:"projects"`
	}
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.SchemaVersion != 1 || len(decoded.Projects) != 1 {
		t.Fatalf("fresh status schema = %s", encoded)
	}
	server := decoded.Projects[0].Server
	if _, legacy := server["public_urls"]; legacy {
		t.Fatalf("status retained a second inventory: %s", encoded)
	}
	var inventory []map[string]json.RawMessage
	if err := json.Unmarshal(server["services"], &inventory); err != nil || len(inventory) != 2 {
		t.Fatalf("service inventory = %s: %v", encoded, err)
	}
	if string(inventory[0]["service_id"]) != `"svc_ready"` || string(inventory[0]["service_run_id"]) != `"sr_fixture"` ||
		string(inventory[0]["run_number"]) != `"37"` || string(inventory[0]["publisher_observation"]) != `"ready_publisher_hint"` {
		t.Fatalf("ready-publisher hint changed its meaning or run number: %s", encoded)
	}
	if string(inventory[1]["publisher_observation"]) != `"no_ready_publisher_observed"` ||
		inventory[1]["service_run_id"] != nil || inventory[1]["run_number"] != nil {
		t.Fatalf("absence of a hint invented a service run: %s", encoded)
	}
	for _, item := range inventory {
		for _, key := range []string{"public_url_id", "updated_at", "lifecycle_state", "open_publish_run_id", "next_publish_run_number", "next_run_number", "publish_run_state", "run_state", "ready", "routable"} {
			if _, exists := item[key]; exists {
				t.Fatalf("status invented unavailable lifecycle facts (%s): %s", key, encoded)
			}
		}
	}
}

func TestStatusServiceHumanOutputUsesHintsAndIndependentEndpointFacts(t *testing.T) {
	run, number := "sr_fixture", int64(37)
	services := statusServicesForProject([]controlv1.ServiceSummary{
		{Id: "svc_ready", Name: "web", Enabled: true, Protocol: controlv1.ServiceProtocolHTTP, ServiceRunId: &run, RunNumber: &number,
			Endpoint: &controlv1.ServiceEndpoint{Hostname: "web.example.test", Port: 443}},
		{Id: "svc_saved", Name: "database", Protocol: controlv1.Postgres,
			Endpoint: &controlv1.ServiceEndpoint{Hostname: "database.example.test", Port: 0}},
		{Id: "svc_no_endpoint", Name: "private", Protocol: controlv1.Tcp},
	}, map[string]bool{"svc_ready": true, "svc_saved": true, "svc_no_endpoint": true})
	var output bytes.Buffer
	if err := writeHumanFrame(&output, "tnl status", "1 project", "", statusServiceBlocks(services)...); err != nil {
		t.Fatal(err)
	}
	got := output.String()
	normalized := strings.Join(strings.Fields(strings.ReplaceAll(got, "|", " ")), " ")
	for _, fragment := range []string{"+--[ tnl status ]--", "server enabled", "server disabled", "service ID svc_ready", "protocol postgres",
		"ready publisher hint; not a selected visitor run", "service run ID hint sr_fixture", "run number hint 37",
		"no ready publisher observed", "public false", "endpoint port 443", "endpoint port 0", "endpoint not reported"} {
		if !strings.Contains(normalized, fragment) {
			t.Fatalf("status human output missing %q:\n%s", fragment, got)
		}
	}
	for _, fragment := range []string{"public URL ID", "open publish run", "next publish run", "publish run state", "server updated at"} {
		if strings.Contains(got, fragment) {
			t.Fatalf("status human output retained %q:\n%s", fragment, got)
		}
	}
	for _, line := range strings.Split(got, "\n") {
		if len(line) > 72 {
			t.Fatalf("status bypassed renderer width: %q", line)
		}
	}
}

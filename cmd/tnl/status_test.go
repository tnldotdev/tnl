package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	clientproject "github.com/tnldotdev/tnl/internal/client/project"
	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/failure"
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
	if err := runStatus(t.Context(), statusCommand{Output: "json", LastKnown: true, StateDir: root, Project: projectRoot, Configuration: project}, &output); err != nil {
		t.Fatal(err)
	}
	var result statusResult
	if err := json.Unmarshal(output.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.Scope != "local" || len(result.Projects) != 1 || result.Projects[0].Local == nil || result.Projects[0].Server != nil {
		t.Fatalf("status=%s", output.String())
	}
	snapshot := result.Projects[0].Local.Snapshot
	if len(snapshot.Publications) != 2 || len(snapshot.Services) != 1 || snapshot.Cursor == "" {
		t.Fatalf("status=%s", output.String())
	}
	output.Reset()
	if err := runStatus(t.Context(), statusCommand{Service: "web", Output: "json", LastKnown: true, StateDir: root, Project: projectRoot, Configuration: project}, &output); err != nil {
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
	if matched, err := project.Server.selectService("web", clientstate.TunnelSnapshot{}, true); err != nil || !matched {
		t.Fatalf("could not select web: %v", err)
	}
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
	if err := runStatus(t.Context(), statusCommand{Output: "json", LastKnown: true, StateDir: root, All: true}, &output); err != nil {
		t.Fatal(err)
	}
	var all statusResult
	if err := json.Unmarshal(output.Bytes(), &all); err != nil {
		t.Fatal(err)
	}
	if len(all.Projects) != 2 || all.Projects[0].Local.Snapshot.Cursor == all.Projects[1].Local.Snapshot.Cursor {
		t.Fatalf("project cursors=%s", output.String())
	}
	output.Reset()
	if err := runStatus(t.Context(), statusCommand{LastKnown: true, StateDir: root, All: true}, &output); err != nil {
		t.Fatal(err)
	}
	for _, p := range all.Projects {
		if !strings.Contains(output.String(), filepath.Base(p.Project)+": No local publications.") || strings.Contains(output.String(), p.Local.Snapshot.Cursor) {
			t.Fatalf("expected a distinct result per project: %s", &output)
		}
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
	if err := runStatus(t.Context(), statusCommand{Output: statusOutputJSON, StateDir: root, Project: project, Configuration: projectConfiguration{Project: clientproject.Project{Root: project}}, ServerURL: "https://127.0.0.1:1"}, &output); err != nil {
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
			Endpoint: &controlv1.ServiceEndpoint{Hostname: "web.example.test", Public: true, Port: 443}},
		{Id: "svc_saved", Name: "database", Protocol: controlv1.Postgres,
			Endpoint: &controlv1.ServiceEndpoint{Hostname: "database.example.test", Port: 15432}},
		{Id: "svc_no_endpoint", Name: "private", Protocol: controlv1.Tcp},
	}, map[string]bool{"svc_ready": true, "svc_saved": true, "svc_no_endpoint": true})
	var output bytes.Buffer
	if err := writeStatus(&output, statusCommand{ServerOnly: true}, []projectStatus{{Server: &statusServer{Available: true, ControlURL: "https://control.example", Services: services}}}); err != nil {
		t.Fatal(err)
	}
	want := "Server: https://control.example\n" +
		"SERVICE   STATE     PROTOCOL  ACCESS          ADDRESS\n" +
		"web       enabled   http      public          https://web.example.test\n" +
		"database  disabled  postgres  connector-only  -\n" +
		"private   disabled  tcp       not reported    -\n"
	if got := output.String(); got != want {
		t.Fatalf("server status:\n%s\nwant:\n%s", got, want)
	}
}

const statusAccountsURL = "https://accounts-tnl-dev.m-pnnmceidbvki5sik2qxb6eacq4.quirky-snap.tnl.dev"

func statusAccounts() projectStatus {
	at := time.Unix(1000, 0).UTC()
	tunnel := clientstate.TunnelInfo{ID: "tunnel-1", Project: "/local/project", Service: "accounts", State: clientstate.TunnelStateReady,
		Server: "https://control.example", PublicURL: statusAccountsURL, ServiceProtocol: controlv1.ServiceProtocolHTTP,
		ServiceID: "svc-accounts", ServiceRunID: "run-42", PublishRunNumber: 42}
	service := publisherapp.Service{
		Name: tunnel.Service, TunnelID: tunnel.ID, PublicURL: tunnel.PublicURL, Registered: true, Routable: true, Ready: true,
		RunNumber: 42, RegistrationID: "reg-current", Readiness: publisherapp.Readiness{Path: "/health"},
		Observation: &publisherapp.Observation{RegistrationID: "reg-current", RunNumber: 42, Readiness: publisherapp.Readiness{Path: "/health"}, CheckedAt: at, Status: 204, Ready: true},
	}
	inventory := statusServicesForProject([]controlv1.ServiceSummary{{Id: tunnel.ServiceID, Name: "accounts-worktree", Enabled: true,
		Protocol: controlv1.ServiceProtocolHTTP, Endpoint: &controlv1.ServiceEndpoint{Public: true, Hostname: strings.TrimPrefix(tunnel.PublicURL, "https://"), Port: 443},
	}}, map[string]bool{tunnel.ServiceID: true})
	return projectStatus{Project: tunnel.Project, Local: &statusLocal{Available: true, CheckedAt: at,
		Snapshot: publisherapp.Snapshot{Services: []publisherapp.Service{service}}, Tunnels: clientstate.TunnelSnapshot{Tunnels: []clientstate.TunnelInfo{tunnel}}},
		Server: &statusServer{Available: true, ControlURL: tunnel.Server, Services: inventory,
			Applied: &controlv1.AppliedProjectConfiguration{
				ServiceDeclarations: controlv1.ProjectServiceDeclarations{service.Name: controlv1.ServiceProtocolHTTP},
				Services:            []controlv1.AppliedProjectService{{Service: service.Name, Deployment: "local", ServiceKind: "local"}},
			}}}
}

func statusTranscript(t *testing.T, flags statusCommand, projects ...projectStatus) string {
	t.Helper()
	var output bytes.Buffer
	if err := writeStatus(&output, flags, projects); err != nil {
		t.Fatal(err)
	}
	return output.String()
}

func TestStatusHumanRecordedReadinessListAndDetail(t *testing.T) {
	project := statusAccounts()
	flags := statusCommand{Configuration: projectConfiguration{Project: clientproject.Project{Config: config.TNL{Services: config.Services{"accounts": {}}}}}}
	render := func(want string) {
		t.Helper()
		if got := statusTranscript(t, flags, project); got != want {
			t.Fatalf("status:\n%swant:\n%s", got, want)
		}
	}
	render("SERVICE   READY  URL\naccounts  Yes    " + statusAccountsURL + "\n")
	s := &project.Local.Snapshot.Services[0]
	s.Ready, s.Routable, s.Failure = false, false, string(failure.ServerResponseInvalid)
	render("SERVICE   READY    URL\naccounts  Unknown  " + statusAccountsURL + "\n")
	project.Server = nil
	flags.Service = "accounts"
	render("Service     accounts\nURL         " + statusAccountsURL + "\nReady       Unknown\nLast error  The server returned an unexpected response.\n\ntnl wait accounts\n")
	flags.StateDir, flags.configArgs = "/private/tnl state", configArgs(false, "/local/app config.ts")
	const command = "\ntnl --config='/local/app config.ts' wait accounts --state-dir='/private/tnl state'\n"
	render("Service     accounts\nURL         " + statusAccountsURL + "\nReady       Unknown\nLast error  The server returned an unexpected response.\n" + command)
	s.Routable = true
	s.Observation.Ready, s.Observation.Status, s.Observation.Reason = false, 503, "runtime.probe_rejected"
	render("Service  accounts\nURL      " + statusAccountsURL + "\nReady    No (HTTP 503)\n" + command)
	project.Local.Tunnels.Tunnels[0].State = clientstate.TunnelStateStale
	project.Local.Tunnels.Tunnels[0].HeartbeatAt = project.Local.CheckedAt.Add(-10 * time.Minute)
	render("Service     accounts\nURL         " + statusAccountsURL + "\nReady       Unknown (stale)\nLast seen   10 minutes ago\nLast error  The server returned an unexpected response.\n" + command)
}

func TestStatusReadinessNeedsACurrentObservation(t *testing.T) {
	for _, test := range []struct {
		name string
		edit func(*publisherapp.Service, *clientstate.TunnelInfo)
		want string
	}{
		{"no check", func(s *publisherapp.Service, _ *clientstate.TunnelInfo) { s.Observation = nil }, "Unknown"},
		{"old run", func(s *publisherapp.Service, _ *clientstate.TunnelInfo) { s.Observation.RunNumber-- }, "Unknown"},
		{"new tunnel run", func(_ *publisherapp.Service, t *clientstate.TunnelInfo) { t.PublishRunNumber++ }, "Unknown"},
		{"old registration", func(s *publisherapp.Service, _ *clientstate.TunnelInfo) { s.Observation.RegistrationID = "reg-old" }, "Unknown"},
		{"old check path", func(s *publisherapp.Service, _ *clientstate.TunnelInfo) { s.Observation.Readiness.Path = "/" }, "Unknown"},
		{"draining", func(_ *publisherapp.Service, t *clientstate.TunnelInfo) { t.State = clientstate.TunnelStateDraining }, "Unknown"},
		{"target changed", func(s *publisherapp.Service, _ *clientstate.TunnelInfo) {
			s.Ready, s.Observation.Ready, s.Observation.Reason = false, false, "runtime.target_changed"
		}, "Unknown"},
		{"target only", func(s *publisherapp.Service, t *clientstate.TunnelInfo) { s.PublicURL, t.PublicURL = "", "" }, "Yes (target only)"},
	} {
		t.Run(test.name, func(t *testing.T) {
			project := statusAccounts()
			project.Server = nil
			test.edit(&project.Local.Snapshot.Services[0], &project.Local.Tunnels.Tunnels[0])
			got := statusTranscript(t, statusCommand{Service: "accounts"}, project)
			if !strings.Contains(got, "Ready    "+test.want+"\n") && !strings.Contains(got, "Ready       "+test.want+"\n") {
				t.Fatalf("status:\n%s", got)
			}
		})
	}
}

func TestStatusBothKeepsIndependentServerFacts(t *testing.T) {
	for name, edit := range map[string]func(*statusServer){
		"server":     func(s *statusServer) { s.ControlURL += ".other" },
		"identity":   func(s *statusServer) { s.Services[0].ServiceID = "svc-other" },
		"run number": func(s *statusServer) { s.Services[0].RunNumber = new(int64(43)) },
		"run ID":     func(s *statusServer) { s.Services[0].ServiceRunID = new("run-other") },
		"endpoint":   func(s *statusServer) { s.Services[0].Endpoint.Hostname = "other.example.test" },
		"disabled":   func(s *statusServer) { s.Services[0].Enabled = false },
		"access":     func(s *statusServer) { s.Services[0].Endpoint.Public = false },
	} {
		t.Run(name, func(t *testing.T) {
			project := statusAccounts()
			edit(project.Server)
			got := statusTranscript(t, statusCommand{}, project)
			if !strings.HasPrefix(got, "SERVICE   READY  URL\naccounts  Yes") || !strings.Contains(got, "accounts-worktree") {
				t.Fatalf("missing an independent observation:\n%s", got)
			}
		})
	}
	project := statusAccounts()
	project.Server.Applied.Services[0].ServiceId = new("another-service")
	got := statusTranscript(t, statusCommand{}, project)
	if !strings.Contains(got, "DEPLOYMENT") {
		t.Fatalf("local app name hid a distinct applied binding:\n%s", got)
	}
}

func TestStatusHumanDistinguishesRemoteFromMissingLocalService(t *testing.T) {
	var output bytes.Buffer
	project := projectStatus{Local: &statusLocal{Available: true}, Server: &statusServer{Available: true, AppliedServices: []controlv1.AppliedProjectService{
		{Service: "accounts", Deployment: "production", ServiceKind: "service", ServiceId: new("svc-accounts"), Hostname: new("accounts.test")},
	}}}
	flags := statusCommand{Service: "accounts", Configuration: projectConfiguration{Project: clientproject.Project{Config: config.TNL{Deployment: "production"}}}}
	if err := writeStatus(&output, flags, []projectStatus{project}); err != nil {
		t.Fatal(err)
	}
	if got := output.String(); got != "Deployment production is remote. No local publications.\n\nService     accounts\nURL         -\nReady       Unknown\nDeployment  production\nAccess      connector-only\n" {
		t.Fatalf("remote service:\n%s", got)
	}
}

func TestStatusSelectedServiceCombinesLocalCheckAndServerObservation(t *testing.T) {
	project := statusAccounts()
	flags := statusCommand{Service: "accounts", Configuration: projectConfiguration{Project: clientproject.Project{Config: config.TNL{Services: config.Services{"accounts": {}}}}}}
	got := statusTranscript(t, flags, project)
	want := "Service     accounts\nURL         " + statusAccountsURL + "\nReady       Yes\nServer      https://control.example\n" +
		"State       enabled\nProtocol    http\nAccess      public\nPublisher   none reported\nDeployment  local\n"
	if got != want {
		t.Fatalf("combined status:\n%swant:\n%s", got, want)
	}
	project.Server.Services[0].PublisherObservation = "ready_publisher_hint"
	project.Server.Services[0].RunNumber = new(int64(42))
	project.Local.Snapshot.Services[0].Observation = nil
	got = statusTranscript(t, flags, project)
	if strings.Count(got, statusAccountsURL) != 1 || !strings.Contains(got, "Publisher   reported\n") || !strings.Contains(got, "Ready       Unknown\n") {
		t.Fatalf("server hint supplied app readiness or duplicated the service:\n%s", got)
	}
	project = statusAccounts()
	project.Server = nil
	project.Local.Snapshot.Services[0].PublicURL = ""
	project.Local.Tunnels.Tunnels[0].PublicURL = ""
	got = statusTranscript(t, flags, project)
	if got != "Service  accounts\nURL      -\nReady    Yes (target only)\n" {
		t.Fatalf("target check suggested a public readiness check:\n%s", got)
	}
}

func TestStatusSelectedServerInventoryDoesNotClaimReadiness(t *testing.T) {
	server := &statusServer{Available: true, Services: []statusServerService{{Name: "db", ServiceID: "svc-db", Protocol: controlv1.Postgres,
		Endpoint: &controlv1.ServiceEndpoint{Hostname: "db.test", Port: 15432}, RunNumber: new(int64(3)), PublisherObservation: "ready_publisher_hint"}},
		Applied: &controlv1.AppliedProjectConfiguration{ServiceDeclarations: controlv1.ProjectServiceDeclarations{"db": controlv1.Postgres},
			Services: []controlv1.AppliedProjectService{{Service: "db", ServiceId: new("svc-db"), ServiceKind: "service",
				Deployment: "production", Hostname: new("db.test"), Port: new(15432)}}}}
	if matched, err := server.selectService("db", clientstate.TunnelSnapshot{}, true); err != nil || !matched {
		t.Fatalf("could not select db: %v", err)
	}
	got := statusTranscript(t, statusCommand{ServerOnly: true, Service: "db"}, projectStatus{Server: server})
	want := "Service        db\nURL            -\nReady          Unknown\nState          disabled\nProtocol       postgres\n" +
		"Access         connector-only\nPublisher      reported\nReserved port  15432\nDeployment     production\n"
	if got != want {
		t.Fatalf("server detail:\n%swant:\n%s", got, want)
	}
}

func TestStatusBothMatchesConnectorOnlyInventoryOnlyWithRunEvidence(t *testing.T) {
	project := statusAccounts()
	local, tunnel := &project.Local.Snapshot.Services[0], &project.Local.Tunnels.Tunnels[0]
	local.PublicURL, tunnel.PublicURL = "", ""
	project.Server.Applied = nil
	item := &project.Server.Services[0]
	item.Endpoint.Public = false
	for _, test := range []struct {
		name string
		run  *int64
		host string
		join bool
	}{
		{"matching private run", new(int64(42)), "private.test", true},
		{"absent run", nil, "private.test", false},
		{"different run", new(int64(43)), "private.test", false},
		{"no valid endpoint", new(int64(42)), "", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			item.RunNumber, item.Endpoint.Hostname = test.run, test.host
			got := statusTranscript(t, statusCommand{Service: local.Name}, project)
			if strings.Contains(got, item.Name) == test.join || !strings.Contains(got, "Yes (target only)") || strings.Contains(got, "private.test") {
				t.Fatalf("connector-only details:\n%s", got)
			}
		})
	}
}

func TestStatusAllFilteredKeepsProjectColumn(t *testing.T) {
	var projects []projectStatus
	for _, path := range []string{"/home/me/one/site", "/home/me/two/site", "/home/me/other"} {
		p := statusAccounts()
		p.Project, p.Server = path, nil
		projects = append(projects, p)
	}
	got := statusTranscript(t, statusCommand{All: true, Service: "accounts"}, projects...)
	want := "PROJECT   SERVICE   READY  URL\n" +
		"one/site  accounts  Yes    " + statusAccountsURL + "\n" +
		"two/site  accounts  Yes    " + statusAccountsURL + "\n" +
		"other     accounts  Yes    " + statusAccountsURL + "\n"
	if got != want {
		t.Fatalf("multi-project status:\n%swant:\n%s", got, want)
	}
}

func TestStatusSeparatesIntegrationStateFromServiceReadiness(t *testing.T) {
	local := &statusLocal{Available: true, Tunnels: clientstate.TunnelSnapshot{
		Tunnels: []clientstate.TunnelInfo{{ID: "one", Service: "web", State: clientstate.TunnelStateReady, PublicURL: "https://web.test"}},
		IntegrationURLs: []clientstate.IntegrationURLInfo{{Kind: "webhooks", State: "ready", PublicURL: "https://hooks.test",
			Endpoints: []clientstate.WebhookEndpointInfo{{Name: "event", Service: "web", State: "stale", URL: "https://hooks.test/event"}}}},
		Aliases: []clientstate.AliasInfo{{Name: "review", Service: "web", State: "ready", PublicURL: "https://review.test", SelectedProject: "/work/site"}},
	}}
	got := statusTranscript(t, statusCommand{}, projectStatus{Local: local})
	want := "SERVICE  READY    URL\nweb      Unknown  https://web.test\n\n" +
		"INTEGRATION  STATE  URL\nwebhooks     ready  https://hooks.test\n\n" +
		"WEBHOOK  SERVICE  STATE  URL\nevent    web      stale  https://hooks.test/event\n\n" +
		"ALIAS   SERVICE  STATE  URL                  SELECTED WORKTREE\nreview  web      ready  https://review.test  /work/site\n"
	if got != want {
		t.Fatalf("integration status:\n%swant:\n%s", got, want)
	}
	u := &local.Tunnels.IntegrationURLs[0]
	expired, _ := failure.DefinitionFor(failure.IntegrationURLLeaseExpired)
	u.State, u.Reason, u.Action = "stale", failure.IntegrationURLLeaseExpired, expired.Action
	u.Endpoints[0].Reason, u.Endpoints[0].Action = u.Reason, u.Action
	alias := &local.Tunnels.Aliases[0]
	missing, _ := failure.DefinitionFor(failure.AliasReceiverUnready)
	alias.State, alias.Reason, alias.Action = "unavailable", failure.AliasReceiverUnready, missing.Action
	got = statusTranscript(t, statusCommand{}, projectStatus{Local: local})
	prose := strings.Join(strings.Fields(got), " ")
	for _, fact := range []string{"webhooks, webhook event: " + expired.Message, expired.Action, "alias review: " + missing.Message, missing.Action} {
		if strings.Count(prose, fact) != 1 {
			t.Fatalf("expected one %q in:\n%s", fact, got)
		}
	}
}

func TestStatusKeepsAvailableFactsAndWarnsOnUnreadableScope(t *testing.T) {
	var diagnostics bytes.Buffer
	flags := statusCommand{diagnostics: &diagnostics}
	project := statusAccounts()
	project.Server = &statusServer{ControlURL: "https://control.example", Reason: "identity inventory unavailable"}
	got := statusTranscript(t, flags, project)
	if got != "SERVICE   READY  URL\naccounts  Yes    "+statusAccountsURL+"\n" ||
		diagnostics.String() != "Server status unavailable: identity inventory unavailable\n(https://control.example)\n" {
		t.Fatalf("partial status:\n%sdiagnostics:\n%s", got, &diagnostics)
	}
	diagnostics.Reset()
	project.Local, project.Server = nil, &statusServer{Available: true}
	got = statusTranscript(t, flags, project)
	if got != "No server service records.\n" || diagnostics.Len() != 0 {
		t.Fatalf("empty server status:\n%sdiagnostics:\n%s", got, &diagnostics)
	}
}

func TestStatusBothReadsServerDespiteUnreadableAppJournal(t *testing.T) {
	origin, token, _ := statusTestControl(t, []string{statusTestTeamOne}, func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(controlv1.ServicePage{Services: []controlv1.ServiceSummary{{
			Id: statusTestSavedID, Name: "database", Protocol: controlv1.Postgres, Enabled: true,
		}}})
	})
	state := statusTestDatabase(t)
	project := t.TempDir()
	tunnel := statusTestTunnel(t, state, origin, project, statusTestSavedID)
	if err := tunnel.Finish(t.Context(), nil); err != nil {
		t.Fatal(err)
	}
	snapshot, err := state.ReadRuntimeSnapshot(t.Context(), project)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := state.CommitRuntimeUpdate(t.Context(), project, clientstate.RuntimeUpdate{
		ExpectedCursor: snapshot.Cursor, Type: "service.readiness", Payload: json.RawMessage(`{}`),
		Services: []json.RawMessage{json.RawMessage(`{"ready":"invalid"}`)},
	}); err != nil {
		t.Fatal(err)
	}
	var out, diagnostics bytes.Buffer
	flags := statusCommand{StateDir: state.Root(), ServerURL: origin, AccessToken: token, Project: project, diagnostics: &diagnostics,
		Configuration: projectConfiguration{Project: clientproject.Project{Root: project}}}
	err = runStatus(t.Context(), flags, &out)
	if _, ok := errors.AsType[*json.UnmarshalTypeError](err); !ok {
		t.Fatalf("lost original app journal read error: %v", err)
	}
	if !strings.Contains(out.String(), "database") || strings.Contains(out.String(), "No local publications") || diagnostics.Len() != 0 {
		t.Fatalf("server inventory with an unreadable app journal:\n%sdiagnostics:\n%s", &out, &diagnostics)
	}
	out.Reset()
	flags.ServerOnly, flags.Output = true, statusOutputJSON
	if err := runStatus(t.Context(), flags, &out); err != nil {
		t.Fatalf("server-only status read its unrequested app journal: %v", err)
	}
	var result statusResult
	if err := json.Unmarshal(out.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.Scope != "server" || len(result.Projects) != 1 || result.Projects[0].Local != nil || len(result.Projects[0].Server.Services) != 1 {
		t.Fatalf("wrong server-only status: %s", &out)
	}
}

func TestStatusLastKnownKeepsSavedFailureAfterOwnerExit(t *testing.T) {
	state, directory := statusTestDatabase(t), t.TempDir()
	origin, token, requests := statusTestControl(t, []string{statusTestTeamOne}, func(http.ResponseWriter, *http.Request) {
		t.Error("last-known status must not contact control")
	})
	statusTestTunnel(t, state, origin, directory, statusTestSavedID)
	project := projectConfiguration{Project: clientproject.Project{
		Root: directory, Config: config.TNL{Services: config.Services{"accounts": {}}},
	}}
	saved, err := publisherapp.ReadSnapshotFrom(t.Context(), state, directory)
	if err != nil {
		t.Fatal(err)
	}
	saved.Services = []publisherapp.Service{{
		Name: "accounts", Registered: true, PublicURL: statusAccountsURL, RegistrationID: "registration",
		RunNumber: 1, Readiness: publisherapp.Readiness{Path: "/"}, Failure: string(failure.ServerResponseInvalid),
		Observation: &publisherapp.Observation{RegistrationID: "registration", RunNumber: 1, CheckedAt: time.Now().Add(-11 * time.Minute)},
	}}
	if err := publisherapp.CommitSnapshot(t.Context(), state, &saved, "service.readiness", &saved.Services[0]); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := runStatus(t.Context(), statusCommand{
		Project: directory, Configuration: project, StateDir: state.Root(), LastKnown: true, Service: "accounts", ServerURL: origin, AccessToken: token,
	}, &out); err != nil {
		t.Fatal(err)
	}
	for _, fact := range []string{statusAccountsURL, "Ready         Unknown", "Last checked  11 minutes ago",
		"Last error    The server returned an unexpected response.", "\ntnl wait accounts --state-dir=" + state.Root() + "\n"} {
		if !strings.Contains(out.String(), fact) {
			t.Fatalf("missing %q in recorded detail:\n%s", fact, &out)
		}
	}
	if got := requests(); len(got) != 0 {
		t.Fatalf("last-known status made network requests: %v", got)
	}
}

func TestStatusDoesNotShowStalePublicationOverItsReplacement(t *testing.T) {
	project := statusAccounts()
	current := &project.Local.Tunnels.Tunnels[0]
	current.StartedAt = project.Local.CheckedAt.Add(-time.Minute)
	old := *current
	old.ID, old.State, old.PublicURL = "old", clientstate.TunnelStateStale, "https://old.example.test"
	old.StartedAt = current.StartedAt.Add(-time.Minute)
	project.Local.Tunnels.Tunnels = append([]clientstate.TunnelInfo{old}, project.Local.Tunnels.Tunnels...)
	got := statusTranscript(t, statusCommand{Service: "accounts"}, project)
	if !strings.Contains(got, "Ready       Yes") || strings.Contains(got, old.PublicURL) {
		t.Fatalf("stale tunnel obscured its current replacement:\n%s", got)
	}
	// a service with the same local name but a different ID is independent.
	project.Local.Tunnels.Tunnels[0].ServiceID = "another-service"
	got = statusTranscript(t, statusCommand{Service: "accounts"}, project)
	if !strings.Contains(got, old.PublicURL) || !strings.Contains(got, "Unknown (stale)") {
		t.Fatalf("independent stale tunnel was hidden:\n%s", got)
	}
}

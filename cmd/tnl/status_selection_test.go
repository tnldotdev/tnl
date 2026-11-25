package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	"github.com/tnldotdev/tnl/internal/control/api/serviceaccess"
	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/naming"
	publisherapp "github.com/tnldotdev/tnl/internal/publisher/app"
	publisherprotocol "github.com/tnldotdev/tnl/internal/publisher/localapi/protocol"
	"github.com/tnldotdev/tnl/internal/security/credentials"
	authorityv1 "github.com/tnldotdev/tnl/pkg/api/control/authority/v1"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestStatusSelectsStoppedServiceByConfiguredSourceName(t *testing.T) {
	const otherID = "svc_0000000000000000000002"
	summary := func(id, name string) controlv1.ServiceSummary {
		return serviceaccess.Summary(controlstate.ServiceRecord{
			ID: id, TeamID: statusTestTeamOne, Name: name, Enabled: true, ServiceMetadata: controlstate.ServiceMetadata{Protocol: "http"},
			Source: &controlstate.LocalServiceSource{ProjectKey: "shop", Service: "web", SourceFingerprint: strings.Repeat("a", 64), WorktreeKey: strings.Repeat("b", 64)},
		})
	}
	origin, token, _ := statusTestControl(t, []string{statusTestTeamOne}, func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(controlv1.ServicePage{Services: []controlv1.ServiceSummary{
			summary(statusTestSavedID, "web-0123456789"), summary(otherID, "web-aaaaaaaaaa"),
		}})
	})
	state, project := statusTestDatabase(t), t.TempDir()
	for root, id := range map[string]string{project: statusTestSavedID, t.TempDir(): otherID} {
		tunnel := statusTestTunnel(t, state, origin, root, id)
		if err := tunnel.Finish(t.Context(), nil); err != nil {
			t.Fatal(err)
		}
	}
	var output bytes.Buffer
	flags := statusCommand{ServerOnly: true, Project: project, StateDir: state.Root(), ServerURL: origin, AccessToken: token, Service: "web", Output: statusOutputJSON}
	if err := runStatus(t.Context(), flags, &output); err != nil {
		t.Fatal(err)
	}
	var result statusResult
	if err := json.Unmarshal(output.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if len(result.Projects) != 1 || result.Projects[0].Server == nil || len(result.Projects[0].Server.Services) != 1 {
		t.Fatalf("selected inventory: %s", &output)
	}
	got := result.Projects[0].Server.Services[0]
	if got.ServiceID != statusTestSavedID || got.Name != "web-0123456789" || got.ServiceRunID != nil || got.RunNumber != nil ||
		strings.Contains(output.String(), `"source`) {
		t.Fatalf("source name changed inventory identity, scope or wire shape: %s", &output)
	}
	flags.Output = statusOutputHuman
	output.Reset()
	if err := runStatus(t.Context(), flags, &output); err != nil {
		t.Fatal(err)
	}
	fields := strings.Join(strings.Fields(output.String()), " ")
	if !strings.Contains(fields, "Service web URL") || !strings.Contains(fields, "Saved name web-0123456789") || strings.Contains(fields, "web-aaaaaaaaaa") {
		t.Fatalf("selected configured service:\n%s", &output)
	}
}

func TestStatusAllFetchesTheRecordedProjectsSelectedDeployment(t *testing.T) {
	const remote = "https://example.test/shop.git"
	source, err := (naming.GitProjectSource{GitOrigin: remote, ConfigurationPath: "tnl.json"}).Identity()
	if err != nil {
		t.Fatal(err)
	}
	access, _, _, err := credentials.NewAccessToken()
	if err != nil {
		t.Fatal(err)
	}
	refresh, _, _, err := credentials.NewRefreshToken()
	if err != nil {
		t.Fatal(err)
	}
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method != http.MethodGet || r.URL.Path != "/v1/discovery" && r.Header.Get("Authorization") != "Bearer "+access.String() {
			t.Error("status did not make the scoped authenticated read")
			w.WriteHeader(http.StatusForbidden)
			return
		}
		switch r.URL.Path {
		case "/v1/discovery":
			_ = json.NewEncoder(w).Encode(controlv1.ControlDiscovery{ManagedDomain: "example.test", ManagedUrlMode: "generated",
				Authentication: controlv1.AuthenticationFacts{Methods: []controlv1.AuthenticationFactsMethods{"oidc"}, Oidc: &controlv1.OIDCAuthenticationFacts{Issuer: "https://issuer.example.test", LoginFlow: "device_code"}}})
		case "/v1/identity":
			_ = json.NewEncoder(w).Encode(authorityv1.IdentityContext{PersonalTeamId: statusTestTeamOne, Memberships: []authorityv1.Membership{{TeamId: statusTestTeamOne, Role: "owner"}}})
		case "/v1/teams/" + statusTestTeamOne:
			_ = json.NewEncoder(w).Encode(authorityv1.Team{Id: statusTestTeamOne})
		case "/v1/projects/" + source.Key + "/configuration":
			if r.URL.Query().Get("deployment") != "staging" || r.URL.Query().Get("team_id") != statusTestTeamOne {
				t.Errorf("fetched the wrong applied configuration: %s", r.URL)
			}
			_ = json.NewEncoder(w).Encode(controlstate.AppliedProjectConfiguration{
				ProjectKey: source.Key, SourceFingerprint: source.Fingerprint, TeamID: statusTestTeamOne, Deployment: "staging",
				ServiceDeclarations: map[string]string{"db": "postgres"},
				Services:            []controlstate.AppliedProjectService{{Service: "db", Deployment: "staging", Kind: "service", ServiceID: statusTestSavedID, Hostname: "db.example.test"}},
			})
		default:
			t.Errorf("unexpected status request: %s", r.URL)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer origin.Close()
	previous := http.DefaultTransport
	http.DefaultTransport = origin.Client().Transport
	defer func() { http.DefaultTransport = previous }()
	state := statusTestDatabase(t)
	if err := state.SaveServer(t.Context(), "https://127.0.0.1:1"); err != nil {
		t.Fatal(err)
	}
	profile, err := state.Server(t.Context(), origin.URL)
	if err != nil {
		t.Fatal(err)
	}
	if err := profile.SaveControlSession(t.Context(), clientstate.ControlSession{SessionID: "cs_0123456789abcdefghijkl",
		AccessToken: access.String(), RefreshToken: refresh.String(), AccessExpiresAt: time.Now().Add(time.Hour), RefreshExpiresAt: time.Now().Add(24 * time.Hour)}); err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	initIgnoreRepository(t, root)
	initIgnoreGit(t, root, "remote", "add", "origin", remote)
	// resolving local first would fail: that deployment has no Compose file.
	document := fmt.Sprintf(`{"version":1,"tnl":{"server":%q,"services":{"db":{"protocol":"postgres"}},"deployments":{"local":{"targets":{"db":{"type":"compose","service":"db","port":5432}}},"staging":{"targets":{"db":{"address":"staging.internal:5432"}}}}}}`, origin.URL)
	if err := os.WriteFile(filepath.Join(root, "tnl.json"), []byte(document), 0600); err != nil {
		t.Fatal(err)
	}
	// a local tunnel on a different server must not override project configuration.
	statusTestTunnel(t, state, "https://127.0.0.1:2", root, statusTestSavedID)
	var output bytes.Buffer
	if err := runStatus(t.Context(), statusCommand{ServerOnly: true, All: true, StateDir: state.Root(), Deployment: "staging", Output: statusOutputJSON}, &output); err != nil {
		t.Fatal(err)
	}
	var result statusResult
	if err := json.Unmarshal(output.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if len(result.Projects) != 1 || result.Projects[0].Server == nil {
		t.Fatalf("missing project: %s", &output)
	}
	server := result.Projects[0].Server
	if server.ControlURL != origin.URL || server.Applied == nil || server.Applied.Deployment != "staging" || len(server.Applied.Services) != 1 ||
		server.Applied.Services[0].Service != "db" || server.Applied.Services[0].Public != nil {
		t.Fatalf("wrong server, deployment or applied wire record: %s", &output)
	}
}

func TestStatusStaleLeaseOnlyInvalidatesItsOwnRegistration(t *testing.T) {
	project, state, _, endpoint := observationFixture(t, false)
	path, err := publisherprotocol.DescriptorPath(state.Root(), project.Root)
	if err != nil {
		t.Fatal(err)
	}
	if err := publisherprotocol.WriteEndpoint(path, endpoint); err != nil {
		t.Fatal(err)
	}
	const target = "http://127.0.0.1:3000"
	options := clientstate.BeginTunnelOptions{Command: clientstate.TunnelCommandPublish, Project: project.Root, Service: "web", Target: target, Server: "https://control.example.test"}
	begin := func() *clientstate.Tunnel {
		// keep the journal row and stop heartbeats, as after an owner exit.
		ctx, cancel := context.WithCancel(t.Context())
		tunnel, err := state.BeginTunnel(ctx, options)
		cancel()
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = tunnel.Finish(context.Background(), nil) })
		if err := tunnel.SetReady(t.Context(), "https://web.example.test", 1); err != nil {
			t.Fatal(err)
		}
		return tunnel
	}
	old, current := begin(), begin()
	db, err := sql.Open("sqlite", clientstate.DatabasePath(state.Root()))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	saved, err := publisherapp.ReadSnapshotFrom(t.Context(), state, project.Root)
	if err != nil {
		t.Fatal(err)
	}
	saved.Services = []publisherapp.Service{{Name: "web", Target: target, TunnelID: current.ID(), RegistrationID: "reg-current", RunNumber: 1, Registered: true, Routable: true, Ready: true,
		Readiness: publisherapp.Readiness{Path: "/"}, Observation: &publisherapp.Observation{RegistrationID: "reg-current", RunNumber: 1, Readiness: publisherapp.Readiness{Path: "/"}, Ready: true, CheckedAt: time.Now()}}}
	if err := publisherapp.CommitSnapshot(t.Context(), state, &saved, "service.readiness", nil); err != nil {
		t.Fatal(err)
	}
	for _, tunnel := range []*clientstate.Tunnel{old, current} {
		if _, err := db.ExecContext(t.Context(), "UPDATE local_tunnels SET lease_expires_at = heartbeat_at WHERE id = ?", tunnel.ID()); err != nil {
			t.Fatal(err)
		}
		snapshot, err := readAppSnapshotFrom(t.Context(), project, state)
		if err != nil {
			t.Fatal(err)
		}
		index := slices.IndexFunc(snapshot.Services, func(s publisherapp.Service) bool { return s.Name == "web" })
		if index < 0 {
			t.Fatal("missing web registration")
		}
		s := snapshot.Services[index]
		wantReady := tunnel == old
		if s.Registered != wantReady || s.Routable != wantReady || s.Ready != wantReady || (s.Observation != nil) != wantReady {
			t.Fatalf("expired tunnel %s, current %s: %+v", tunnel.ID(), current.ID(), s)
		}
	}
}

func TestStatusPreservesPartialReadAndWriteErrors(t *testing.T) {
	state := statusTestDatabase(t)
	project, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	const origin = "https://127.0.0.1:1"
	statusTestTunnel(t, state, origin, project, statusTestSavedID)
	snapshot, err := state.ReadRuntimeSnapshot(t.Context(), project)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := state.CommitRuntimeUpdate(t.Context(), project, clientstate.RuntimeUpdate{
		Type: "service.readiness", ExpectedCursor: snapshot.Cursor, Payload: json.RawMessage(`{}`), Services: []json.RawMessage{json.RawMessage(`{"ready":"invalid"}`)},
	}); err != nil {
		t.Fatal(err)
	}
	writeErr := errors.New("partial result write failed")
	err = runStatus(t.Context(), statusCommand{StateDir: state.Root(), Project: project, ServerURL: origin}, errorWriter{writeErr})
	var readErr *json.UnmarshalTypeError
	if !errors.As(err, &readErr) || !errors.Is(err, writeErr) {
		t.Fatalf("missing independent read or write failure: %v", err)
	}
}

func TestStatusAddressAndIDSelectOnlyExactLocalRecords(t *testing.T) {
	const secondID = "svc_0000000000000000000002"
	state := statusTestDatabase(t)
	directory, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, fixture := range []struct{ id, url string }{
		{statusTestSavedID, "https://accounts.example.test"},
		{secondID, "https://accounts-preview.example.test"},
	} {
		tunnel, err := state.BeginTunnel(t.Context(), clientstate.BeginTunnelOptions{
			Command: clientstate.TunnelCommandPublish, Server: "https://control.example", Project: directory,
			Service: "accounts", ServiceID: fixture.id, Target: "http://127.0.0.1:3000",
		})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = tunnel.Finish(context.Background(), nil) })
		if err := tunnel.SetReady(t.Context(), fixture.url, 1); err != nil {
			t.Fatal(err)
		}
	}
	flags := statusCommand{Project: directory, StateDir: state.Root(), LastKnown: true, Output: statusOutputJSON}
	for selector, want := range map[string]string{
		"HTTPS://ACCOUNTS.EXAMPLE.TEST:443/": statusTestSavedID,
		"accounts-preview.example.test:443":  secondID,
		statusTestSavedID:                    statusTestSavedID,
	} {
		t.Run(selector, func(t *testing.T) {
			var out bytes.Buffer
			flags.Service = selector
			if err := runStatus(t.Context(), flags, &out); err != nil {
				t.Fatal(err)
			}
			var result statusResult
			if err := json.Unmarshal(out.Bytes(), &result); err != nil {
				t.Fatal(err)
			}
			local := result.Projects[0].Local
			if len(local.Tunnels.Tunnels) != 1 || len(local.Snapshot.Publications) != 1 || local.Tunnels.Summary.Total != 1 ||
				local.Tunnels.Tunnels[0].ServiceID != want || local.Snapshot.Publications[0].ServiceID != want {
				t.Fatalf("exact selection widened: %s", &out)
			}
		})
	}
	for selector, reason := range map[string]failure.Reason{
		"acounts":                            failure.ServiceNotConfigured,
		"accounts.example.test:4430":         failure.ServiceNotConfigured,
		"https://accounts.example.test/path": failure.InvalidCommand,
	} {
		t.Run(selector, func(t *testing.T) {
			var out bytes.Buffer
			flags.Service = selector
			err := runStatus(t.Context(), flags, &out)
			if got, _ := failure.ReasonOf(err); got != reason || out.Len() != 0 {
				t.Fatalf("bad selector widened or returned the wrong error: %v, %s", err, &out)
			}
		})
	}
}

func TestStatusServerEndpointMatchesProtocolAndExactPort(t *testing.T) {
	const secondID = "svc_0000000000000000000002"
	for raw, want := range map[string]string{
		"postgres://DATABASE.EXAMPLE.TEST/":       statusTestSavedID,
		"postgresql://database.example.test:5432": statusTestSavedID,
		"database.example.test:15432":             secondID,
		"database.example.test":                   "ambiguous",
		"https://database.example.test:5432":      "",
	} {
		t.Run(raw, func(t *testing.T) {
			project := projectStatus{Server: &statusServer{Services: []statusServerService{
				{ServiceID: statusTestSavedID, Protocol: controlv1.Postgres, Endpoint: &controlv1.ServiceEndpoint{Hostname: "database.example.test", Port: 5432}},
				{ServiceID: secondID, Protocol: controlv1.Postgres, Endpoint: &controlv1.ServiceEndpoint{Hostname: "database.example.test", Port: 15432}},
			}}}
			selector, err := naming.ParseServiceSelector(raw)
			if err != nil {
				t.Fatal(err)
			}
			matched, err := selectStatusService(&project, selector, clientstate.TunnelSnapshot{})
			if want == "ambiguous" {
				if reason, _ := failure.ReasonOf(err); reason != failure.InvalidCommand {
					t.Fatalf("expected an ambiguous endpoint error, got %v", err)
				}
				message := presentHumanFailure(err).message
				if !strings.Contains(message, statusTestSavedID) || !strings.Contains(message, secondID) {
					t.Fatalf("ambiguous endpoint did not identify its choices: %s", message)
				}
			} else if err != nil || matched != (want != "") || matched && (len(project.Server.Services) != 1 || project.Server.Services[0].ServiceID != want) {
				t.Fatalf("exact endpoint selection failed: %+v, %v, %v", project.Server.Services, matched, err)
			}
		})
	}
}

func TestStatusNameKeepsAppliedIDsAndRejectsConflictingSavedNames(t *testing.T) {
	project := projectStatus{Server: &statusServer{
		Applied: &controlv1.AppliedProjectConfiguration{Services: []controlv1.AppliedProjectService{
			{Service: "accounts", ServiceId: new("svc_selected")},
			{Service: "api", ServiceId: new("svc_unrelated")},
		}},
		Services: []statusServerService{
			{ServiceID: "svc_selected", Name: "accounts-worktree"},
			{ServiceID: "svc_unrelated", Name: "accounts", sourceName: "accounts"},
		},
	}}
	matched, err := selectStatusService(&project, naming.ServiceSelector{Kind: naming.SelectorName, Name: "accounts"}, clientstate.TunnelSnapshot{})
	if err != nil || !matched || project.Server.Applied != nil || len(project.Server.AppliedServices) != 1 ||
		len(project.Server.Services) != 1 || project.Server.Services[0].ServiceID != "svc_selected" {
		t.Fatalf("selection crossed applied binding: %+v, %v", project.Server, err)
	}
}

func TestStatusAllDoesNotInferServerFromOnlySelectedService(t *testing.T) {
	state, directory := statusTestDatabase(t), t.TempDir()
	origin, token, requests := statusTestControl(t, []string{statusTestTeamOne}, func(http.ResponseWriter, *http.Request) {
		t.Error("mixed checkout must not query the selected service's server implicitly")
	})
	for name, server := range map[string]string{"accounts": origin, "api": "https://another.example.test"} {
		tunnel, err := state.BeginTunnel(t.Context(), clientstate.BeginTunnelOptions{
			Command: clientstate.TunnelCommandPublish, Server: server, Project: directory, Service: name,
			ServiceID: statusTestSavedID, Target: "http://127.0.0.1:3000",
		})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = tunnel.Finish(context.Background(), nil) })
	}
	if err := state.SaveServer(t.Context(), origin); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := runStatus(t.Context(), statusCommand{
		StateDir: state.Root(), All: true, Service: "accounts", AccessToken: token, Output: statusOutputJSON,
	}, &out); err != nil {
		t.Fatal(err)
	}
	if len(requests()) != 0 || !strings.Contains(out.String(), "multiple local servers") || strings.Contains(out.String(), `"service":"api"`) {
		t.Fatalf("inferred a server from a filtered checkout: %s (requests %v)", &out, requests())
	}
}

func TestStatusDoesNotSendExplicitTokenToInferredServer(t *testing.T) {
	state, directory := statusTestDatabase(t), t.TempDir()
	origin, token, requests := statusTestControl(t, []string{statusTestTeamOne}, func(http.ResponseWriter, *http.Request) {
		t.Error("inferred server must not receive the explicit token")
	})
	if err := state.SaveServer(t.Context(), "https://selected.example.test"); err != nil {
		t.Fatal(err)
	}
	statusTestTunnel(t, state, origin, directory, statusTestSavedID)
	var out bytes.Buffer
	if err := runStatus(t.Context(), statusCommand{
		Project: directory, StateDir: state.Root(), AccessToken: token, Output: statusOutputJSON,
	}, &out); err != nil {
		t.Fatal(err)
	}
	if len(requests()) != 0 || !strings.Contains(out.String(), "select the project server with --server to use an explicit access token") {
		t.Fatalf("read the inferred server with an unbound explicit token: %s (requests %v)", &out, requests())
	}
}

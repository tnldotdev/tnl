package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"sync"
	"testing"

	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	"github.com/tnldotdev/tnl/internal/security/credentials"
	authorityv1 "github.com/tnldotdev/tnl/pkg/api/control/authority/v1"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

const (
	statusTestTeamOne = "tm_0123456789abcdefghijkl"
	statusTestTeamTwo = "tm_abcdefghijkl0123456789"
	statusTestSavedID = "svc_0000000000000000000001"
)

func statusTestDatabase(t *testing.T) *clientstate.Database {
	t.Helper()
	state, err := clientstate.Open(t.Context(), filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = state.Close() })
	return state
}

func statusTestControl(t *testing.T, teams []string, inventory http.HandlerFunc) (string, string, func() []string) {
	t.Helper()
	access, _, _, err := credentials.NewAccessToken()
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var requests []string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		requests = append(requests, r.Method+" "+r.URL.RequestURI())
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path != "/v1/discovery" && r.Header.Get("Authorization") != "Bearer "+access.String() {
			t.Error("status did not use its control session")
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		switch r.Method + " " + r.URL.Path {
		case "GET /v1/discovery":
			_ = json.NewEncoder(w).Encode(controlv1.ControlDiscovery{
				ManagedDomain: "example.test", ManagedUrlMode: "generated",
				Authentication: controlv1.AuthenticationFacts{Methods: []controlv1.AuthenticationFactsMethods{"oidc"},
					Oidc: &controlv1.OIDCAuthenticationFacts{Issuer: "https://issuer.example.test", LoginFlow: "device_code"}},
			})
		case "GET /v1/identity":
			identity := authorityv1.IdentityContext{PersonalTeamId: statusTestTeamOne}
			for _, team := range teams {
				identity.Memberships = append(identity.Memberships, authorityv1.Membership{TeamId: team, Role: "owner"})
			}
			_ = json.NewEncoder(w).Encode(identity)
		case "GET /v1/services":
			inventory(w, r)
		default:
			t.Errorf("status made an unrelated or mutating request: %s %s", r.Method, r.URL)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(server.Close)
	original := http.DefaultTransport
	http.DefaultTransport = server.Client().Transport
	t.Cleanup(func() { http.DefaultTransport = original })
	return server.URL, access.String(), func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), requests...)
	}
}

func statusTestTunnel(t *testing.T, state *clientstate.Database, server, project, serviceID string) *clientstate.Tunnel {
	t.Helper()
	tunnel, err := state.BeginTunnel(t.Context(), clientstate.BeginTunnelOptions{
		Command: clientstate.TunnelCommandPublish, Server: server, Project: project, ServiceID: serviceID,
		Target: "http://127.0.0.1:3000",
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = tunnel.Finish(context.Background(), nil) })
	return tunnel
}

func statusTestAlias(t *testing.T, state *clientstate.Database, server, primary, selected, targetID, serviceID string) {
	t.Helper()
	scope := clientstate.AliasScope{Server: server, ProjectKey: primary, TeamID: statusTestTeamOne,
		MembershipID: "membership_fixture", Namespace: "p" + targetID[4:] + ".example.test", Name: "review"}
	integration := clientstate.IntegrationScope{PrimaryProjectRoot: primary, Namespace: scope.Namespace}
	tunnel, err := state.BeginTunnel(t.Context(), clientstate.BeginTunnelOptions{
		Command: clientstate.TunnelCommandPublish, Server: server, Project: selected, Service: "api", ServiceID: targetID,
		Target: "http://127.0.0.1:3000", IntegrationScope: integration,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = tunnel.Finish(context.Background(), nil) })
	if err := tunnel.SetProvisioning(t.Context(), 1); err != nil {
		t.Fatal(err)
	}
	if err := tunnel.SetReady(t.Context(), "https://target."+scope.Namespace, 1); err != nil {
		t.Fatal(err)
	}
	selection, err := state.RegisterAlias(t.Context(), clientstate.AliasRegistration{
		Scope: scope, Hostname: "review." + scope.Namespace, Service: "api", TunnelID: tunnel.ID(),
		IntegrationScope: integration, Fingerprint: sha256.Sum256([]byte("status fixture")),
	})
	if err != nil {
		t.Fatal(err)
	}
	if selected != primary {
		selection, err = state.SelectAlias(t.Context(), scope, selected, false)
		if err != nil {
			t.Fatal(err)
		}
	}
	selection, receiver, err := state.AliasCandidate(t.Context(), selection.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := state.MarkIntegrationURLReady(t.Context(), server, selection.Hostname, "status fixture", serviceID, 1); err != nil {
		t.Fatal(err)
	}
	if err := state.MarkAliasRunReady(t.Context(), clientstate.AliasPublishRun{
		Selection: selection, Receiver: receiver, Owner: "status fixture", ServiceID: serviceID, Number: 1,
	}); err != nil {
		t.Fatal(err)
	}
}

func TestReadStatusServerUsesSavedServicesAndScopedAliasJournals(t *testing.T) {
	const (
		activeID       = "svc_0000000000000000000002"
		targetID       = "svc_0000000000000000000003"
		aliasID        = "svc_0000000000000000000004"
		otherProjectID = "svc_0000000000000000000005"
		otherServerID  = "svc_0000000000000000000006"
		otherAliasID   = "svc_0000000000000000000007"
		serverAliasID  = "svc_0000000000000000000008"
	)
	run, number, cursor := "sr_0123456789abcdefghijkl", int64(37), "status-page-two"
	pages := map[string]controlv1.ServicePage{
		statusTestTeamOne + "|": {NextCursor: &cursor, Services: []controlv1.ServiceSummary{
			{Id: activeID, Name: "web", Enabled: true, Protocol: controlv1.ServiceProtocolHTTP, ServiceRunId: &run, RunNumber: &number,
				Endpoint: &controlv1.ServiceEndpoint{Hostname: "web.example.test", Public: true, Port: 443}},
			{Id: otherProjectID}, {Id: otherServerID}, {Id: otherAliasID}, {Id: serverAliasID}, {Id: targetID},
		}},
		statusTestTeamOne + "|" + cursor: {Services: []controlv1.ServiceSummary{
			{Id: statusTestSavedID, Name: "database", Enabled: true, Protocol: controlv1.Postgres,
				Endpoint: &controlv1.ServiceEndpoint{Hostname: "database.example.test", Port: 0}},
		}},
		statusTestTeamTwo + "|": {Services: []controlv1.ServiceSummary{
			{Id: aliasID, Name: "review", Enabled: true, Protocol: controlv1.ServiceProtocolHTTP,
				Endpoint: &controlv1.ServiceEndpoint{Hostname: "review.example.test", Port: 443}},
		}},
	}
	server, token, requests := statusTestControl(t, []string{statusTestTeamOne, statusTestTeamOne, statusTestTeamTwo, "tm_not_needed"},
		func(w http.ResponseWriter, r *http.Request) {
			if len(r.URL.Query()) > 2 {
				t.Errorf("status added non-inventory selectors: %s", r.URL)
			}
			page, found := pages[r.URL.Query().Get("team_id")+"|"+r.URL.Query().Get("cursor")]
			if !found {
				t.Errorf("status repeated or extended its bounded inventory read: %s", r.URL)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			_ = json.NewEncoder(w).Encode(page)
		})
	state := statusTestDatabase(t)
	project, linked, other := t.TempDir(), t.TempDir(), t.TempDir()
	saved := statusTestTunnel(t, state, server, project, statusTestSavedID)
	if err := saved.Finish(t.Context(), nil); err != nil {
		t.Fatal(err)
	}
	statusTestTunnel(t, state, server, project, activeID)
	statusTestTunnel(t, state, server, other, otherProjectID)
	statusTestTunnel(t, state, "https://another.example.test", project, otherServerID)
	statusTestAlias(t, state, server, project, linked, targetID, aliasID)
	statusTestAlias(t, state, server, other, other, "svc_0000000000000000000009", otherAliasID)
	statusTestAlias(t, state, "https://another.example.test", project, project, "svc_0000000000000000000010", serverAliasID)

	result := readStatusServer(t.Context(), state, server+"/", token, project)
	if !result.Available || result.ControlURL != server || result.Reason != "" || result.CheckedAt.IsZero() || len(result.Services) != 3 {
		t.Fatalf("scoped status = %+v", result)
	}
	gotIDs := []string{}
	for _, service := range result.Services {
		gotIDs = append(gotIDs, service.ServiceID)
	}
	if !reflect.DeepEqual(gotIDs, []string{activeID, statusTestSavedID, aliasID}) {
		t.Fatalf("status mixed projects, worktrees, servers, or aliases: %v", gotIDs)
	}
	if result.Services[0].PublisherObservation != "ready_publisher_hint" || result.Services[0].RunNumber == nil || *result.Services[0].RunNumber != 37 ||
		result.Services[1].PublisherObservation != "no_ready_publisher_observed" || result.Services[1].ServiceRunID != nil ||
		result.Services[1].Protocol != controlv1.Postgres || result.Services[1].Endpoint == nil || result.Services[1].Endpoint.Public || result.Services[1].Endpoint.Port != 0 ||
		result.Services[2].Endpoint == nil || result.Services[2].Endpoint.Public || result.Services[2].Endpoint.Port != 443 {
		t.Fatalf("status changed hints, native/connector service facts, or independent port/public facts: %+v", result.Services)
	}
	wantRequests := []string{
		"GET /v1/discovery", "GET /v1/identity",
		"GET /v1/services?team_id=" + statusTestTeamOne,
		"GET /v1/services?team_id=" + statusTestTeamOne + "&cursor=" + cursor,
		"GET /v1/services?team_id=" + statusTestTeamTwo,
	}
	if !reflect.DeepEqual(requests(), wantRequests) {
		t.Fatalf("status should read summaries only, once per team/page, without visitor selection: %v", requests())
	}
}

func TestReadStatusServerDoesNotInferStateForAnInvisibleSavedService(t *testing.T) {
	server, token, requests := statusTestControl(t, []string{statusTestTeamOne}, func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(controlv1.ServicePage{Services: []controlv1.ServiceSummary{}})
	})
	state := statusTestDatabase(t)
	project := t.TempDir()
	tunnel := statusTestTunnel(t, state, server, project, statusTestSavedID)
	if err := tunnel.Finish(t.Context(), nil); err != nil {
		t.Fatal(err)
	}
	result := readStatusServer(t.Context(), state, server, token, project)
	if !result.Available || result.Reason != "" || result.Services == nil || len(result.Services) != 0 || len(requests()) != 3 {
		t.Fatalf("invisible service became a fabricated lifecycle fact: %+v, %v", result, requests())
	}
	known, err := state.KnownProjectServices(t.Context(), project, server)
	if err != nil || !reflect.DeepEqual(known, []string{statusTestSavedID}) {
		t.Fatalf("fresh inventory read discarded saved local service knowledge: %v, %v", known, err)
	}
}

func TestReadStatusServerClearsPartialInventoryOnFailure(t *testing.T) {
	server, token, _ := statusTestControl(t, []string{statusTestTeamOne, statusTestTeamTwo}, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("team_id") == statusTestTeamTwo {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		_ = json.NewEncoder(w).Encode(controlv1.ServicePage{Services: []controlv1.ServiceSummary{{Id: statusTestSavedID}}})
	})
	state := statusTestDatabase(t)
	project := t.TempDir()
	statusTestTunnel(t, state, server, project, statusTestSavedID)
	statusTestTunnel(t, state, server, project, "svc_0000000000000000000002")
	result := readStatusServer(t.Context(), state, server, token, project)
	if result.Available || result.Reason != "service inventory unavailable" || result.Services == nil || len(result.Services) != 0 {
		t.Fatalf("failed inventory was presented as a complete server observation: %+v", result)
	}
}

func TestReadStatusServerSkipsControlWithoutProjectServerIDs(t *testing.T) {
	server, token, requests := statusTestControl(t, []string{statusTestTeamOne}, func(_ http.ResponseWriter, _ *http.Request) {
		t.Error("status queried inventory without project/server IDs")
	})
	state := statusTestDatabase(t)
	project := t.TempDir()
	statusTestTunnel(t, state, server, project, statusTestSavedID)
	for _, selection := range []struct{ project, server string }{
		{t.TempDir(), server}, {project, "https://another.example.test"},
	} {
		result := readStatusServer(t.Context(), state, selection.server, token, selection.project)
		if result.Available || result.Reason != "no local service IDs for this project" || result.Services == nil || len(result.Services) != 0 {
			t.Fatalf("local inventory crossed project/server scope: %+v", result)
		}
	}
	if len(requests()) != 0 {
		t.Fatalf("empty scoped inventory made control requests: %v", requests())
	}
}

func TestStatusAllServerIncludesStoppedServiceJournal(t *testing.T) {
	server, token, _ := statusTestControl(t, []string{statusTestTeamOne}, func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(controlv1.ServicePage{Services: []controlv1.ServiceSummary{{
			Id: statusTestSavedID, Name: "saved", Enabled: true, Protocol: controlv1.Postgres,
		}}})
	})
	state := statusTestDatabase(t)
	project := t.TempDir()
	tunnel := statusTestTunnel(t, state, server, project, statusTestSavedID)
	if err := tunnel.Finish(t.Context(), nil); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	if err := runStatus(t.Context(), statusCommand{
		Output: statusOutputJSON, ServerOnly: true, All: true, StateDir: state.Root(), ServerURL: server, AccessToken: token,
	}, &output); err != nil {
		t.Fatal(err)
	}
	var result statusResult
	if err := json.Unmarshal(output.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.SchemaVersion != 1 || len(result.Projects) != 1 || result.Projects[0].Project != project || result.Projects[0].Local != nil ||
		result.Projects[0].Server == nil || !result.Projects[0].Server.Available || len(result.Projects[0].Server.Services) != 1 ||
		result.Projects[0].Server.Services[0].ServiceID != statusTestSavedID {
		t.Fatalf("--all server status omitted a stopped project's saved service: %s", output.String())
	}
}

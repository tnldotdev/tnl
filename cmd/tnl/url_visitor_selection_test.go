package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/tnldotdev/tnl/internal/client/auth"
	clientcontrol "github.com/tnldotdev/tnl/internal/client/control"
	clientteam "github.com/tnldotdev/tnl/internal/client/team"
	authorityv1 "github.com/tnldotdev/tnl/pkg/api/control/authority/v1"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestVisitorServiceSelectionNeverFallsBackToManagerInventory(t *testing.T) {
	const id = "svc_0123456789abcdefghijkl"
	var listed atomic.Bool
	listed.Store(true)
	var reads atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/v1/visitor/services" || r.URL.Query().Get("access_path") != "public_endpoint" || r.Header.Get("Authorization") != "Bearer visitor" {
			t.Errorf("visitor selection used management or retired URL authority: %s %s", r.Method, r.URL)
			w.WriteHeader(http.StatusNotFound)
			return
		}
		reads.Add(1)
		w.Header().Set("Content-Type", "application/json")
		page := controlv1.ServicePage{Services: []controlv1.ServiceSummary{}}
		if listed.Load() {
			page.Services = append(page.Services, controlv1.ServiceSummary{Id: id, TeamId: "tm_0123456789abcdefghijkl", Name: "web",
				Enabled: true, Protocol: controlv1.ServiceProtocolHTTP, TrustRevision: 1,
				Endpoint: &controlv1.ServiceEndpoint{Hostname: "app.example.test", Port: 443, Public: true}})
		}
		_ = json.NewEncoder(w).Encode(page)
	}))
	defer server.Close()
	control, err := clientcontrol.New(server.URL, server.Client(), "visitor")
	if err != nil {
		t.Fatal(err)
	}
	session := clientteam.NewSession(nil, nil, &auth.Client{Control: control}, authorityv1.IdentityContext{}, clientteam.Options{})
	for _, selector := range []string{id, "app.example.test", "https://app.example.test"} {
		selected, err := resolveVisitorService(t.Context(), session, selector)
		if err != nil || selected.Id != id {
			t.Fatalf("visitor selector %q lost the exact service: %v", selector, err)
		}
	}
	listed.Store(false)
	for _, selector := range []string{id, "app.example.test"} {
		if _, err := resolveVisitorService(t.Context(), session, selector); !errors.Is(err, clientcontrol.ErrNotFound) {
			t.Fatalf("unlisted visitor service %q selected manager authority: %v", selector, err)
		}
	}
	if reads.Load() != 5 {
		t.Fatalf("visitor selection reads=%d", reads.Load())
	}
}

func TestVisitorServiceSelectionFiltersActualTeamFactsWithoutMembership(t *testing.T) {
	const teamID = "tm_0123456789abcdefghijkl"
	const teamName = "reviewed-team"
	const serviceID = "svc_0123456789abcdefghijkl"
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/v1/visitor/services" || r.URL.Query().Get("access_path") != "public_endpoint" ||
			len(r.URL.Query()) != 1 || r.Header.Get("Authorization") != "Bearer visitor" {
			t.Errorf("team filtering required membership or used another authority: %s %s", r.Method, r.URL)
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(controlv1.ServicePage{Services: []controlv1.ServiceSummary{
			{Id: serviceID, TeamId: teamID, TeamName: teamName, Name: "web", VisitorAccess: "identity_grant", Protocol: controlv1.ServiceProtocolHTTP,
				Endpoint: &controlv1.ServiceEndpoint{Hostname: "web.example.test", Port: 443, Public: true}},
			{Id: "svc_abcdefghijkl0123456789", TeamId: "tm_abcdefghijkl0123456789", TeamName: "other-team", Name: "api", VisitorAccess: "team_grant", Protocol: controlv1.ServiceProtocolHTTP,
				Endpoint: &controlv1.ServiceEndpoint{Hostname: "api.example.test", Port: 443, Public: true}},
		}})
	}))
	defer server.Close()
	control, err := clientcontrol.New(server.URL, server.Client(), "visitor")
	if err != nil {
		t.Fatal(err)
	}
	for _, team := range []string{teamID, teamName, "not-a-team-membership"} {
		items, err := visitorURLList(t.Context(), control, team)
		if err != nil {
			t.Fatal(err)
		}
		if team == "not-a-team-membership" {
			if len(items) != 0 {
				t.Fatal("unknown team filter exposed another team's service")
			}
			continue
		}
		if len(items) != 1 || items[0].Id != serviceID || items[0].TeamId != teamID || items[0].TeamName != teamName || items[0].VisitorAccess != "identity_grant" {
			t.Fatal("team filtering changed actual service, team, or permission facts", items)
		}
	}
}

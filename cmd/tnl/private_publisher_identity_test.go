package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sync/atomic"
	"testing"

	"github.com/tnldotdev/tnl/internal/client/auth"
	clientauthority "github.com/tnldotdev/tnl/internal/client/authority"
	clientcontrol "github.com/tnldotdev/tnl/internal/client/control"
	clientteam "github.com/tnldotdev/tnl/internal/client/team"
	"github.com/tnldotdev/tnl/internal/security/targettrust"
	authorityv1 "github.com/tnldotdev/tnl/pkg/api/control/authority/v1"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestManagedPublisherServiceReadsExactTrustWithoutVisitorInventory(t *testing.T) {
	const id = "svc_0123456789abcdefghijkl"
	const team = "tm_0123456789abcdefghijkl"
	trust, err := targettrust.NewDeclaration("target.internal", nil)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := trust.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	saved := controlv1.Service{Id: id, TeamId: team, Name: "database", Protocol: controlv1.Postgres, Enabled: true, TrustRevision: 4,
		TargetTls: &controlv1.ServiceTargetTLS{Hostname: snapshot.Hostname, Digest: snapshot.Digest, System: true}}
	for _, test := range []struct {
		name   string
		change func(*controlv1.Service)
		valid  bool
	}{
		{name: "exact connector-only service", valid: true},
		{name: "another service", change: func(s *controlv1.Service) { s.Id = "svc_abcdefghijkl0123456789" }},
		{name: "another team", change: func(s *controlv1.Service) { s.TeamId = "tm_abcdefghijkl0123456789" }},
		{name: "disabled", change: func(s *controlv1.Service) { s.Enabled = false }},
		{name: "missing trust revision", change: func(s *controlv1.Service) { s.TrustRevision = 0 }},
	} {
		t.Run(test.name, func(t *testing.T) {
			response := saved
			if test.change != nil {
				test.change(&response)
			}
			var reads atomic.Int32
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("Authorization") != "Bearer manager" {
					t.Error("publisher setup did not use its control session")
				}
				w.Header().Set("Content-Type", "application/json")
				switch r.Method + " " + r.URL.Path {
				case "GET /v1/teams/" + team:
					_ = json.NewEncoder(w).Encode(authorityv1.Team{Id: team})
				case "GET /v1/services/" + id:
					reads.Add(1)
					_ = json.NewEncoder(w).Encode(response)
				default:
					t.Errorf("exact publisher setup enumerated or used another authority: %s %s", r.Method, r.URL)
					w.WriteHeader(http.StatusNotFound)
				}
			}))
			defer server.Close()
			control, err := clientcontrol.New(server.URL, server.Client(), "manager")
			if err != nil {
				t.Fatal(err)
			}
			authority, err := clientauthority.New(server.URL, server.Client(), "manager")
			if err != nil {
				t.Fatal(err)
			}
			session := clientteam.NewSession(nil, nil, &auth.Client{Control: control, Authority: authority},
				authorityv1.IdentityContext{Memberships: []authorityv1.Membership{{TeamId: team}}}, clientteam.Options{SelectedTeam: team})
			got, err := managedService(t.Context(), session, id)
			if (err == nil) != test.valid || reads.Load() != 1 || test.valid && !reflect.DeepEqual(got, saved) {
				t.Fatalf("exact publisher service read: reads=%d valid=%v err=%v", reads.Load(), test.valid, err)
			}
		})
	}
}

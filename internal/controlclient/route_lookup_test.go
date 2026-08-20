package controlclient

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

func TestRouteHostnameLookupIsBoundedAndValidatesResponse(t *testing.T) {
	want := controlv1.Route{Id: "route_found", TeamId: "team_1", CanonicalHostname: "demo.example", LifecycleState: controlv1.Enabled}
	otherTeam, otherHost, deleted, suspended := want, want, want, want
	otherTeam.TeamId = "team_other"
	otherHost.CanonicalHostname = "other.example"
	deleted.LifecycleState = "deleted"
	suspended.LifecycleState = controlv1.Suspended
	cursor := "next-page"
	for _, test := range []struct {
		name           string
		page           controlv1.RoutePage
		valid, missing bool
	}{
		{"found", controlv1.RoutePage{Routes: []controlv1.Route{want}}, true, false},
		{"suspended", controlv1.RoutePage{Routes: []controlv1.Route{suspended}}, true, false},
		{"missing", controlv1.RoutePage{Routes: []controlv1.Route{}}, false, true},
		{"wrong team", controlv1.RoutePage{Routes: []controlv1.Route{otherTeam}}, false, false},
		{"wrong hostname", controlv1.RoutePage{Routes: []controlv1.Route{otherHost}}, false, false},
		{"deleted", controlv1.RoutePage{Routes: []controlv1.Route{deleted}}, false, false},
		{"unfiltered list", controlv1.RoutePage{Routes: []controlv1.Route{want, otherHost}}, false, false},
		{"unexpected pagination", controlv1.RoutePage{Routes: []controlv1.Route{want}, NextCursor: &cursor}, false, false},
		{"empty page with cursor", controlv1.RoutePage{Routes: []controlv1.Route{}, NextCursor: &cursor}, false, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			var requests atomic.Int32
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				if r.Method != http.MethodGet || r.URL.Path != "/v1/routes" || r.URL.Query().Get("team_id") != "team_1" ||
					r.URL.Query().Get("canonical_hostname") != "demo.example" || r.URL.Query().Has("cursor") || r.Header.Get("Authorization") != "Bearer access" {
					t.Errorf("unexpected lookup request: %s %s", r.Method, r.URL)
				}
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(test.page)
			}))
			defer server.Close()
			client, err := New(server.URL, server.Client(), "access")
			if err != nil {
				t.Fatal(err)
			}
			got, err := client.GetRouteByHostname(t.Context(), "team_1", "demo.example")
			if (err == nil) != test.valid || errors.Is(err, ErrNotFound) != test.missing || requests.Load() != 1 {
				t.Fatalf("route=%+v err=%v requests=%d", got, err, requests.Load())
			}
			if test.valid && (got.Id != want.Id || got.CanonicalHostname != want.CanonicalHostname) {
				t.Fatalf("wrong route: %+v", got)
			}
			if _, err := client.GetRouteByHostname(t.Context(), "team_1", ""); err == nil || requests.Load() != 1 {
				t.Fatal("empty hostname caused an unfiltered request")
			}
		})
	}
}

package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"sync"
	"testing"
	"time"

	clientcontrol "github.com/tnldotdev/tnl/internal/client/control"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestVisitorURLListAccumulatesHTTPSPagesBeforeLocalTeamFiltering(t *testing.T) {
	const teamID = "tm_0123456789abcdefghijkl"
	const next = "second/page+opaque=="
	first := controlv1.ServiceSummary{Id: "svc_0123456789abcdefghijkl", TeamId: teamID, TeamName: "studio",
		Protocol: controlv1.ServiceProtocolHTTP, VisitorAccess: "identity_grant",
		Endpoint: &controlv1.ServiceEndpoint{Hostname: "first.example.test", Port: 443, Public: true}}
	second := controlv1.ServiceSummary{Id: "svc_abcdefghijkl0123456789", TeamId: "tm_abcdefghijkl0123456789", TeamName: "another",
		Protocol: controlv1.ServiceProtocolHTTP, VisitorAccess: "team_grant",
		Endpoint: &controlv1.ServiceEndpoint{Hostname: "second.example.test", Port: 443, Public: true}}
	third := controlv1.ServiceSummary{Id: "svc_123456789abcdefghijkl0", TeamId: teamID, TeamName: "studio",
		Protocol: controlv1.ServiceProtocolHTTP, VisitorAccess: "identity_grant",
		Endpoint: &controlv1.ServiceEndpoint{Hostname: "third.example.test", Port: 443, Public: true}}
	private := controlv1.ServiceSummary{Id: "svc_23456789abcdefghijkl01", TeamId: teamID, TeamName: "studio",
		Protocol: controlv1.ServiceProtocolHTTP,
		Endpoint: &controlv1.ServiceEndpoint{Hostname: "private.example.test", Port: 443, Public: false}}

	for _, team := range []string{"", "studio", teamID} {
		t.Run(map[string]string{"": "all", "studio": "team name", teamID: "team ID"}[team], func(t *testing.T) {
			var mu sync.Mutex
			var cursors []string
			requests := 0
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				mu.Lock()
				defer mu.Unlock()
				requests++
				if r.TLS == nil || r.Method != http.MethodGet || r.URL.Path != "/v1/visitor/services" ||
					r.Header.Get("Authorization") != "Bearer visitor" {
					t.Error("visitor inventory changed its HTTPS path, method, or authentication")
					http.Error(w, "unexpected inventory request", http.StatusBadRequest)
					return
				}
				want := url.Values{"access_path": {"public_endpoint"}}
				page := controlv1.ServicePage{Services: []controlv1.ServiceSummary{first, private}, NextCursor: new(next)}
				if requests == 2 {
					want.Set("cursor", next)
					page = controlv1.ServicePage{Services: []controlv1.ServiceSummary{second, third}}
				} else if requests != 1 {
					t.Error("visitor inventory continued after the final page")
					http.Error(w, "unexpected third page", http.StatusBadRequest)
					return
				}
				if !reflect.DeepEqual(r.URL.Query(), want) {
					t.Error("visitor inventory changed its access path/cursor or sent a team/membership filter")
				}
				cursors = append(cursors, r.URL.Query().Get("cursor"))
				w.Header().Set("Content-Type", "application/json")
				if err := json.NewEncoder(w).Encode(page); err != nil {
					t.Error(err)
				}
			}))
			defer server.Close()
			control, err := clientcontrol.New(server.URL, server.Client(), "visitor")
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			items, err := visitorURLList(ctx, control, team)
			if err != nil {
				t.Fatal("two-page visitor inventory failed", err)
			}
			want := []controlv1.ServiceSummary{first, third}
			if team == "" {
				want = []controlv1.ServiceSummary{first, second, third}
			}
			mu.Lock()
			defer mu.Unlock()
			if requests != 2 || !reflect.DeepEqual(cursors, []string{"", next}) || !reflect.DeepEqual(items, want) {
				t.Fatal("visitor inventory lost a page, changed ordering, or failed local team/exposure filtering", requests, cursors, items)
			}
		})
	}
}

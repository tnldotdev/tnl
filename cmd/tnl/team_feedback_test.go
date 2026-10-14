package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tnldotdev/tnl/internal/credentials"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/pkg/api/authorityv1"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

func TestTeamFeedbackCommandsUseSelectedTeamAndExplicitBoolean(t *testing.T) {
	access, _, _, err := credentials.NewAccessToken()
	if err != nil {
		t.Fatal(err)
	}
	var calls []string
	required := false
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path != "/v1/discovery" && r.Header.Get("Authorization") != "Bearer "+access.String() {
			t.Error("missing explicit authentication")
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		switch r.URL.Path {
		case "/v1/discovery":
			_ = json.NewEncoder(w).Encode(controlv1.ControlDiscovery{Authentication: controlv1.AuthenticationFacts{Methods: []controlv1.AuthenticationFactsMethods{controlv1.LoginToken}}})
		case "/v1/identity":
			_ = json.NewEncoder(w).Encode(authorityv1.IdentityContext{PersonalTeamId: "team_personal", Identity: authorityv1.Identity{Id: "identity_test"}, Memberships: []authorityv1.Membership{
				{TeamId: "team_personal", TeamDisplayName: "personal", Role: authorityv1.TeamRoleOwner},
				{TeamId: "team_studio", TeamDisplayName: "studio", Role: authorityv1.TeamRoleAdmin},
			}})
		case "/v1/teams/team_studio/feedback-policy":
			calls = append(calls, r.Method)
			if r.Method == http.MethodPut {
				var body authorityv1.TeamFeedbackPolicy
				if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
					t.Error(err)
				}
				required = body.RequireSignIn
			}
			_ = json.NewEncoder(w).Encode(authorityv1.TeamFeedbackPolicy{RequireSignIn: required})
		default:
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	// use the httptest CA only for this isolated, non-parallel command fixture.
	previous := http.DefaultTransport
	http.DefaultTransport = server.Client().Transport
	t.Cleanup(func() { http.DefaultTransport = previous })
	stateDir := filepath.Join(t.TempDir(), "state")
	for _, command := range [][]string{{"show"}, {"set", "--require-sign-in=true"}, {"show"}, {"set", "--require-sign-in=false"}} {
		var output, diagnostics bytes.Buffer
		args := append([]string{"--no-config", "team", "feedback"}, command...)
		args = append(args, "--team=studio", "--server="+server.URL, "--state-dir="+stateDir, "--access-token="+access.String())
		if err := run(t.Context(), args, &output, &diagnostics); err != nil {
			t.Fatal(err)
		}
		got := output.String()
		if !strings.HasPrefix(got, "+--[ tnl team feedback ") || !strings.Contains(got, "studio") || !strings.Contains(got, "require sign-in") || !strings.Contains(got, map[bool]string{true: "true", false: "false"}[required]) || diagnostics.Len() != 0 {
			t.Fatalf("output=%q diagnostics=%q", got, diagnostics.String())
		}
		for _, line := range strings.Split(got, "\n") {
			if len(line) > 72 {
				t.Fatalf("overwide frame: %q", line)
			}
		}
	}
	if strings.Join(calls, ",") != "GET,PUT,GET,PUT" {
		t.Fatalf("policy requests = %v", calls)
	}
	var output, diagnostics bytes.Buffer
	err = run(t.Context(), []string{
		"--no-config", "team", "feedback", "set", "--team=studio", "--server=" + server.URL,
		"--state-dir=" + stateDir, "--access-token=" + access.String(),
	}, &output, &diagnostics)
	if reason, ok := failure.ReasonOf(err); !ok || reason != failure.TeamUnavailable || !strings.Contains(err.Error(), "missing flags: --require-sign-in") {
		t.Fatalf("missing flag diagnostic = %v (reason=%s)", err, reason)
	}
	if strings.Join(calls, ",") != "GET,PUT,GET,PUT" || output.Len() != 0 || diagnostics.Len() != 0 {
		t.Fatalf("missing flag reached policy request: calls=%v output=%q diagnostics=%q", calls, output.String(), diagnostics.String())
	}
}

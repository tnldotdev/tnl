package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/client/auth"
	clientauthority "github.com/tnldotdev/tnl/internal/client/authority"
	clientcontrol "github.com/tnldotdev/tnl/internal/client/control"
	clientteam "github.com/tnldotdev/tnl/internal/client/team"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/security/credentials"
	authorityv1 "github.com/tnldotdev/tnl/pkg/api/control/authority/v1"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestShareLifetimeAcceptsDaysAndBoundsExpiration(t *testing.T) {
	for input, want := range map[string]time.Duration{"24h": 24 * time.Hour, "7d": 7 * 24 * time.Hour, "30d": 30 * 24 * time.Hour} {
		got, err := parseShareLifetime(input)
		if err != nil || got != want {
			t.Fatalf("lifetime %q = %s, %v", input, got, err)
		}
	}
	for _, input := range []string{"", "0d", "31d", "1.5d", "0s", "721h", "-1h", "1d2h"} {
		_, err := parseShareLifetime(input)
		if reason, ok := failure.ReasonOf(err); !ok || reason != failure.ShareInputInvalid {
			t.Fatalf("invalid share lifetime %q was accepted", input)
		}
	}
}

func TestHTTPShareGrantsUseSessionAndIdempotencyKey(t *testing.T) {
	for _, kind := range []string{"invite", "team"} {
		t.Run(kind, func(t *testing.T) {
			const id = "svc_0123456789abcdefghijkl"
			const team = "tm_0123456789abcdefghijkl"
			const invitationID = "sivt_0123456789abcdefghijkl"
			secret := invitationID + "." + strings.Repeat("A", 43)
			posts := 0
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				if r.Header.Get("Authorization") != "Bearer session" {
					t.Error("grant management must use the control session")
				}
				if r.Method == http.MethodGet && r.URL.Path == "/v1/teams/"+team {
					_ = json.NewEncoder(w).Encode(authorityv1.Team{Id: team})
					return
				}
				if r.Method == http.MethodGet && r.URL.Path == "/v1/services" {
					_ = json.NewEncoder(w).Encode(controlv1.ServicePage{Services: []controlv1.ServiceSummary{{Id: id, TeamId: team, Protocol: controlv1.ServiceProtocolHTTP, Endpoint: &controlv1.ServiceEndpoint{Hostname: "app.example.test", Port: 443, Public: true}}}})
					return
				}
				path := "/v1/services/" + id + "/grants"
				if kind == "invite" {
					path = "/v1/services/" + id + "/invitations"
				}
				if r.Method != http.MethodPost || r.URL.Path != path {
					t.Errorf("unexpected request: %s %s", r.Method, r.URL)
					w.WriteHeader(http.StatusNotFound)
					return
				}
				posts++
				var body map[string]any
				if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
					t.Error(err)
				}
				if _, exists := body["ssh_user"]; exists {
					t.Error("HTTP request included removed ssh_user field")
				}
				if _, exists := body["token_digest"]; exists {
					t.Error("caller sent an invitation digest")
				}
				if r.Header.Get("Idempotency-Key") == "" {
					t.Error("missing idempotency key")
				}
				response := map[string]any{"id": "sgr_0123456789abcdefghijkl", "service_id": id, "expires_at": body["expires_at"]}
				if kind == "team" {
					response["kind"] = "team"
				} else {
					response["email"] = body["email"]
					response["id"] = invitationID
					response = map[string]any{"invitation": response, "credential": secret}
				}
				w.WriteHeader(http.StatusCreated)
				_ = json.NewEncoder(w).Encode(response)
			}))
			defer server.Close()
			control, err := clientcontrol.New(server.URL, server.Client(), credentials.AccessToken("session"))
			if err != nil {
				t.Fatal(err)
			}
			membership := authorityv1.Membership{TeamId: team, Role: "owner"}
			authority, err := clientauthority.New(server.URL, server.Client(), credentials.AccessToken("session"))
			if err != nil {
				t.Fatal(err)
			}
			session := clientteam.NewSession(nil, nil, &auth.Client{Control: control, Authority: authority}, authorityv1.IdentityContext{PersonalTeamId: team, Memberships: []authorityv1.Membership{membership}}, clientteam.Options{SelectedTeam: team})
			var output bytes.Buffer
			if kind == "invite" {
				err = createShareInvitation(t.Context(), session, shareInviteCreateCommand{URL: id, Email: "reviewer@example.test"}, time.Hour, &output)
			} else {
				err = exactTeamShare(t.Context(), session, id, "1h", false, statusOutputHuman, &output)
			}
			if err != nil || posts != 1 {
				t.Fatalf("grant creation: err=%v, posts=%d", err, posts)
			}
			if kind == "invite" && output.String() != secret+"\n" {
				t.Fatal("caller did not use the complete server-issued credential")
			}
			if kind == "team" && !strings.HasPrefix(output.String(), "https://app.example.test\nTeam access granted until ") {
				t.Fatalf("team grant did not lead with the URL and expiry: %s", &output)
			}
		})
	}
}

func TestAnonymousPreviewSharesExcludeUnknownProtocols(t *testing.T) {
	routes := []controlv1.ServiceSummary{
		{Id: "svc_web", Protocol: controlv1.ServiceProtocolHTTP, Endpoint: &controlv1.ServiceEndpoint{Public: true}},
		{Id: "svc_unknown", Protocol: "unknown", Endpoint: &controlv1.ServiceEndpoint{Public: true}},
		{Id: "svc_api", Protocol: controlv1.ServiceProtocolHTTP, Endpoint: &controlv1.ServiceEndpoint{Public: true}},
		{Id: "svc_private", Protocol: controlv1.ServiceProtocolHTTP, Endpoint: &controlv1.ServiceEndpoint{Public: false}},
	}
	if got := anonymousPreviewServiceIDs(routes); strings.Join(got, ",") != "svc_api,svc_web" {
		t.Fatalf("anonymous share URLs = %v", got)
	}
}

func TestShareTeamSSHUserIsRejectedBeforeAuthentication(t *testing.T) {
	err := run(t.Context(), []string{"--no-config", "share", "team", "create", "--ssh-user", "deploy", "--state-dir", filepath.Join(t.TempDir(), "state")}, io.Discard, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "ssh-user") {
		t.Fatalf("SSH preview grant dispatch error = %v", err)
	}
}

func TestShareSelectsOnlyConfiguredPublicURLFromProject(t *testing.T) {
	webID := "svc_0123456789abcdefghijkl"
	routes := []controlv1.ServiceSummary{{Id: webID, Name: "web", Protocol: "http", Endpoint: &controlv1.ServiceEndpoint{Hostname: "web.example.test", Port: 443}}, {Id: "svc_abcdefghijkl0123456789", Name: "api", Protocol: "http", Endpoint: &controlv1.ServiceEndpoint{Hostname: "api.example.test", Port: 443}}}
	for _, selector := range []string{"web", webID, "web.example.test", "https://web.example.test", "https://Web.example.test:443/", "web.example.test:443"} {
		got, err := selectShareService(selector, routes)
		if err != nil || got.Id != webID {
			t.Fatalf("selector %q = %+v, %v", selector, got, err)
		}
	}
	if _, err := selectShareService("", routes); err == nil || !strings.Contains(err.Error(), "Select the public URL") {
		t.Fatalf("ambiguous preview page: %v", err)
	}
	for _, selector := range []string{"https://web.example.test/path", "http://web.example.test", "web.example.test:444", "https://web.example.test?secret=yes"} {
		if _, err := selectShareService(selector, routes); err == nil {
			t.Fatalf("invalid page %q was accepted", selector)
		}
	}
	if _, err := selectShareService("other.example.test", routes); !errors.Is(err, clientcontrol.ErrNotFound) {
		t.Fatalf("unconfigured hostname = %v", err)
	}
}

func TestShareCreateRejectsInvalidExpiryBeforeAuthentication(t *testing.T) {
	err := run(t.Context(), []string{"--no-config", "share", "link", "create", "--state-dir", filepath.Join(t.TempDir(), "state"), "--expires-in", "0d"}, io.Discard, io.Discard)
	if reason, ok := failure.ReasonOf(err); !ok || reason != failure.ShareInputInvalid {
		t.Fatalf("share create dispatch error = %v", err)
	}
}

func TestTeamShareCommandsSelectAConfiguredPreviewBeforeAuthentication(t *testing.T) {
	for _, command := range [][]string{{"team", "create"}, {"team", "revoke"}} {
		arguments := append([]string{"--no-config", "share"}, command...)
		arguments = append(arguments, "--state-dir", filepath.Join(t.TempDir(), "state"))
		err := run(t.Context(), arguments, io.Discard, io.Discard)
		if reason, ok := failure.ReasonOf(err); !ok || reason != failure.PreviewNotSaved {
			t.Fatalf("team share command %v selected a preview: %v", arguments, err)
		}
	}
}

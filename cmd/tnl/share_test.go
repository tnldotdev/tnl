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
	clientcontrol "github.com/tnldotdev/tnl/internal/client/control"
	clientteam "github.com/tnldotdev/tnl/internal/client/team"
	"github.com/tnldotdev/tnl/internal/config"
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
			const id = "url_0123456789abcdefghijkl"
			posts := 0
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				if r.Header.Get("Authorization") != "Bearer session" {
					t.Error("grant management must use the control session")
				}
				if r.Method == http.MethodGet && r.URL.Path == "/v1/visitor/public-urls" {
					_ = json.NewEncoder(w).Encode(controlv1.AvailablePublicURLPage{PublicUrls: []controlv1.AvailablePublicURL{{Id: id, ServiceProtocol: "http", CanonicalHostname: "app.example.test"}}})
					return
				}
				path := "/v1/public-urls/" + id + "/visitor-grants"
				if kind == "invite" {
					path = "/v1/public-urls/" + id + "/visitor-invitations"
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
				if r.Header.Get("Idempotency-Key") == "" {
					t.Error("missing idempotency key")
				}
				response := map[string]any{"id": "grant_test", "public_url_id": id, "expires_at": time.Now().Add(time.Hour)}
				if kind == "team" {
					response["kind"] = "team"
				} else {
					response["email"] = body["email"]
				}
				w.WriteHeader(http.StatusCreated)
				_ = json.NewEncoder(w).Encode(response)
			}))
			defer server.Close()
			control, err := clientcontrol.New(server.URL, server.Client(), credentials.AccessToken("session"))
			if err != nil {
				t.Fatal(err)
			}
			session := clientteam.NewSession(nil, nil, &auth.Client{Control: control}, authorityv1.IdentityContext{}, clientteam.Options{})
			var output bytes.Buffer
			if kind == "invite" {
				err = createShareInvitation(t.Context(), session, shareInviteCreateCommand{URL: id, Email: "reviewer@example.test"}, time.Hour, &output)
			} else {
				err = exactTeamShare(t.Context(), session, id, "1h", false, statusOutputHuman, &output)
			}
			if err != nil || posts != 1 {
				t.Fatalf("grant creation: err=%v, posts=%d", err, posts)
			}
		})
	}
}

func TestAnonymousPreviewSharesExcludeUnknownProtocols(t *testing.T) {
	routes := []controlv1.PublicURL{
		{Id: "url_web", ServiceProtocol: controlv1.Http},
		{Id: "url_unknown", ServiceProtocol: "unknown"},
		{Id: "url_api", ServiceProtocol: controlv1.Http},
	}
	if got := anonymousPreviewPublicURLIDs(routes); strings.Join(got, ",") != "url_api,url_web" {
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
	webID := "url_0123456789abcdefghijkl"
	routes := []controlv1.PublicURL{{Id: webID, CanonicalHostname: "web.example.test"}, {Id: "url_abcdefghijkl0123456789", CanonicalHostname: "api.example.test"}}
	for _, selector := range []string{webID, "web.example.test", "https://web.example.test"} {
		got, err := selectSharePublicURL(selector, routes)
		if err != nil || got.Id != webID {
			t.Fatalf("selector %q = %+v, %v", selector, got, err)
		}
	}
	if _, err := selectSharePublicURL("", routes); err == nil || !strings.Contains(err.Error(), "select the public URL") {
		t.Fatalf("ambiguous preview page: %v", err)
	}
	for _, selector := range []string{"https://web.example.test/path", "http://web.example.test", "web.example.test:443", "https://web.example.test?secret=yes"} {
		if _, err := selectSharePublicURL(selector, routes); err == nil {
			t.Fatalf("invalid page %q was accepted", selector)
		}
	}
	if _, err := selectSharePublicURL("other.example.test", routes); !errors.Is(err, clientcontrol.ErrNotFound) {
		t.Fatalf("unconfigured hostname = %v", err)
	}
}

func TestShareCreateRejectsInvalidExpiryBeforeAuthentication(t *testing.T) {
	err := run(t.Context(), []string{"--no-config", "share", "link", "create", "--state-dir", filepath.Join(t.TempDir(), "state"), "--expires-in", "0d"}, io.Discard, io.Discard)
	if reason, ok := failure.ReasonOf(err); !ok || reason != failure.ShareInputInvalid {
		t.Fatalf("share create dispatch error = %v", err)
	}
}

func TestShareServiceURLsUseConfiguredNames(t *testing.T) {
	project := projectConfiguration{}
	project.Config.Services = config.Services{"web": {Tunnel: &config.Tunnel{}}, "api": {}, "docs": {Tunnel: &config.Tunnel{}}}
	routes := []controlv1.PublicURL{
		{Id: "url_web", CanonicalHostname: "web.example.test", ServiceProtocol: controlv1.Http},
		{Id: "url_docs", CanonicalHostname: "docs.example.test", ServiceProtocol: controlv1.Http},
	}
	services := shareServiceURLs(project, routes, map[string]string{"api": "web.example.test", "web": "web.example.test", "docs": "docs.example.test"})
	if len(services) != 2 || services["docs"].PublicURL != "https://docs.example.test" || services["web"].PublicURLID != "url_web" {
		t.Fatalf("unexpected share service mapping: %+v", services)
	}
	encoded, err := json.Marshal(services)
	if err != nil || strings.Contains(string(encoded), "__tnl/share") || strings.Contains(string(encoded), `"api"`) {
		t.Fatalf("unexpected share URL in ordinary service mapping: %s, %v", encoded, err)
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

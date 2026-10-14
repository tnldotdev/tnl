package main

import (
	"encoding/json"
	"errors"
	"io"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/controlclient"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
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
	if _, err := selectSharePublicURL("other.example.test", routes); !errors.Is(err, controlclient.ErrNotFound) {
		t.Fatalf("unconfigured hostname = %v", err)
	}
}

func TestTeamShareSelectsExactDatabaseAddress(t *testing.T) {
	port := 5432
	webID, dbID := "url_0123456789abcdefghijkl", "url_abcdefghijkl0123456789"
	routes := []controlv1.PublicURL{
		{Id: webID, CanonicalHostname: "orders.example.test", ServiceProtocol: controlv1.Http},
		{Id: dbID, CanonicalHostname: "orders.example.test", ServiceProtocol: controlv1.Postgres, PublicPort: &port},
	}
	for _, selector := range []string{dbID, "orders.example.test:5432"} {
		selected, err := selectTeamSharePublicURL(selector, routes)
		if err != nil || selected.Id != dbID {
			t.Fatalf("database selector %q = %+v, %v", selector, selected, err)
		}
	}
	selected, err := selectTeamSharePublicURL("https://orders.example.test", routes)
	if err != nil || selected.Id != webID {
		t.Fatalf("HTTP selector = %+v, %v", selected, err)
	}
	for _, selector := range []string{"orders.example.test", "orders.example.test:05432", "orders.example.test:443", "https://orders.example.test:5432"} {
		if _, err := selectTeamSharePublicURL(selector, routes); err == nil {
			t.Fatalf("ambiguous or malformed selector %q was accepted", selector)
		}
	}
}

func TestShareCreateRejectsInvalidExpiryBeforeAuthentication(t *testing.T) {
	err := run(t.Context(), []string{"--no-config", "share", "link", "create", "--state-dir", filepath.Join(t.TempDir(), "state"), "--expires-in", "0d"}, io.Discard, io.Discard)
	if reason, ok := failure.ReasonOf(err); !ok || reason != failure.ShareInputInvalid {
		t.Fatalf("share create dispatch error = %v", err)
	}
}

func TestShareInviteRejectsInvalidExpiryBeforeAuthentication(t *testing.T) {
	err := run(t.Context(), []string{"--no-config", "share", "invite", "create", "web.example.test", "--email", "sam@example.test", "--expires-in", "0d", "--state-dir", filepath.Join(t.TempDir(), "state")}, io.Discard, io.Discard)
	if reason, ok := failure.ReasonOf(err); !ok || reason != failure.ShareInputInvalid {
		t.Fatalf("invalid named invite lifetime was accepted: %v", err)
	}
}

func TestShareServiceURLsUseConfiguredNames(t *testing.T) {
	project := projectConfiguration{}
	project.Config.Services = config.Services{"web": {}, "api": {}}
	routes := []controlv1.PublicURL{
		{Id: "url_api", CanonicalHostname: "api.example.test"},
		{Id: "url_web", CanonicalHostname: "web.example.test"},
	}
	services := shareServiceURLs(project, routes)
	if services["api"].PublicURL != "https://api.example.test" || services["web"].PublicURLID != "url_web" {
		t.Fatalf("unexpected share service mapping: %+v", services)
	}
	encoded, err := json.Marshal(services)
	if err != nil || strings.Contains(string(encoded), "__tnl/share") {
		t.Fatalf("unexpected share URL in ordinary service mapping: %s, %v", encoded, err)
	}
}

func TestPreviewShareServiceNamesExcludeDatabaseServices(t *testing.T) {
	postgres := "postgres"
	project := projectConfiguration{}
	project.Config.Services = config.Services{
		"database": {Publish: &config.Publish{Protocol: &postgres}},
		"web":      {},
	}
	services := shareServiceURLs(project, []controlv1.PublicURL{{Id: "url_web", CanonicalHostname: "web.example.test"}})
	if len(services) != 1 || services["web"].PublicURLID != "url_web" {
		t.Fatalf("database entered HTTP preview share: %+v", services)
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

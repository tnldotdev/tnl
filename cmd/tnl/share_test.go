package main

import (
	"bytes"
	"errors"
	"io"
	"path/filepath"
	"strings"
	"testing"
	"time"

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

func TestTeamShareCreatedExplainsSelectedTeamAndPreviewScope(t *testing.T) {
	var output bytes.Buffer
	if err := writeTeamShareCreated(&output, "acme", controlv1.Preview{Id: "pv_private", PublicUrlIds: []string{"url_web", "url_api"}}, controlv1.PublicURL{CanonicalHostname: "web.acme.example"}); err != nil {
		t.Fatal(err)
	}
	text := output.String()
	for _, want := range []string{"+--[ tnl share team create ]-- shared", "team", "acme", "current team members; all 2 public URLs", "entry URL", "https://web.acme.example/", "tnl share team revoke --team acme", "team access applies to this whole preview"} {
		if !strings.Contains(text, want) {
			t.Fatalf("share output missing %q: %s", want, text)
		}
	}
	if strings.Contains(text, "pv_private") || strings.Contains(text, "/__tnl/team/login") {
		t.Fatalf("share output exposed internal scope or entry sign-in: %s", text)
	}
	for _, line := range strings.Split(text, "\n") {
		if len(line) > 72 || strings.ContainsRune(line, '\x1b') {
			t.Fatalf("invalid share frame line: %q", line)
		}
	}
}

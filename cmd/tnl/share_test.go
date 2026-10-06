package main

import (
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/controlclient"
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
		if _, err := parseShareLifetime(input); err == nil {
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
	err := run(t.Context(), []string{"--no-config", "share", "link", "create", "--expires-in", "0d"}, io.Discard, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "share lifetime") {
		t.Fatalf("share create dispatch error = %v", err)
	}
}

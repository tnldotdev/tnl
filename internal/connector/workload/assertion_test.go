package workloadclient

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tnldotdev/tnl/internal/client/project/workloadmanifest"
)

func TestAssertionSourceOneOfAndRotation(t *testing.T) {
	file := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(file, []byte(" first.jwt.value\n"), 0600); err != nil {
		t.Fatal(err)
	}
	source := AssertionSource{TokenFile: file}
	if raw, err := source.Acquire(t.Context()); err != nil || raw != "first.jwt.value" {
		t.Fatal("file acquisition", err)
	}
	if err := os.WriteFile(file, []byte("second.jwt.value"), 0600); err != nil {
		t.Fatal(err)
	}
	if raw, err := source.Acquire(t.Context()); err != nil || raw != "second.jwt.value" {
		t.Fatal("rotation was cached", err)
	}
	for _, s := range []AssertionSource{{}, {Assertion: "one", TokenFile: file}, {TokenFile: file, Callback: func(context.Context) (string, error) { return "callback", nil }}} {
		if _, err := s.Acquire(t.Context()); !errors.Is(err, ErrAssertionSource) {
			t.Fatal("ambiguous source accepted", err)
		}
	}
	t.Setenv("VERCEL_OIDC_TOKEN", "fallback.jwt.value")
	t.Setenv("VERCEL_OIDC_TOKEN_FILE", file)
	if err := os.WriteFile(file, nil, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Acquire(t.Context(), workloadmanifest.Acquisition{Method: "vercel-oidc"}, nil); !errors.Is(err, ErrAssertionUnavailable) {
		t.Fatal("empty configured file fell back to env", err)
	}
	if raw, err := Acquire(t.Context(), workloadmanifest.Acquisition{Method: "vercel-oidc"}, func(context.Context) (string, error) { return "request.jwt.value", nil }); err != nil || raw != "request.jwt.value" {
		t.Fatal("request callback did not own acquisition", err)
	}
	if _, err := (AssertionSource{Assertion: strings.Repeat("x", (32<<10)+1)}).Acquire(t.Context()); !errors.Is(err, ErrAssertionUnavailable) {
		t.Fatal("oversized assertion accepted")
	}
}

func TestFlyMachineTokenWire(t *testing.T) {
	socket := filepath.Join(t.TempDir(), "api.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" || r.URL.Path != "/v1/tokens/oidc" || r.Header.Get("Authorization") != "" {
			t.Error("unexpected machine token request")
		}
		var body struct {
			Audience string `json:"aud"`
		}
		if json.NewDecoder(r.Body).Decode(&body) != nil || body.Audience != "https://fly.io/acme" {
			t.Error("wrong machine audience")
		}
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("signed.machine.jwt\n"))
	})}
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() { _ = server.Close() })
	if raw, err := flyAssertion(t.Context(), "https://fly.io/acme", socket); err != nil || raw != "signed.machine.jwt" {
		t.Fatal("documented text token response rejected", err)
	}
}

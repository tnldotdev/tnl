package oidc_test

import (
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/control/oidc"
	"github.com/tnldotdev/tnl/internal/testutil/githubtest"
)

func TestGitHubWorkloadClaims(t *testing.T) {
	issuer := githubtest.New(t)
	verifier, err := oidc.NewGitHubWorkloadVerifier("https://control.example:443/", issuer.Client)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	if claims, err := verifier.Verify(t.Context(), issuer.Sign(t, githubtest.Claims("https://control.example", now))); err != nil || claims.CheckRunID != "222" {
		t.Fatal(claims, err)
	}
	for name, mutation := range map[string]func(map[string]any){
		"issuer":             func(c map[string]any) { c["iss"] = "https://attacker.example" },
		"audience":           func(c map[string]any) { c["aud"] = "https://other.example" },
		"multiple-audiences": func(c map[string]any) { c["aud"] = []string{"https://control.example", "other"} },
		"expired":            func(c map[string]any) { c["exp"] = now.Add(-time.Minute).Unix() },
		"future-iat":         func(c map[string]any) { c["iat"] = now.Add(time.Minute).Unix() },
		"future-nbf":         func(c map[string]any) { c["nbf"] = now.Add(time.Minute).Unix() },
		"missing-nbf":        func(c map[string]any) { delete(c, "nbf") },
		"stale":              func(c map[string]any) { c["iat"] = now.Add(-6 * time.Minute).Unix() },
		"long-lived":         func(c map[string]any) { c["exp"] = now.Add(time.Hour).Unix() },
		"numeric-run":        func(c map[string]any) { c["run_id"] = 111 },
		"missing-check":      func(c map[string]any) { delete(c, "check_run_id"); c["job_id"] = "invented" },
		"oversized-jti":      func(c map[string]any) { c["jti"] = strings.Repeat("a", 129) },
		"typed-jti":          func(c map[string]any) { c["jti"] = []string{"id"} },
		"control-subject":    func(c map[string]any) { c["sub"] = "unsafe\nsubject" },
	} {
		t.Run(name, func(t *testing.T) {
			claims := githubtest.Claims("https://control.example", now)
			mutation(claims)
			if _, err := verifier.Verify(t.Context(), issuer.Sign(t, claims)); !errors.Is(err, oidc.ErrUnauthenticated) {
				t.Fatalf("accepted invalid claims: %v", err)
			}
		})
	}
}

type failedGitHubKeys struct{ cause error }

func (t failedGitHubKeys) RoundTrip(*http.Request) (*http.Response, error) { return nil, t.cause }

func TestGitHubWorkloadSignatureAndKeyFailures(t *testing.T) {
	issuer := githubtest.New(t)
	other := githubtest.New(t)
	v, err := oidc.NewGitHubWorkloadVerifier("https://control.example", issuer.Client)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = v.Verify(t.Context(), other.Sign(t, githubtest.Claims("https://control.example", time.Now()))); !errors.Is(err, oidc.ErrUnauthenticated) {
		t.Fatal("accepted another signing key", err)
	}
	if _, err = v.Verify(t.Context(), "eyJhbGciOiJub25lIn0.e30."); !errors.Is(err, oidc.ErrUnauthenticated) {
		t.Fatal("accepted unsigned JWT", err)
	}
	cause := errors.New("local signing-key transport failure")
	v, err = oidc.NewGitHubWorkloadVerifier("https://control.example", &http.Client{Transport: failedGitHubKeys{cause}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = v.Verify(t.Context(), issuer.Sign(t, githubtest.Claims("https://control.example", time.Now()))); !errors.Is(err, oidc.ErrUnavailable) || !errors.Is(err, cause) {
		t.Fatal("provider failure lost classification or cause", err)
	}
}

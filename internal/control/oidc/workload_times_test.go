package oidc_test

import (
	"errors"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/control/oidc"
	"github.com/tnldotdev/tnl/internal/testutil/githubtest"
)

func TestWorkloadOptionalNotBefore(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	policy := oidc.WorkloadTrust{Provider: "oidc", Issuer: "https://issuer.example", JWKSURL: "https://issuer.example/.well-known/jwks", Audience: "tnl", Claims: map[string]string{"sub": "worker"}}
	issuer := githubtest.NewProvider(t, policy.Issuer)
	verifier, err := oidc.NewWorkloadVerifier("https://control.example", issuer.Client)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name   string
		change func(map[string]any)
		valid  bool
	}{
		{"absent", func(map[string]any) {}, true},
		{"present", func(c map[string]any) { c["nbf"] = now.Unix() }, true},
		{"null", func(c map[string]any) { c["nbf"] = nil }, false},
		{"zero", func(c map[string]any) { c["nbf"] = 0 }, false},
		{"string", func(c map[string]any) { c["nbf"] = "now" }, false},
		{"future", func(c map[string]any) { c["nbf"] = now.Add(time.Hour).Unix() }, false},
		{"future issuance", func(c map[string]any) { c["iat"] = now.Add(time.Hour).Unix() }, false},
		{"missing issuance", func(c map[string]any) { delete(c, "iat") }, false},
		{"expired", func(c map[string]any) { c["exp"] = now.Add(-time.Second).Unix() }, false},
		{"extra audience", func(c map[string]any) { c["aud"] = []string{"tnl", "other"} }, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			claims := map[string]any{"iss": policy.Issuer, "aud": policy.Audience, "sub": "worker", "iat": now.Unix(), "exp": now.Add(time.Hour).Unix()}
			test.change(claims)
			verified, err := verifier.Verify(t.Context(), policy, issuer.Sign(t, claims))
			if test.valid {
				if err != nil || verified.NotBefore != now.Unix() || !verified.Matches(policy) {
					t.Fatal("valid token rejected or effective start changed", err)
				}
			} else if !errors.Is(err, oidc.ErrUnauthenticated) {
				t.Fatal("invalid token accepted", err)
			}
		})
	}
}

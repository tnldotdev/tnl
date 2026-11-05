package oidc_test

import (
	"errors"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/control/oidc"
	"github.com/tnldotdev/tnl/internal/testutil/githubtest"
)

func TestGoogleWorkloadIdentity(t *testing.T) {
	policy := oidc.WorkloadTrust{Provider: "google", Issuer: config.GoogleWorkloadIssuer, JWKSURL: config.GoogleWorkloadJWKS, Audience: "https://control.example", Claims: map[string]string{"sub": "112010400000000710080"}}
	issuer := githubtest.NewKeySet(t, policy.JWKSURL)
	verifier, err := oidc.NewWorkloadVerifier(policy.Audience, issuer.Client)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	claims := map[string]any{"iss": policy.Issuer, "aud": policy.Audience, "sub": policy.Claims["sub"], "iat": now.Unix(), "exp": now.Add(time.Hour).Unix()}
	if verified, err := verifier.Verify(t.Context(), policy, issuer.Sign(t, claims)); err != nil || !verified.Matches(policy) {
		t.Fatal("Google identity without optional email or not-before rejected", err)
	}
	for _, field := range []string{"sub", "iss", "aud", "exp", "iat", "nbf"} {
		original, existed := claims[field]
		claims[field] = "wrong"
		if _, err := verifier.Verify(t.Context(), policy, issuer.Sign(t, claims)); !errors.Is(err, oidc.ErrUnauthenticated) {
			t.Fatal("invalid Google claim accepted", field, err)
		}
		if existed {
			claims[field] = original
		} else {
			delete(claims, field)
		}
	}
	claims["email"], claims["email_verified"] = "renamed@project.iam.gserviceaccount.com", true
	if _, err := verifier.Verify(t.Context(), policy, issuer.Sign(t, claims)); err != nil {
		t.Fatal("optional email replaced numeric authority", err)
	}
	claims["sub"] = "212010400000000710080"
	if _, err := verifier.Verify(t.Context(), policy, issuer.Sign(t, claims)); !errors.Is(err, oidc.ErrUnauthenticated) {
		t.Fatal("email bypassed immutable subject binding", err)
	}
}

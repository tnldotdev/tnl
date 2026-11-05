package oidc_test

import (
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/control/oidc"
	"github.com/tnldotdev/tnl/internal/testutil/githubtest"
)

func TestKubernetesWorkloadPinsAccountUIDAndPodExecution(t *testing.T) {
	issuerURL := "https://oidc.eks.us-west-2.amazonaws.com/id/example"
	policy := oidc.WorkloadTrust{Provider: "kubernetes", Issuer: issuerURL, JWKSURL: issuerURL + "/keys", Audience: "https://control.example", Claims: map[string]string{"sub": "system:serviceaccount:production:orders", "service_account_uid": "11111111-1111-4111-8111-111111111111"}}
	issuer := githubtest.NewKeySet(t, policy.JWKSURL)
	verifier, err := oidc.NewWorkloadVerifier(policy.Audience, issuer.Client)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	account := map[string]any{"name": "orders", "uid": policy.Claims["service_account_uid"]}
	pod := map[string]any{"name": "orders-one", "uid": "22222222-2222-4222-8222-222222222222"}
	kube := map[string]any{"namespace": "production", "serviceaccount": account, "pod": pod}
	claims := map[string]any{"iss": policy.Issuer, "aud": []string{policy.Audience}, "sub": policy.Claims["sub"], "iat": now.Unix(), "exp": now.Add(time.Hour).Unix(), "kubernetes.io": kube}
	first, err := verifier.Verify(t.Context(), policy, issuer.Sign(t, claims))
	if err != nil || first.Kubernetes == nil || !first.Matches(policy) {
		t.Fatal("projected Pod token rejected", err)
	}
	claims["exp"] = now.Add(2 * time.Hour).Unix()
	claims["iat"] = now.Add(time.Second).Unix()
	claims["nbf"] = now.Unix()
	kube["warnafter"] = now.Add(30 * time.Minute).Unix()
	kube["node"] = map[string]any{"name": "worker-one", "uid": "55555555-5555-4555-8555-555555555555"}
	rotated, err := verifier.Verify(t.Context(), policy, issuer.Sign(t, claims))
	if err != nil || first.IdentityDigest() != rotated.IdentityDigest() {
		t.Fatal("proof rotation replaced the Pod execution", err)
	}
	pod["uid"] = "33333333-3333-4333-8333-333333333333"
	other, err := verifier.Verify(t.Context(), policy, issuer.Sign(t, claims))
	if err != nil || other.IdentityDigest() == first.IdentityDigest() {
		t.Fatal("a different Pod reused execution identity", err)
	}
	pod["uid"] = "22222222-2222-4222-8222-222222222222"
	account["uid"] = "44444444-4444-4444-8444-444444444444"
	if _, err := verifier.Verify(t.Context(), policy, issuer.Sign(t, claims)); !errors.Is(err, oidc.ErrUnauthenticated) {
		t.Fatal("recreated account inherited the saved grant", err)
	}
	account["uid"] = policy.Claims["service_account_uid"]
	for _, test := range []struct {
		name   string
		change func(map[string]any, map[string]any, map[string]any, map[string]any)
	}{
		{"missing namespace", func(_ map[string]any, k, _, _ map[string]any) { delete(k, "namespace") }},
		{"wrong namespace", func(_ map[string]any, k, _, _ map[string]any) { k["namespace"] = "another" }},
		{"wrong subject", func(c, _, _, _ map[string]any) { c["sub"] = "system:serviceaccount:production:another" }},
		{"wrong account name", func(_, _, a, _ map[string]any) { a["name"] = "another" }},
		{"malformed account uid", func(_, _, a, _ map[string]any) { a["uid"] = 123 }},
		{"missing pod name", func(_, _, _, p map[string]any) { delete(p, "name") }},
		{"invalid pod name", func(_, _, _, p map[string]any) { p["name"] = "../other" }},
		{"missing pod uid", func(_, _, _, p map[string]any) { delete(p, "uid") }},
		{"malformed pod uid", func(_, _, _, p map[string]any) { p["uid"] = "not-a-uid" }},
		{"wrong audience", func(c, _, _, _ map[string]any) { c["aud"] = "https://another.example" }},
		{"extra audience", func(c, _, _, _ map[string]any) { c["aud"] = []string{policy.Audience, "https://another.example"} }},
		{"null not-before", func(c, _, _, _ map[string]any) { c["nbf"] = nil }},
		{"expired proof", func(c, _, _, _ map[string]any) { c["exp"] = now.Add(-time.Minute).Unix() }},
		{"excessive proof lifetime", func(c, _, _, _ map[string]any) { c["exp"] = now.Add(13 * time.Hour).Unix() }},
	} {
		t.Run(test.name, func(t *testing.T) {
			data, err := json.Marshal(claims)
			if err != nil {
				t.Fatal(err)
			}
			var invalid map[string]any
			if err := json.Unmarshal(data, &invalid); err != nil {
				t.Fatal(err)
			}
			k := invalid["kubernetes.io"].(map[string]any)
			test.change(invalid, k, k["serviceaccount"].(map[string]any), k["pod"].(map[string]any))
			if _, err := verifier.Verify(t.Context(), policy, issuer.Sign(t, invalid)); !errors.Is(err, oidc.ErrUnauthenticated) {
				t.Fatal("invalid Pod identity accepted", err)
			}
		})
	}
	delete(kube, "pod")
	if _, err := verifier.Verify(t.Context(), policy, issuer.Sign(t, claims)); !errors.Is(err, oidc.ErrUnauthenticated) {
		t.Fatal("unbound service-account token established a Pod execution", err)
	}
}

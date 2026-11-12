package state

import (
	"errors"
	"maps"
	"testing"

	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/control/oidc"
)

func TestKubernetesWorkloadTrustPinsAccountAndSetupSelectors(t *testing.T) {
	p := oidc.WorkloadTrust{Provider: "kubernetes", Issuer: "https://issuer.example/cluster", JWKSURL: "https://issuer.example/cluster/keys", Audience: "https://control.example", Claims: map[string]string{"sub": "system:serviceaccount:production:orders", "service_account_uid": "11111111-1111-4111-8111-111111111111"}}
	if err := validateMachineOIDCTrust(p); err != nil {
		t.Fatal("valid Kubernetes trust rejected", err)
	}
	for _, change := range []func(*oidc.WorkloadTrust){
		func(p *oidc.WorkloadTrust) { p.JWKSURL = "http://issuer.example/keys" },
		func(p *oidc.WorkloadTrust) { delete(p.Claims, "service_account_uid") },
		func(p *oidc.WorkloadTrust) { p.Claims["service_account_uid"] = "not-a-uid" },
		func(p *oidc.WorkloadTrust) { p.Claims["pod_uid"] = "22222222-2222-4222-8222-222222222222" },
	} {
		bad := p
		bad.Claims = maps.Clone(p.Claims)
		change(&bad)
		if err := validateMachineOIDCTrust(bad); !errors.Is(err, ErrEnvironmentInvalid) {
			t.Fatal("invalid Kubernetes trust accepted", err)
		}
	}
	setup := config.WorkloadKubernetes{Context: "eks-development", Namespace: "production", ServiceAccount: "orders"}
	for _, change := range []func(*config.WorkloadKubernetes){func(p *config.WorkloadKubernetes) { p.ServiceAccount = "" }, func(p *config.WorkloadKubernetes) { p.Audience = "*" }} {
		bad := setup
		change(&bad)
		if err := config.ValidateWorkloads(config.Services{"api": {}}, map[string]config.Workload{"test": {Kubernetes: &bad, Services: []string{"api"}}}); err == nil {
			t.Fatal("invalid setup selectors accepted")
		}
	}
	if err := config.ValidateWorkloads(config.Services{"api": {}}, map[string]config.Workload{"test": {Services: []string{"api"}}}); err == nil {
		t.Fatal("missing Kubernetes setup accepted")
	}
	for _, subject := range []string{"system:serviceaccount:another:orders", "system:serviceaccount:production:another"} {
		bad := p
		bad.Claims = maps.Clone(p.Claims)
		bad.Claims["sub"] = subject
		execution := oidc.WorkloadExecution{Provider: p.Provider, Issuer: p.Issuer, Audience: p.Audience, TrustDigest: bad.Digest(), Subject: p.Claims["sub"], Kubernetes: &oidc.KubernetesExecution{Namespace: "production", ServiceAccount: oidc.KubernetesObjectIdentity{Name: "orders", UID: p.Claims["service_account_uid"]}}}
		if execution.Matches(bad) {
			t.Fatal("another setup account matched approved identity")
		}
	}
}

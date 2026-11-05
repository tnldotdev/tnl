package state

import (
	"errors"
	"testing"

	"github.com/tnldotdev/tnl/internal/control/oidc"
)

func TestKubernetesWorkloadTrustPinsAccountAndSetupSelectors(t *testing.T) {
	p := ProjectWorkload{Provider: "kubernetes", Kubernetes: &ProjectWorkloadKubernetes{Context: "eks-development", ClusterServer: "https://cluster.example.test", Namespace: "production", ServiceAccount: "orders"}, Trust: oidc.WorkloadTrust{Provider: "kubernetes", Issuer: "https://issuer.example/cluster", JWKSURL: "https://issuer.example/cluster/keys", Audience: "https://control.example", Claims: map[string]string{"sub": "system:serviceaccount:production:orders", "service_account_uid": "11111111-1111-4111-8111-111111111111"}}}
	if err := p.validateTrust(); err != nil {
		t.Fatal("valid Kubernetes trust rejected", err)
	}
	for _, change := range []func(*ProjectWorkload){
		func(p *ProjectWorkload) { p.Kubernetes = nil },
		func(p *ProjectWorkload) { p.Kubernetes.Context = "" },
		func(p *ProjectWorkload) { p.Kubernetes.ClusterServer = "http://cluster.example.test" },
		func(p *ProjectWorkload) { p.Kubernetes.Namespace = "another" },
		func(p *ProjectWorkload) { p.Kubernetes.ServiceAccount = "another" },
		func(p *ProjectWorkload) { p.Trust.JWKSURL = "http://issuer.example/keys" },
		func(p *ProjectWorkload) { delete(p.Trust.Claims, "service_account_uid") },
		func(p *ProjectWorkload) { p.Trust.Claims["service_account_uid"] = "not-a-uid" },
		func(p *ProjectWorkload) { p.Trust.Claims["pod_uid"] = "22222222-2222-4222-8222-222222222222" },
	} {
		bad := p
		selectors := *p.Kubernetes
		bad.Kubernetes = &selectors
		bad.Trust.Claims = map[string]string{}
		for key, value := range p.Trust.Claims {
			bad.Trust.Claims[key] = value
		}
		change(&bad)
		if err := bad.validateTrust(); !errors.Is(err, ErrProjectConfigurationInvalid) {
			t.Fatal("invalid Kubernetes trust accepted", err)
		}
	}
}

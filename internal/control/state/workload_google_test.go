package state

import (
	"errors"
	"testing"

	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/control/oidc"
)

func TestGoogleWorkloadTrustIsFixedAndNumericallyBound(t *testing.T) {
	trust := oidc.WorkloadTrust{Provider: "google", Issuer: config.GoogleWorkloadIssuer, JWKSURL: config.GoogleWorkloadJWKS, Audience: "https://control.example", Claims: map[string]string{"sub": "112010400000000710080"}}
	if err := validateMachineOIDCTrust(trust); err != nil {
		t.Fatal("valid Google trust rejected", err)
	}
	for _, change := range []func(*oidc.WorkloadTrust){
		func(p *oidc.WorkloadTrust) { p.Issuer = "https://attacker.example" },
		func(p *oidc.WorkloadTrust) { p.JWKSURL = "https://attacker.example/keys" },
		func(p *oidc.WorkloadTrust) {
			p.Claims = map[string]string{"sub": "orders@project.iam.gserviceaccount.com"}
		},
		func(p *oidc.WorkloadTrust) {
			p.Claims = map[string]string{"sub": "112010400000000710080", "email": "orders@project.iam.gserviceaccount.com"}
		},
	} {
		bad := trust
		change(&bad)
		if err := validateMachineOIDCTrust(bad); !errors.Is(err, ErrEnvironmentInvalid) {
			t.Fatal("changed Google authority accepted", err)
		}
	}
	// setup selectors belong to config authoring, not a second state trust model.
	for _, account := range []*config.WorkloadGoogle{nil, {ServiceAccount: "*"}} {
		if err := config.ValidateWorkloads(config.Services{"api": {}}, map[string]config.Workload{"test": {Google: account, Services: []string{"api"}}}); err == nil {
			t.Fatal("missing or inexact setup account accepted")
		}
	}
	if err := config.ValidateWorkloads(config.Services{"api": {}}, map[string]config.Workload{"test": {Google: &config.WorkloadGoogle{ServiceAccount: "orders@project.iam.gserviceaccount.com"}, Services: []string{"api"}}}); err != nil {
		t.Fatal("valid setup account rejected", err)
	}
	// setup now also accepts an already-resolved numeric account. another exact
	// account remains a distinct identity, never an alias for the approved one.
	other := trust
	other.Claims = map[string]string{"sub": "212010400000000710080"}
	execution := oidc.WorkloadExecution{Provider: trust.Provider, Issuer: trust.Issuer, Audience: trust.Audience, TrustDigest: other.Digest(), Subject: trust.Claims["sub"]}
	if execution.Matches(other) {
		t.Fatal("another numeric account adopted approved identity")
	}
}

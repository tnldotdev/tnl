package state

import (
	"errors"
	"testing"

	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/control/oidc"
)

func TestGoogleWorkloadTrustIsFixedAndNumericallyBound(t *testing.T) {
	p := ProjectWorkload{Provider: "google", Google: &ProjectWorkloadGoogle{ServiceAccount: "orders@project.iam.gserviceaccount.com"}, Trust: oidc.WorkloadTrust{Provider: "google", Issuer: config.GoogleWorkloadIssuer, JWKSURL: config.GoogleWorkloadJWKS, Audience: "https://control.example", Claims: map[string]string{"sub": "112010400000000710080"}}}
	if err := p.validateTrust(); err != nil {
		t.Fatal("valid Google trust rejected", err)
	}
	for _, change := range []func(*ProjectWorkload){
		func(p *ProjectWorkload) { p.Trust.Issuer = "https://attacker.example" },
		func(p *ProjectWorkload) { p.Trust.JWKSURL = "https://attacker.example/keys" },
		func(p *ProjectWorkload) {
			p.Trust.Claims = map[string]string{"sub": "orders@project.iam.gserviceaccount.com"}
		},
		func(p *ProjectWorkload) {
			p.Trust.Claims = map[string]string{"sub": "112010400000000710080", "email": "orders@project.iam.gserviceaccount.com"}
		},
		func(p *ProjectWorkload) { p.Google = nil },
		func(p *ProjectWorkload) { p.Google = &ProjectWorkloadGoogle{ServiceAccount: "212010400000000710080"} },
	} {
		bad := p
		change(&bad)
		if err := bad.validateTrust(); !errors.Is(err, ErrProjectConfigurationInvalid) {
			t.Fatal("changed Google authority accepted", err)
		}
	}
}

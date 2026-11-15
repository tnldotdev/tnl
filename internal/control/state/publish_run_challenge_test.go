package state

import (
	"testing"

	"github.com/tnldotdev/tnl/internal/security/certificateidentity"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestPublishRunRequestValidatesChallengeMethod(t *testing.T) {
	for _, test := range []struct {
		name        string
		method      certificateidentity.ChallengeMethod
		identifiers []string
		wantError   bool
	}{
		{"dns_exact", certificateidentity.ChallengeDNS01, []string{"route.example.test"}, false},
		{"dns_wildcard", certificateidentity.ChallengeDNS01, []string{"*.route.example.test"}, false},
		{"unknown", certificateidentity.ChallengeMethod("other"), []string{"route.example.test"}, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := certificateidentity.CanonicalPlan(controlv1.CertificatePlan{
				CacheKey: "test", Scope: "route.example.test", Identifiers: test.identifiers, ChallengeMethod: controlv1.CertificateChallengeMethod(test.method),
			})
			if (err != nil) != test.wantError {
				t.Fatal("certificate challenge validation changed", err)
			}
		})
	}
}

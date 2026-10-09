package authorization

import (
	"slices"
	"testing"

	"github.com/tnldotdev/tnl/internal/certificateidentity"
)

func TestPublicURLCertificatePlanDoesNotCrossNamespaceOrScope(t *testing.T) {
	const namespace = "alex.studio.example.com"
	first := PublicURLCertificatePlan("web."+namespace, namespace, true, true)
	second := PublicURLCertificatePlan("api."+namespace, namespace, true, true)
	if first.CacheKey != namespace || second.CacheKey != namespace ||
		!slices.Equal(first.Identifiers, []string{"*." + namespace, namespace}) ||
		!certificateidentity.Covers(first.Identifiers, "api."+namespace) ||
		certificateidentity.Covers(first.Identifiers, "web.sam.studio.example.com") ||
		certificateidentity.Covers(first.Identifiers, "api.preview."+namespace) {
		t.Fatalf("member pool crossed namespace: first=%#v, second=%#v", first, second)
	}
	for _, test := range []struct {
		name          string
		hostname      string
		member        bool
		dnsAutomation bool
		method        certificateidentity.ChallengeMethod
	}{
		{"nested", "api.preview." + namespace, true, true, certificateidentity.ChallengeDNS01},
		{"shared", "app.studio.example.com", false, true, certificateidentity.ChallengeDNS01},
		{"manual_dns", "web." + namespace, true, false, certificateidentity.ChallengeTLSALPN01},
	} {
		t.Run(test.name, func(t *testing.T) {
			plan := PublicURLCertificatePlan(test.hostname, namespace, test.member, test.dnsAutomation)
			if plan.CacheKey != test.hostname || !slices.Equal(plan.Identifiers, []string{test.hostname}) ||
				plan.ChallengeMethod != test.method {
				t.Fatalf("exact plan = %#v", plan)
			}
		})
	}
}

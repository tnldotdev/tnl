package authorization

import (
	"github.com/tnldotdev/tnl/internal/certificateidentity"
	"github.com/tnldotdev/tnl/internal/naming"
)

// PublicURLCertificatePlan groups sibling URLs beneath the narrowest authorized
// wildcard when DNS automation is available. apexAllowed applies only to the
// root of a shared custom domain, not to member namespaces.
func PublicURLCertificatePlan(hostname, namespace string, apexAllowed, dnsAutomation bool) *CertificatePlan {
	plan := &CertificatePlan{
		CacheKey: hostname, Scope: hostname, Identifiers: []string{hostname},
		ChallengeMethod: certificateidentity.ChallengeTLSALPN01,
	}
	if dnsAutomation {
		plan.ChallengeMethod = certificateidentity.ChallengeDNS01
		if hostname == namespace && apexAllowed {
			plan.Identifiers = []string{"*." + namespace, namespace}
		}
		if wildcard := naming.PublicURLWildcard(hostname, namespace); wildcard != "" {
			root := wildcard[2:]
			plan.CacheKey, plan.Scope = root, root
			plan.Identifiers = []string{wildcard}
			if root == namespace && apexAllowed {
				plan.Identifiers = append(plan.Identifiers, root)
			}
		}
	}
	return plan
}

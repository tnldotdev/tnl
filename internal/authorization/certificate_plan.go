package authorization

import (
	"github.com/tnldotdev/tnl/internal/certificateidentity"
	"github.com/tnldotdev/tnl/internal/naming"
)

// PublicURLCertificatePlan selects the existing exact-name or member-namespace
// certificate plan after the hostname and public URL scope have been authorized.
func PublicURLCertificatePlan(hostname, namespace string, member, dnsAutomation bool) *CertificatePlan {
	plan := &CertificatePlan{
		CacheKey: hostname, Scope: hostname, Identifiers: []string{hostname},
		ChallengeMethod: certificateidentity.ChallengeTLSALPN01,
	}
	if dnsAutomation {
		plan.ChallengeMethod = certificateidentity.ChallengeDNS01
		if depth, within := naming.ChildDepth(hostname, namespace); member && within && depth <= 1 {
			plan.CacheKey, plan.Scope = namespace, namespace
			plan.Identifiers = []string{"*." + namespace, namespace}
		}
	}
	return plan
}

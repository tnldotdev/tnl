package state

import (
	"slices"
	"testing"

	"github.com/tnldotdev/tnl/internal/security/certificateidentity"
)

func TestRunAliasCertificatePlanKeepsOnlyApprovedNames(t *testing.T) {
	for _, test := range []struct {
		name, hostname, alias string
		plan                  CertificatePlan
		want                  []string
	}{
		{"disabled", "site.example.test", "", CertificatePlan{CacheKey: "site.example.test", Scope: "site.example.test", Identifiers: []string{"site.example.test"}}, []string{"site.example.test"}},
		{"reuse wildcard", "site.example.test", "r-one.example.test", CertificatePlan{CacheKey: "example.test", Scope: "example.test", Identifiers: []string{"*.example.test"}}, []string{"*.example.test"}},
		{"exact pair", "site.example.test", "r-one.example.test", CertificatePlan{CacheKey: "site.example.test", Scope: "site.example.test", Identifiers: []string{"site.example.test"}}, []string{"r-one.example.test", "site.example.test"}},
		{"narrow wildcard", "site.apps.example.test", "r-one.example.test", CertificatePlan{CacheKey: "apps.example.test", Scope: "apps.example.test", Identifiers: []string{"*.apps.example.test"}}, []string{"r-one.example.test", "site.apps.example.test"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			before := slices.Clone(test.plan.Identifiers)
			got := certificatePlanWithRunAlias(test.plan, test.hostname, test.alias)
			if !slices.Equal(got.Identifiers, test.want) || !slices.Equal(test.plan.Identifiers, before) ||
				!certificateidentity.Covers(got.Identifiers, test.hostname) ||
				test.alias != "" && !certificateidentity.Covers(got.Identifiers, test.alias) {
				t.Fatal("alias plan lost coverage, changed input, or broadened approval")
			}
			if len(test.want) == 2 && (got.Scope != test.hostname || got.CacheKey == test.plan.CacheKey) {
				t.Fatal("exact-run plan reused another scope's cache entry")
			}
			retry := certificatePlanWithRunAlias(test.plan, test.hostname, test.alias)
			if got.CacheKey != retry.CacheKey {
				t.Fatal("alias certificate cache key changed on retry")
			}
		})
	}
}

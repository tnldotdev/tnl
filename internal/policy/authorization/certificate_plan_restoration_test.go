package authorization

import (
	"slices"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/security/certificateidentity"
)

func TestServiceCertificateRestoredRoutineTwelveCaseFormationMatrix(t *testing.T) {
	const (
		domain              = "routes.example.test"
		managedMember       = "member.team-generated.routes.example.test"
		customMember        = "member.routes.example.test"
		customDeployment    = "production.shop.routes.example.test"
		simpleDeployment    = "production.shop.studio.routes.example.test"
		generatedDeployment = "production.shop.team-generated.routes.example.test"
	)
	// these are explicit captured-scope facts, not authorization decisions.
	// state proves who may capture them in its paired integration matrix.
	for _, test := range []struct {
		name          string
		managed       bool
		shared        bool
		simple        bool
		personal      bool
		nested        bool
		noDNS         bool
		wantNamespace string
		wantScope     string
		wantIDs       []string
	}{
		{
			name: "managed_member_dns", managed: true, wantNamespace: managedMember,
			wantScope: "api." + managedMember, wantIDs: []string{"api." + managedMember},
		},
		{
			name: "custom_member_dns", wantNamespace: customMember,
			wantScope: "api." + customMember, wantIDs: []string{"api." + customMember},
		},
		{
			name: "managed_member_no_dns", managed: true, noDNS: true, wantNamespace: managedMember,
			wantScope: "api." + managedMember, wantIDs: []string{"api." + managedMember},
		},
		{
			name: "custom_member_no_dns", noDNS: true, wantNamespace: customMember,
			wantScope: "api." + customMember, wantIDs: []string{"api." + customMember},
		},
		{
			name: "shared_dns", shared: true, wantNamespace: customDeployment,
			wantScope: customDeployment, wantIDs: []string{"*." + customDeployment},
		},
		{
			name: "simple_team_shared_dns", managed: true, shared: true, simple: true, personal: true,
			wantNamespace: simpleDeployment, wantScope: simpleDeployment, wantIDs: []string{"*." + simpleDeployment},
		},
		{
			name: "generated_team_shared_dns", managed: true, shared: true, wantNamespace: generatedDeployment,
			wantScope: generatedDeployment, wantIDs: []string{"*." + generatedDeployment},
		},
		{
			name: "shared_no_dns", shared: true, noDNS: true, wantNamespace: customDeployment,
			wantScope: customDeployment, wantIDs: []string{"*." + customDeployment},
		},
		{
			name: "nested_managed_dns", managed: true, nested: true, wantNamespace: managedMember,
			wantScope: "api.shop." + managedMember, wantIDs: []string{"api.shop." + managedMember},
		},
		{
			name: "nested_managed_manual_dns", managed: true, nested: true, noDNS: true, wantNamespace: managedMember,
			wantScope: "api.shop." + managedMember, wantIDs: []string{"api.shop." + managedMember},
		},
		{
			name: "nested_custom_domain", nested: true, wantNamespace: customMember,
			wantScope: "api.shop." + customMember, wantIDs: []string{"api.shop." + customMember},
		},
		{
			// maxChildLabels=1 has no current formation-helper input.
			// this retains depth-two formation, not the removed denial.
			name: "nested_managed_limited", managed: true, nested: true, wantNamespace: managedMember,
			wantScope: "api.shop." + managedMember, wantIDs: []string{"api.shop." + managedMember},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			mode := naming.ManagedURLModeGenerated
			if test.simple {
				mode = naming.ManagedURLModeSimple
			}
			facts := naming.NamespaceFacts{
				Domain: domain, Managed: test.managed, Mode: mode, Personal: test.personal,
				TeamName: "studio", MemberSlug: "member", ManagedLabel: "team-generated",
			}
			var namespace string
			if test.shared {
				owner := naming.SharedPublicURLNamespace(domain, test.managed, mode, "studio", "team-generated")
				wantOwner := domain
				if test.managed {
					wantOwner = "team-generated." + domain
					if test.simple {
						wantOwner = "studio." + domain
					}
				}
				if owner != wantOwner {
					t.Fatalf("shared naming root=%q, want %q", owner, wantOwner)
				}
				var err error
				namespace, err = naming.DeploymentNamespace("production", "shop", owner)
				if err != nil {
					t.Fatal(err)
				}
				if test.personal {
					personal, direct := naming.PublicURLNamespace(facts)
					if personal != "studio."+domain || direct {
						t.Fatal("simple personal managed naming lost its team-bound suffix", personal, direct)
					}
				}
			} else {
				var direct bool
				namespace, direct = naming.PublicURLNamespace(facts)
				if direct {
					t.Fatal("member formation unexpectedly selected a direct shared name")
				}
			}
			if namespace != test.wantNamespace {
				t.Fatalf("namespace=%q, want %q", namespace, test.wantNamespace)
			}
			hostname := "api." + namespace
			wantDepth := 1
			if test.nested {
				hostname, wantDepth = "api.shop."+namespace, 2
			}
			if depth, within := naming.ChildDepth(hostname, namespace); !within || depth != wantDepth {
				t.Fatalf("hostname depth=%d within=%t, want %d/true", depth, within, wantDepth)
			}
			capturedScope := hostname
			if test.shared {
				capturedScope = namespace
			}
			checkPlan := func(got *CertificatePlan, want CertificatePlan) {
				t.Helper()
				if diff := cmp.Diff(&want, got); diff != "" {
					t.Fatalf("certificate plan (-want +got):\n%s", diff)
				}
				if !slices.IsSorted(got.Identifiers) {
					t.Fatalf("unsorted certificate identifiers: %v", got.Identifiers)
				}
			}
			// current state capture passes false/true here independently of
			// endpoint DNS automation or the API's issuance-availability gate.
			plan := ServiceCertificatePlan(hostname, capturedScope, false, true)
			checkPlan(plan, CertificatePlan{
				CacheKey: test.wantScope, Scope: test.wantScope, Identifiers: test.wantIDs,
				ChallengeMethod: certificateidentity.ChallengeDNS01,
			})
			for _, probe := range []struct {
				hostname string
				covered  bool
			}{
				{hostname, true},
				{namespace, false},
				{"sibling." + namespace, test.shared},
				{"deep." + hostname, false},
				{"api.outside." + domain, false},
			} {
				if got := certificateidentity.Covers(plan.Identifiers, probe.hostname); got != probe.covered {
					t.Fatalf("coverage of %q=%t, want %t", probe.hostname, got, probe.covered)
				}
			}
			if test.shared {
				// the existing helper narrows a deeper hostname to its
				// immediate parent; this does not approve a database grant.
				deeperHostname := "deep." + hostname
				narrowed := ServiceCertificatePlan(deeperHostname, capturedScope, false, true)
				checkPlan(narrowed, CertificatePlan{
					CacheKey: hostname, Scope: hostname, Identifiers: []string{"*." + hostname},
					ChallengeMethod: certificateidentity.ChallengeDNS01,
				})
				if !certificateidentity.Covers(narrowed.Identifiers, deeperHostname) ||
					certificateidentity.Covers(narrowed.Identifiers, hostname) ||
					certificateidentity.Covers(narrowed.Identifiers, "sibling."+namespace) {
					t.Fatal("deeper wildcard formation covered its apex or the original sibling namespace")
				}
				// an explicit deeper endpoint captured by current state instead
				// supplies that one exact hostname as its scope.
				exact := ServiceCertificatePlan(deeperHostname, deeperHostname, false, true)
				checkPlan(exact, CertificatePlan{
					CacheKey: deeperHostname, Scope: deeperHostname, Identifiers: []string{deeperHostname},
					ChallengeMethod: certificateidentity.ChallengeDNS01,
				})
				if !certificateidentity.Covers(exact.Identifiers, deeperHostname) ||
					certificateidentity.Covers(exact.Identifiers, "child."+deeperHostname) {
					t.Fatal("explicit deeper exact-host formation widened certificate coverage")
				}
			}
			if test.noDNS {
				// retain the pure helper's manual exact-host fallback contrast.
				// current state does not select it from endpoint/API availability;
				// notably shared_no_dns still captures the approved wildcard.
				manual := ServiceCertificatePlan(hostname, capturedScope, false, false)
				checkPlan(manual, CertificatePlan{
					CacheKey: hostname, Scope: hostname, Identifiers: []string{hostname},
					ChallengeMethod: certificateidentity.ChallengeDNS01,
				})
				if !certificateidentity.Covers(manual.Identifiers, hostname) ||
					certificateidentity.Covers(manual.Identifiers, "sibling."+namespace) {
					t.Fatal("manual formation lost exact-host coverage")
				}
			}
		})
	}
}

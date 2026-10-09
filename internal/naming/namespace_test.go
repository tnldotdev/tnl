package naming

import "testing"

func TestMemberNamespaceUsesTheDomainOwnershipLabel(t *testing.T) {
	if got := MemberNamespace("routes.example.com", true, "generated-label", "alex"); got != "generated-label.routes.example.com" {
		t.Fatalf("managed namespace = %q", got)
	}
	if got := MemberNamespace("studio.example.com", false, "generated-label", "alex"); got != "alex.studio.example.com" {
		t.Fatalf("custom namespace = %q", got)
	}
}

func TestPublicURLNamespaceOwnership(t *testing.T) {
	for _, test := range []struct {
		name, domain, team, want           string
		managed, personal, builtin, shared bool
		mode                               ManagedURLMode
	}{
		{"builtin_managed", "routes.example.com", "local-administrator", "routes.example.com", true, true, true, true, ManagedURLModeSimple},
		{"oidc_personal", "routes.example.com", "alex", "alex.routes.example.com", true, true, false, false, ManagedURLModeSimple},
		{"organization", "routes.example.com", "studio", "alex.studio.routes.example.com", true, false, false, false, ManagedURLModeSimple},
		{"personal_custom", "dev.example.com", "alex", "dev.example.com", false, true, false, true, ManagedURLModeSimple},
		{"organization_custom", "studio.example.com", "studio", "alex.studio.example.com", false, false, false, false, ManagedURLModeSimple},
		{"hosted_managed", "tnl.dev", "studio", "ecstatic-penguin.tnl.dev", true, false, false, false, ManagedURLModeGenerated},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, shared := PublicURLNamespace(NamespaceFacts{Domain: test.domain, Managed: test.managed,
				Mode: test.mode, TeamName: test.team, MemberSlug: "alex", ManagedLabel: "ecstatic-penguin",
				Personal: test.personal, Builtin: test.builtin})
			if got != test.want || shared != test.shared {
				t.Fatalf("suffix = %q, shared = %t; want %q, %t", got, shared, test.want, test.shared)
			}
		})
	}
}

func TestPublicURLWildcardStaysUnderTheAuthorizedNamespace(t *testing.T) {
	const namespace = "alex.studio.routes.example.com"
	for _, test := range []struct{ hostname, want string }{
		{"app." + namespace, "*." + namespace},
		{"api.preview." + namespace, "*.preview." + namespace},
		{namespace, ""},
		{"api.bob.studio.routes.example.com", ""},
	} {
		if got := PublicURLWildcard(test.hostname, namespace); got != test.want {
			t.Errorf("wildcard for %q = %q, want %q", test.hostname, got, test.want)
		}
	}
}

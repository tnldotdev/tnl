package naming

import (
	"strings"
	"testing"
)

func TestManagedGroupUsesExistingNamespace(t *testing.T) {
	for _, owner := range []string{"alex.studio.example.com", "studio.example.com", "ecstatic-penguin.tnl.dev"} {
		namespace, err := GroupNamespace("production", "storefront", owner)
		if err != nil || namespace != "production.storefront."+owner || PublicURLWildcard("orders."+namespace, owner) != "*."+namespace {
			t.Fatalf("namespace = %q, %v", namespace, err)
		}
	}
	for _, group := range []string{"local", "Production", "a.b", "-invalid"} {
		if _, err := GroupNamespace(group, "storefront", "dev.acme.com"); err == nil {
			t.Fatalf("invalid group %q accepted", group)
		}
	}
	if _, err := GroupNamespace("production", "storefront", strings.Repeat("a.", 115)+"example.com"); err == nil {
		t.Fatal("oversized validation record accepted")
	}
	if got := ProjectDNSLabel("tnl.dev", "apps/accounts"); got != "tnl-dev-apps-accounts" {
		t.Fatal(got)
	}
}

func TestProjectDNSLabelFitsLongMonorepoNamespace(t *testing.T) {
	directory := strings.Repeat("platform/", 12) + "accounts"
	label := ProjectDNSLabel("company-monorepo", directory)
	if label == "" || len(label) > 63 {
		t.Fatalf("generated project label exceeds DNS bounds: %q", label)
	}
	if _, err := GroupNamespace("production", label, "alex.example.test"); err != nil {
		t.Fatalf("automatic namespace rejected: %v", err)
	}
	if label != ProjectDNSLabel("company-monorepo", directory) || label == ProjectDNSLabel("company-monorepo", directory+"-other") {
		t.Fatal("long labels must be stable and preserve distinguishing suffixes")
	}
	if got := ProjectDNSLabel("...", "."); got == "" {
		t.Fatal("empty normalized repository needs a usable fallback")
	}
}

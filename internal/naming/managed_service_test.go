package naming

import (
	"strings"
	"testing"
)

func TestManagedGroupUsesExistingNamespace(t *testing.T) {
	for _, owner := range []string{"alex.studio.example.com", "studio.example.com", "ecstatic-penguin.tnl.dev"} {
		namespace, err := ManagedGroupNamespace("production", "storefront", owner)
		if err != nil || namespace != "production.storefront."+owner || PublicURLWildcard("orders."+namespace, owner) != "*."+namespace {
			t.Fatalf("namespace = %q, %v", namespace, err)
		}
	}
	for _, group := range []string{"local", "Production", "a.b", "-invalid"} {
		if _, err := ManagedGroupNamespace(group, "storefront", "dev.acme.com"); err == nil {
			t.Fatalf("invalid group %q accepted", group)
		}
	}
	if _, err := ManagedGroupNamespace("production", "storefront", strings.Repeat("a.", 115)+"example.com"); err == nil {
		t.Fatal("oversized validation record accepted")
	}
	if got := ProjectDNSLabel("tnl.dev", "apps/accounts"); got != "tnl-dev-apps-accounts" {
		t.Fatal(got)
	}
}

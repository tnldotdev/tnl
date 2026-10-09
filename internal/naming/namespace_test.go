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

package authorization

import (
	"slices"
	"testing"

	"github.com/tnldotdev/tnl/internal/certificateidentity"
)

func TestPublicURLCertificatePlanDoesNotCrossNamespaceOrScope(t *testing.T) {
	const namespace = "alex.studio.example.com"
	first := PublicURLCertificatePlan("web."+namespace, namespace, false, true)
	second := PublicURLCertificatePlan("api."+namespace, namespace, false, true)
	if first.CacheKey != namespace || second.CacheKey != namespace ||
		!slices.Equal(first.Identifiers, []string{"*." + namespace}) ||
		!certificateidentity.Covers(first.Identifiers, "api."+namespace) ||
		certificateidentity.Covers(first.Identifiers, namespace) ||
		certificateidentity.Covers(first.Identifiers, "web.sam.studio.example.com") ||
		certificateidentity.Covers(first.Identifiers, "api.preview."+namespace) {
		t.Fatalf("member pool crossed namespace: first=%#v, second=%#v", first, second)
	}
	nested := PublicURLCertificatePlan("api.preview."+namespace, namespace, false, true)
	if nested.CacheKey != "preview."+namespace || !slices.Equal(nested.Identifiers, []string{"*.preview." + namespace}) {
		t.Fatalf("nested pool = %#v", nested)
	}
	shared := PublicURLCertificatePlan("app.studio.example.com", "studio.example.com", true, true)
	apex := PublicURLCertificatePlan("studio.example.com", "studio.example.com", true, true)
	if shared.CacheKey != apex.CacheKey || !slices.Equal(shared.Identifiers, []string{"*.studio.example.com", "studio.example.com"}) ||
		!slices.Equal(shared.Identifiers, apex.Identifiers) {
		t.Fatalf("shared pool = %#v, apex = %#v", shared, apex)
	}
	manual := PublicURLCertificatePlan("web."+namespace, namespace, false, false)
	if manual.CacheKey != "web."+namespace || !slices.Equal(manual.Identifiers, []string{"web." + namespace}) ||
		manual.ChallengeMethod != certificateidentity.ChallengeTLSALPN01 {
		t.Fatalf("manual DNS plan = %#v", manual)
	}
}

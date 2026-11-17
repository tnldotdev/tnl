package authority

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	controlstate "github.com/tnldotdev/tnl/internal/control/state"
)

func TestDomainReleaseResponseIncludesOnlySafeOwnerFacts(t *testing.T) {
	now := time.Date(2026, 11, 16, 12, 0, 0, 0, time.UTC)
	expiry := now.Add(37 * time.Hour)
	internal := controlstate.Domain{ID: "dom_fixture", TeamID: "team_fixture", Kind: controlstate.DomainKindCustom,
		State: controlstate.DomainReleasing, DNSAuthorityReference: "private-authority-reference",
		Release: &controlstate.DomainRelease{ObservedAt: now, CompletionUnknown: true, CertificateExpiresAt: &expiry,
			Blockers: []string{"deployments", "services", "endpoint_dns", "challenge_cleanup", "issuance", "uncertain_issuance", "certificate", "dns_authority"}}}
	wire := domainResponse(internal)
	if wire.Release == nil || !wire.Release.CompletionUnknown || wire.Release.CertificateExpiresAt == nil ||
		!wire.Release.CertificateExpiresAt.Equal(expiry) || len(wire.Release.Blockers) != 8 || wire.Release.ReleasedAt != nil {
		t.Fatal("domain response lost actual expiry or invented completion", wire)
	}
	for _, blocker := range wire.Release.Blockers {
		if !blocker.Valid() {
			t.Fatalf("owner blocker %q is missing from the source contract", blocker)
		}
	}
	encoded, err := json.Marshal(wire)
	if err != nil {
		t.Fatal(err)
	}
	for _, private := range []string{"private-authority-reference", "provider_zone", "certificate_pem", "challenge_token"} {
		if strings.Contains(string(encoded), private) {
			t.Fatalf("release response disclosed private evidence: %s", encoded)
		}
	}
}

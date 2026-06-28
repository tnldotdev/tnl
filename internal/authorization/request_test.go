package authorization

import (
	"crypto/sha256"
	"slices"
	"strconv"
	"testing"
)

func TestCanonicalRequestAndIPPolicyHashes(t *testing.T) {
	prefixes, err := CanonicalizeIPPrefixes([]string{"2001:db8::1/64", "192.0.2.9/24"})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(prefixes, []string{"192.0.2.0/24", "2001:db8::/64"}) {
		t.Fatalf("prefixes = %#v", prefixes)
	}
	request := []byte(`{"allowed_ip_prefixes":["192.0.2.0/24","2001:db8::/64"],"canonical_hostname":"route.example","domain_id":"domain_1","membership_id":"membership_1","route_scope":"member","target":"http://127.0.0.1:3000","team_id":"team_1"}`)
	wantRequestDigest := Digest(sha256.Sum256(request))
	requestDigest, err := CanonicalRequestHash(OperationRequest{
		Operation: OperationRouteCreate, TeamID: "team_1", MembershipID: "membership_1", DomainID: "domain_1",
		CanonicalHostname: "route.example", RouteScope: "member", Target: "http://127.0.0.1:3000",
		AllowedIPPrefixes: prefixes,
	})
	if err != nil || requestDigest != wantRequestDigest {
		t.Fatalf("request digest = %s, want %s, error = %v", requestDigest, wantRequestDigest, err)
	}
	policyDigest, err := IPPolicyHash(prefixes)
	if err != nil {
		t.Fatal(err)
	}
	wantPolicyDigest := Digest(sha256.Sum256([]byte(`["192.0.2.0/24","2001:db8::/64"]`)))
	if policyDigest == nil || *policyDigest != wantPolicyDigest {
		t.Fatalf("policy digest = %v, want %s", policyDigest, wantPolicyDigest)
	}
	publicDigest, err := IPPolicyHash([]string{})
	if err != nil || publicDigest == nil || *publicDigest != Digest(sha256.Sum256([]byte(`[]`))) {
		t.Fatalf("public policy digest = %v, %v", publicDigest, err)
	}
	if none, err := IPPolicyHash(nil); err != nil || none != nil {
		t.Fatalf("nil policy digest = %v, %v", none, err)
	}
	deduplicated, err := CanonicalizeIPPrefixes([]string{"192.0.2.1/24", "192.0.2.0/24"})
	if err != nil || !slices.Equal(deduplicated, []string{"192.0.2.0/24"}) {
		t.Fatalf("deduplicated prefixes = %#v, %v", deduplicated, err)
	}
	tooMany := make([]string, MaxIPPrefixes+1)
	for index := range tooMany {
		tooMany[index] = "192.0.2." + strconv.Itoa(index)
	}
	if _, err := CanonicalizeIPPrefixes(tooMany); err == nil {
		t.Fatal("oversized prefix policy was accepted")
	}
	plan := CertificatePlan{CacheKey: "route.example", Scope: "route.example", Identifiers: []string{"route.example"}, ChallengeMethod: "tls-alpn-01"}
	sessionJSON := []byte(`{"allowed_ip_prefixes":["192.0.2.0/24","2001:db8::/64"],"certificate_plan":{"cache_key":"route.example","scope":"route.example","identifiers":["route.example"],"challenge_method":"tls-alpn-01"},"membership_id":"membership_1","policy_revision":3,"route_id":"route_1","route_version":4,"team_id":"team_1"}`)
	sessionDigest, err := CanonicalRequestHash(OperationRequest{
		Operation: OperationRouteSessionCreate, TeamID: "team_1", MembershipID: "membership_1", RouteID: "route_1",
		RouteVersion: 4, PolicyRevision: 3, CertificatePlan: &plan, AllowedIPPrefixes: prefixes,
	})
	if err != nil || sessionDigest != Digest(sha256.Sum256(sessionJSON)) {
		t.Fatalf("session digest = %s, error = %v", sessionDigest, err)
	}
	if _, err := CanonicalRequestHash(OperationRequest{
		Operation: OperationRouteSessionCreate, TeamID: "team_1", RouteID: "route_1", RouteVersion: 4,
		PolicyRevision: 3, CertificatePlan: &plan,
	}); err == nil {
		t.Fatal("route-session request without an IP policy was accepted")
	}
}

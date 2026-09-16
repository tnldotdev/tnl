package authorization

import (
	"crypto/sha256"
	"slices"
	"strconv"
	"testing"
)

func TestValidateRouteTarget(t *testing.T) {
	for _, target := range []string{"http://127.0.0.1:3000", "http://[::1]:3000"} {
		if err := ValidateRouteTarget(target); err != nil {
			t.Fatalf("target %q: %v", target, err)
		}
	}
	for _, target := range []string{
		"https://127.0.0.1:3000", "http://localhost:3000", "http://192.0.2.1:3000",
		"http://127.0.0.1", "http://127.0.0.1:3000/", "http://user@127.0.0.1:3000",
		"http://127.0.0.1:03000", "http://127.0.0.1:99999", "http://[0:0:0:0:0:0:0:1]:3000",
	} {
		if err := ValidateRouteTarget(target); err == nil {
			t.Fatalf("target %q was accepted", target)
		}
	}
}

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
	ephemeralDigest, err := CanonicalRequestHash(OperationRequest{
		Operation: OperationRouteCreate, TeamID: "team_1", MembershipID: "membership_1", DomainID: "domain_1",
		CanonicalHostname: "route.example", RouteScope: "member", Target: "http://127.0.0.1:3000",
		AllowedIPPrefixes: prefixes, Ephemeral: true,
	})
	if err != nil || ephemeralDigest == requestDigest {
		t.Fatalf("ephemeral request digest = %s, persistent digest = %s, error = %v", ephemeralDigest, requestDigest, err)
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
	if _, err := CanonicalizeIPPrefixes([]string{"192.0.2.1/24", "192.0.2.0/24"}); err == nil {
		t.Fatal("canonically duplicate prefixes were accepted")
	}
	tooMany := make([]string, MaxIPPrefixes+1)
	for index := range tooMany {
		tooMany[index] = "192.0.2." + strconv.Itoa(index)
	}
	if _, err := CanonicalizeIPPrefixes(tooMany); err == nil {
		t.Fatal("oversized prefix policy was accepted")
	}
	plan := CertificatePlan{CacheKey: "route.example", Scope: "route.example", Identifiers: []string{"route.example"}, ChallengeMethod: "tls-alpn-01"}
	sessionJSON := []byte(`{"allowed_ip_prefixes":["192.0.2.0/24","2001:db8::/64"],"canonical_hostname":"route.example","certificate_plan":{"cache_key":"route.example","scope":"route.example","identifiers":["route.example"],"challenge_method":"tls-alpn-01"},"domain_id":"domain_1","ephemeral":true,"membership_id":"membership_1","policy_revision":3,"route_id":"route_1","route_scope":"member","route_version":4,"target":"http://127.0.0.1:3000","team_id":"team_1"}`)
	sessionRequest := OperationRequest{
		Operation: OperationRouteSessionCreate, TeamID: "team_1", MembershipID: "membership_1", DomainID: "domain_1",
		CanonicalHostname: "route.example", RouteScope: "member", RouteID: "route_1", RouteVersion: 4,
		PolicyRevision: 3, Target: "http://127.0.0.1:3000", AllowedIPPrefixes: prefixes, Ephemeral: true,
		CertificatePlan: &plan,
	}
	sessionDigest, err := CanonicalRequestHash(sessionRequest)
	if err != nil || sessionDigest != Digest(sha256.Sum256(sessionJSON)) {
		t.Fatalf("session digest = %s, error = %v", sessionDigest, err)
	}
	sessionRequest.AllowedIPPrefixes = nil
	if _, err := CanonicalRequestHash(sessionRequest); err == nil {
		t.Fatal("route-session request without an IP policy was accepted")
	}
	updateJSON := []byte(`{"allowed_ip_prefixes":["192.0.2.0/24","2001:db8::/64"],"canonical_hostname":"route.example","domain_id":"domain_1","ephemeral":true,"membership_id":"membership_1","policy_revision":3,"route_id":"route_1","route_mutation_revision":4,"route_scope":"member","target":"http://127.0.0.1:4000","team_id":"team_1"}`)
	updateDigest, err := CanonicalRequestHash(OperationRequest{
		Operation: OperationRouteUpdate, TeamID: "team_1", MembershipID: "membership_1", DomainID: "domain_1",
		CanonicalHostname: "route.example", RouteScope: "member", RouteID: "route_1", RouteMutationRevision: 4, PolicyRevision: 3,
		Target: "http://127.0.0.1:4000", AllowedIPPrefixes: prefixes, Ephemeral: true,
	})
	if err != nil || updateDigest != Digest(sha256.Sum256(updateJSON)) {
		t.Fatalf("route update digest = %s, error = %v", updateDigest, err)
	}
}

package authorization

import (
	"crypto/sha256"
	"slices"
	"strconv"
	"testing"
)

func TestValidateTarget(t *testing.T) {
	for _, target := range []string{"http://127.0.0.1:3000", "http://[::1]:3000", "https://127.0.0.1:3000", "http://app:3000", "https://api.example:443"} {
		if err := ValidateTarget(target); err != nil {
			t.Fatalf("target %q: %v", target, err)
		}
	}
	for _, target := range []string{
		"http://localhost:3000", "http://APP:3000", "https://api.example:0443",
		"http://127.0.0.1", "http://127.0.0.1:3000/", "http://user@127.0.0.1:3000",
		"http://127.0.0.1:03000", "http://127.0.0.1:99999", "http://[0:0:0:0:0:0:0:1]:3000",
	} {
		if err := ValidateTarget(target); err == nil {
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
	request := []byte(`{"allowed_ip_prefixes":["192.0.2.0/24","2001:db8::/64"],"canonical_hostname":"route.example","domain_id":"domain_1","membership_id":"membership_1","public_url_scope":"member","target":"http://127.0.0.1:3000","team_id":"team_1"}`)
	wantRequestDigest := Digest(sha256.Sum256(request))
	requestDigest, err := CanonicalRequestHash(OperationRequest{
		Operation: OperationPublicURLCreate, TeamID: "team_1", MembershipID: "membership_1", DomainID: "domain_1",
		CanonicalHostname: "route.example", PublicURLScope: "member", Target: "http://127.0.0.1:3000",
		AllowedIPPrefixes: prefixes,
	})
	if err != nil || requestDigest != wantRequestDigest {
		t.Fatalf("request digest = %s, want %s, error = %v", requestDigest, wantRequestDigest, err)
	}
	ephemeralDigest, err := CanonicalRequestHash(OperationRequest{
		Operation: OperationPublicURLCreate, TeamID: "team_1", MembershipID: "membership_1", DomainID: "domain_1",
		CanonicalHostname: "route.example", PublicURLScope: "member", Target: "http://127.0.0.1:3000",
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
	large := make([]string, 256)
	for index := range large {
		large[index] = "192.0.2." + strconv.Itoa(index)
	}
	if prefixes, err := CanonicalizeIPPrefixes(large); err != nil || len(prefixes) != len(large) {
		t.Fatalf("large prefix policy = %d entries, error = %v", len(prefixes), err)
	}
	plan := CertificatePlan{CacheKey: "route.example", Scope: "route.example", Identifiers: []string{"route.example"}, ChallengeMethod: "tls-alpn-01"}
	sessionJSON := []byte(`{"allowed_ip_prefixes":["192.0.2.0/24","2001:db8::/64"],"canonical_hostname":"route.example","certificate_plan":{"cache_key":"route.example","scope":"route.example","identifiers":["route.example"],"challenge_method":"tls-alpn-01"},"domain_id":"domain_1","ephemeral":true,"membership_id":"membership_1","policy_revision":3,"public_url_id":"public_url_1","public_url_scope":"member","publish_run_number":4,"target":"http://127.0.0.1:3000","team_id":"team_1"}`)
	sessionRequest := OperationRequest{
		Operation: OperationPublishRunCreate, TeamID: "team_1", MembershipID: "membership_1", DomainID: "domain_1",
		CanonicalHostname: "route.example", PublicURLScope: "member", PublicURLID: "public_url_1", PublishRunNumber: 4,
		PolicyRevision: 3, Target: "http://127.0.0.1:3000", AllowedIPPrefixes: prefixes, Ephemeral: true,
		CertificatePlan: &plan,
	}
	sessionDigest, err := CanonicalRequestHash(sessionRequest)
	if err != nil || sessionDigest != Digest(sha256.Sum256(sessionJSON)) {
		t.Fatalf("session digest = %s, error = %v", sessionDigest, err)
	}
	sessionRequest.AllowedIPPrefixes = nil
	if _, err := CanonicalRequestHash(sessionRequest); err == nil {
		t.Fatal("publish-run request without an IP policy was accepted")
	}
	updateJSON := []byte(`{"allowed_ip_prefixes":["192.0.2.0/24","2001:db8::/64"],"canonical_hostname":"route.example","domain_id":"domain_1","ephemeral":true,"membership_id":"membership_1","policy_revision":3,"public_url_id":"public_url_1","public_url_mutation_revision":4,"public_url_scope":"member","target":"http://127.0.0.1:4000","team_id":"team_1"}`)
	updateDigest, err := CanonicalRequestHash(OperationRequest{
		Operation: OperationPublicURLUpdate, TeamID: "team_1", MembershipID: "membership_1", DomainID: "domain_1",
		CanonicalHostname: "route.example", PublicURLScope: "member", PublicURLID: "public_url_1", PublicURLMutationRevision: 4, PolicyRevision: 3,
		Target: "http://127.0.0.1:4000", AllowedIPPrefixes: prefixes, Ephemeral: true,
	})
	if err != nil || updateDigest != Digest(sha256.Sum256(updateJSON)) {
		t.Fatalf("route update digest = %s, error = %v", updateDigest, err)
	}
}

func TestCanonicalRequestRejectsUnknownPublicURLScope(t *testing.T) {
	for _, operation := range []Operation{OperationPublicURLCreate, OperationPublicURLUpdate, OperationPublishRunCreate} {
		t.Run(string(operation), func(t *testing.T) {
			request := OperationRequest{
				Operation: operation, TeamID: "team_1", DomainID: "domain_1", CanonicalHostname: "route.example",
				PublicURLScope: PublicURLScope("unknown"), PublicURLID: "public_url_1",
				PolicyRevision: 1, PublicURLMutationRevision: 1, PublishRunNumber: 1,
				Target: "http://127.0.0.1:3000", AllowedIPPrefixes: []string{},
				CertificatePlan: &CertificatePlan{CacheKey: "route.example", Scope: "route.example", Identifiers: []string{"route.example"}, ChallengeMethod: "tls-alpn-01"},
			}
			if _, err := CanonicalRequestHash(request); err == nil {
				t.Fatal("unknown public URL scope was hashed")
			}
		})
	}
}

package authorization

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"os"
	"slices"
	"strconv"
	"testing"
	"time"
)

func TestVerifierStrictlyBindsTeamRouteSessionAuthorization(t *testing.T) {
	now := time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)
	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	requestDigest := Digest(sha256.Sum256([]byte("request")))
	plan := CertificatePlan{
		CacheKey: "member.example", Scope: "member.example", Identifiers: []string{"member.example", "*.member.example"},
		ChallengeMethod: "dns-01",
	}
	payload := authorizationPayload{
		Version: 1, KeyID: "key-1", Algorithm: Algorithm, Operation: OperationRouteSessionCreate,
		Issuer: "https://authority.example", Receiver: "https://server.example",
		AuthorizationID: "authorization_0123456789abcdef0123456789abcdef",
		TeamID:          "team_0123456789abcdef0123456789abcdef", IdentityID: "identity_0123456789abcdef0123456789abcdef",
		MembershipID: stringPointer("membership_0123456789abcdef0123456789abcdef"),
		DomainID:     "domain_0123456789abcdef0123456789abcdef", CanonicalHostname: "api.member.example", RouteScope: "member",
		RouteID: stringPointer("route_0123456789abcdef0123456789abcdef"), RouteVersion: uint64Pointer(2),
		TeamPolicyRevision: 3, CertificatePlan: &plan, IssuedAt: now.Add(-time.Minute), ExpiresAt: now.Add(10 * time.Minute),
		RetryID: "retry_0123456789abcdef0123456789abcdef", RequestDigest: requestDigest.String(),
	}
	verifier, err := NewVerifier(Config{
		Issuer: payload.Issuer, Receiver: payload.Receiver, KeyID: payload.KeyID,
		PublicKey: publicKey, Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	token := signAuthorization(t, privateKey, map[string]any{"alg": Algorithm, "kid": payload.KeyID, "typ": Type}, payload)
	expected := Expected{
		Operation: payload.Operation, TeamID: payload.TeamID, MembershipID: *payload.MembershipID,
		DomainID: payload.DomainID, CanonicalHostname: payload.CanonicalHostname, RouteScope: payload.RouteScope,
		RouteID: *payload.RouteID, RouteVersion: *payload.RouteVersion, PolicyRevision: payload.TeamPolicyRevision,
		CertificatePlan: &plan, RequestDigest: requestDigest,
	}
	claims, err := verifier.Verify(token, expected)
	if err != nil {
		t.Fatal(err)
	}
	if claims.AuthorizationID != payload.AuthorizationID || claims.PolicyRevision != 3 || claims.TeamID != payload.TeamID {
		t.Fatalf("claims = %#v", claims)
	}
	expected.PolicyRevision++
	if _, err := verifier.Verify(token, expected); err == nil {
		t.Fatal("policy revision mismatch was accepted")
	}

	for name, header := range map[string]map[string]any{
		"wrong algorithm": {"alg": "ES256", "kid": payload.KeyID, "typ": Type},
		"wrong key":       {"alg": Algorithm, "kid": "other", "typ": Type},
		"missing type":    {"alg": Algorithm, "kid": payload.KeyID},
		"unknown field":   {"alg": Algorithm, "kid": payload.KeyID, "typ": Type, "extra": true},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := verifier.Authenticate(signAuthorization(t, privateKey, header, payload)); err == nil {
				t.Fatal("invalid header was accepted")
			}
		})
	}
}

func TestVerifierAuthenticatesUserAssertion(t *testing.T) {
	now := time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)
	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := NewVerifier(Config{
		Issuer: "https://authority.example", Receiver: "https://control.example", KeyID: "key-1",
		PublicKey: publicKey, Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	payload := userAssertionPayload{
		Version: 1, KeyID: "key-1", Algorithm: Algorithm,
		Issuer: "https://authority.example", Receiver: "https://control.example",
		IdentityID: "identity_0123456789abcdef0123456789abcdef", Administrator: true,
		Memberships: []UserAssertionMembership{{
			TeamID: "team_0123456789abcdef0123456789abcdef", MembershipID: "membership_0123456789abcdef0123456789abcdef",
			Role: "owner", PolicyRevision: 3,
		}},
		IssuedAt: now.Add(-time.Minute), ExpiresAt: now.Add(10 * time.Minute),
	}
	token := signToken(t, privateKey, UserAssertionType, payload)
	assertion, err := verifier.AuthenticateUserAssertion(token)
	if err != nil {
		t.Fatal(err)
	}
	membership, found := assertion.Membership(payload.Memberships[0].TeamID)
	if assertion.IdentityID != payload.IdentityID || !assertion.Administrator || !found || membership != payload.Memberships[0] {
		t.Fatalf("assertion = %#v", assertion)
	}
	if _, err := verifier.Authenticate(token); err == nil {
		t.Fatal("user assertion was accepted as an operation authorization")
	}
	payload.Memberships = append(payload.Memberships, payload.Memberships[0])
	if _, err := verifier.AuthenticateUserAssertion(signToken(t, privateKey, UserAssertionType, payload)); err == nil {
		t.Fatal("duplicate user assertion membership was accepted")
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

func TestVerifierAcceptsHostedConformanceFixture(t *testing.T) {
	data, err := os.ReadFile("../../api/fixtures/authority/v1/hosted-authorization.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		PublicKey     string `json:"public_key"`
		Authorization string `json:"authorization"`
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	publicKey, err := base64.RawURLEncoding.DecodeString(fixture.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	requestDigest, _ := ParseDigest("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
	ipPolicyDigest, _ := ParseDigest("BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA")
	plan := CertificatePlan{
		CacheKey: "demo.tnl.dev", Scope: "demo.tnl.dev", Identifiers: []string{"demo.tnl.dev", "*.demo.tnl.dev"},
		ChallengeMethod: "dns-01",
	}
	verifier, err := NewVerifier(Config{
		Issuer: "https://account.tnl.dev", Receiver: "https://control.tnl.dev", KeyID: "hosted-conformance-2026-09",
		PublicKey: publicKey, Now: func() time.Time { return time.Date(2026, 9, 2, 12, 30, 0, 0, time.UTC) },
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = verifier.Verify(fixture.Authorization, Expected{
		Operation: OperationRouteSessionCreate, TeamID: "team_0123456789abcdef0123456789abcdef",
		MembershipID: "membership_0123456789abcdef0123456789abcdef", DomainID: "domain_0123456789abcdef0123456789abcdef",
		CanonicalHostname: "api.demo.tnl.dev", RouteScope: "member", RouteID: "route_0123456789abcdef0123456789abcdef",
		RouteVersion: 7, PolicyRevision: 3, CertificatePlan: &plan, RequestDigest: requestDigest, IPPolicyDigest: &ipPolicyDigest,
	})
	if err != nil {
		t.Fatal(err)
	}
}

type authorizationPayload struct {
	Version            uint64           `json:"version"`
	KeyID              string           `json:"kid"`
	Algorithm          string           `json:"alg"`
	Operation          Operation        `json:"operation"`
	Issuer             string           `json:"issuer"`
	Receiver           string           `json:"receiver"`
	AuthorizationID    string           `json:"authorization_id"`
	TeamID             string           `json:"team_id"`
	IdentityID         string           `json:"identity_id"`
	MembershipID       *string          `json:"membership_id,omitempty"`
	DomainID           string           `json:"domain_id"`
	CanonicalHostname  string           `json:"canonical_hostname"`
	RouteScope         string           `json:"route_scope"`
	RouteID            *string          `json:"route_id,omitempty"`
	RouteVersion       *uint64          `json:"route_version,omitempty"`
	TeamPolicyRevision uint64           `json:"team_policy_revision"`
	CertificatePlan    *CertificatePlan `json:"certificate_plan,omitempty"`
	IssuedAt           time.Time        `json:"issued_at"`
	ExpiresAt          time.Time        `json:"expires_at"`
	RetryID            string           `json:"retry_id"`
	RequestDigest      string           `json:"request_digest"`
	IPPolicyDigest     *string          `json:"ip_policy_digest,omitempty"`
}

type userAssertionPayload struct {
	Version       uint64                    `json:"version"`
	KeyID         string                    `json:"kid"`
	Algorithm     string                    `json:"alg"`
	Issuer        string                    `json:"issuer"`
	Receiver      string                    `json:"receiver"`
	IdentityID    string                    `json:"identity_id"`
	Administrator bool                      `json:"administrator"`
	Memberships   []UserAssertionMembership `json:"memberships"`
	IssuedAt      time.Time                 `json:"issued_at"`
	ExpiresAt     time.Time                 `json:"expires_at"`
}

func signAuthorization(t *testing.T, privateKey ed25519.PrivateKey, header map[string]any, payload authorizationPayload) string {
	t.Helper()
	headerJSON, err := json.Marshal(header)
	if err != nil {
		t.Fatal(err)
	}
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	encodedHeader := base64.RawURLEncoding.EncodeToString(headerJSON)
	encodedPayload := base64.RawURLEncoding.EncodeToString(payloadJSON)
	signed := encodedHeader + "." + encodedPayload
	return signed + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(privateKey, []byte(signed)))
}

func signToken(t *testing.T, privateKey ed25519.PrivateKey, tokenType string, payload any) string {
	t.Helper()
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	headerJSON, err := json.Marshal(map[string]any{"alg": Algorithm, "kid": "key-1", "typ": tokenType})
	if err != nil {
		t.Fatal(err)
	}
	encodedHeader := base64.RawURLEncoding.EncodeToString(headerJSON)
	encodedPayload := base64.RawURLEncoding.EncodeToString(payloadJSON)
	signed := encodedHeader + "." + encodedPayload
	return signed + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(privateKey, []byte(signed)))
}

func stringPointer(value string) *string { return &value }
func uint64Pointer(value uint64) *uint64 { return &value }

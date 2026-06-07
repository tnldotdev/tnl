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

func TestVerifierStrictlyBindsAuthorization(t *testing.T) {
	now := time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)
	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	requestHash := Digest(sha256.Sum256([]byte("request")))
	ipHash := Digest(sha256.Sum256([]byte("policy")))
	payload := authorizationPayload{
		Version: 1, KeyID: "key-1", Algorithm: Algorithm, Operation: OperationRouteSessionCreate,
		Issuer: "https://authority.example", Receiver: "https://server.example",
		AuthorizationID: "authorization_0123456789abcdef0123456789abcdef",
		Hostname:        "route.example", RouteID: stringPointer("route_0123456789abcdef0123456789abcdef"),
		RouteVersion: uint64Pointer(2), Revision: 1, IssuedAt: now.Add(-time.Minute),
		ExpiresAt: now.Add(10 * time.Minute), RetryID: "retry_0123456789abcdef0123456789abcdef",
		CanonicalRequestHash: requestHash.String(), IPPolicyHash: stringPointer(ipHash.String()),
	}
	verifier, err := NewVerifier(Config{
		Issuer: payload.Issuer, Receiver: payload.Receiver, KeyID: payload.KeyID,
		PublicKey: publicKey, Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	token := signAuthorization(t, privateKey, map[string]any{
		"alg": Algorithm, "kid": payload.KeyID, "typ": Type,
	}, payload)
	claims, err := verifier.Verify(token, Expected{
		Operation: payload.Operation, Hostname: payload.Hostname,
		RouteID: *payload.RouteID, RouteVersion: *payload.RouteVersion,
		CanonicalRequestHash: requestHash, IPPolicyHash: &ipHash,
	})
	if err != nil {
		t.Fatal(err)
	}
	if claims.AuthorizationID != payload.AuthorizationID || claims.RetryID != payload.RetryID || claims.Revision != 1 {
		t.Fatalf("claims = %#v", claims)
	}

	for name, header := range map[string]map[string]any{
		"wrong algorithm": {"alg": "ES256", "kid": payload.KeyID, "typ": Type},
		"wrong key":       {"alg": Algorithm, "kid": "other", "typ": Type},
		"missing type":    {"alg": Algorithm, "kid": payload.KeyID},
		"wrong type":      {"alg": Algorithm, "kid": payload.KeyID, "typ": "JWS"},
		"unknown field":   {"alg": Algorithm, "kid": payload.KeyID, "typ": Type, "extra": true},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := verifier.Authenticate(signAuthorization(t, privateKey, header, payload)); err == nil {
				t.Fatal("invalid header was accepted")
			}
		})
	}

	encodedPayload, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	duplicate := append([]byte(`{"version":1,`), encodedPayload[1:]...)
	if _, err := verifier.Authenticate(signEncodedAuthorization(t, privateKey, map[string]any{
		"alg": Algorithm, "kid": payload.KeyID, "typ": Type,
	}, duplicate)); err == nil {
		t.Fatal("duplicate claim was accepted")
	}
}

func TestVerifierAcceptsHostedConformanceFixture(t *testing.T) {
	data, err := os.ReadFile("../../api/fixtures/authorization-authority/v1/hosted-authorization.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		PublicKey     string          `json:"public_key"`
		Authorization string          `json:"authorization"`
		Claims        json.RawMessage `json:"claims"`
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	publicKey, err := base64.RawURLEncoding.DecodeString(fixture.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 9, 2, 12, 30, 0, 0, time.UTC)
	verifier, err := NewVerifier(Config{
		Issuer: "https://account.tnl.dev", Receiver: "https://control.tnl.dev",
		KeyID: "hosted-conformance-2026-09", PublicKey: publicKey, Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	requestHash, err := ParseDigest("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
	if err != nil {
		t.Fatal(err)
	}
	ipPolicyHash, err := ParseDigest("BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA")
	if err != nil {
		t.Fatal(err)
	}
	claims, err := verifier.Verify(fixture.Authorization, Expected{
		Operation: OperationRenew, Hostname: "demo.tnl.dev",
		RouteID: "route_0123456789abcdef0123456789abcdef", RouteVersion: 7,
		CanonicalRequestHash: requestHash, IPPolicyHash: &ipPolicyHash,
	})
	if err != nil {
		t.Fatal(err)
	}
	if claims.AuthorizationID != "authorization_0123456789abcdef0123456789abcdef" ||
		claims.RetryID != "retry_fedcba9876543210fedcba9876543210" || claims.Revision != 3 {
		t.Fatalf("claims = %#v", claims)
	}
}

func TestCanonicalRequestAndIPPolicyHashes(t *testing.T) {
	prefixes, err := CanonicalizeIPPrefixes([]string{"2001:db8::1/64", "192.0.2.9/24"})
	if err != nil {
		t.Fatal(err)
	}
	if len(prefixes) != 2 || prefixes[0] != "192.0.2.0/24" || prefixes[1] != "2001:db8::/64" {
		t.Fatalf("prefixes = %#v", prefixes)
	}
	request := []byte(`{"allowed_ip_prefixes":["192.0.2.0/24","2001:db8::/64"],"hostname":"route.example","local_target":"http://127.0.0.1:3000","route_token":"token"}`)
	wantRequestHash := Digest(sha256.Sum256(request))
	requestHash, err := CanonicalRequestHash(OperationRequest{
		Operation: OperationRouteCreate, Hostname: "route.example", LocalTarget: "http://127.0.0.1:3000",
		RouteToken: "token", AllowedIPPrefixes: prefixes,
	})
	if err != nil {
		t.Fatal(err)
	}
	if requestHash != wantRequestHash {
		t.Fatalf("request hash = %s, want %s", requestHash, wantRequestHash)
	}
	policyHash, err := IPPolicyHash(prefixes)
	if err != nil {
		t.Fatal(err)
	}
	wantPolicyHash := Digest(sha256.Sum256([]byte(`["192.0.2.0/24","2001:db8::/64"]`)))
	if policyHash == nil || *policyHash != wantPolicyHash {
		t.Fatalf("policy hash = %v, want %s", policyHash, wantPolicyHash)
	}
	if none, err := IPPolicyHash(nil); err != nil || none != nil {
		t.Fatalf("nil policy hash = %v, %v", none, err)
	}
	empty, err := IPPolicyHash([]string{})
	if err != nil || empty == nil || *empty == wantPolicyHash {
		t.Fatalf("empty policy hash = %v, %v", empty, err)
	}
	deduplicated, err := CanonicalizeIPPrefixes([]string{"192.0.2.1/24", "192.0.2.0/24"})
	if err != nil || !slices.Equal(deduplicated, []string{"192.0.2.0/24"}) {
		t.Fatalf("deduplicated prefixes = %#v, %v", deduplicated, err)
	}
	addresses, err := CanonicalizeIPPrefixes([]string{"192.0.2.1", "::ffff:192.0.2.1", "2001:db8::1"})
	if err != nil || !slices.Equal(addresses, []string{"192.0.2.1/32", "2001:db8::1/128"}) {
		t.Fatalf("address prefixes = %#v, %v", addresses, err)
	}
	mapped, err := CanonicalizeIPPrefixes([]string{"::ffff:192.0.2.42/120"})
	if err != nil || !slices.Equal(mapped, []string{"192.0.2.0/24"}) {
		t.Fatalf("mapped prefix = %#v, %v", mapped, err)
	}
	for _, invalid := range []string{"::ffff:192.0.2.1/95", "fe80::1%en0"} {
		if _, err := CanonicalizeIPPrefixes([]string{invalid}); err == nil {
			t.Errorf("invalid prefix %q was accepted", invalid)
		}
	}
	tooMany := make([]string, MaxIPPrefixes+1)
	for index := range tooMany {
		tooMany[index] = "192.0.2." + strconv.Itoa(index)
	}
	if _, err := CanonicalizeIPPrefixes(tooMany); err == nil {
		t.Fatal("oversized prefix policy was accepted")
	}
}

type authorizationPayload struct {
	Version              uint64    `json:"version"`
	KeyID                string    `json:"kid"`
	Algorithm            string    `json:"alg"`
	Operation            Operation `json:"operation"`
	Issuer               string    `json:"issuer"`
	Receiver             string    `json:"receiver"`
	AuthorizationID      string    `json:"authorization_id"`
	Hostname             string    `json:"hostname"`
	RouteID              *string   `json:"route_id,omitempty"`
	RouteVersion         *uint64   `json:"route_version,omitempty"`
	Revision             uint64    `json:"revision"`
	IssuedAt             time.Time `json:"issued_at"`
	ExpiresAt            time.Time `json:"expires_at"`
	RetryID              string    `json:"retry_id"`
	CanonicalRequestHash string    `json:"canonical_request_hash"`
	IPPolicyHash         *string   `json:"ip_policy_hash,omitempty"`
}

func signAuthorization(t *testing.T, privateKey ed25519.PrivateKey, header map[string]any, payload any) string {
	t.Helper()
	encodedPayload, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	return signEncodedAuthorization(t, privateKey, header, encodedPayload)
}

func signEncodedAuthorization(t *testing.T, privateKey ed25519.PrivateKey, header map[string]any, payload []byte) string {
	t.Helper()
	encodedHeader, err := json.Marshal(header)
	if err != nil {
		t.Fatal(err)
	}
	signingInput := base64.RawURLEncoding.EncodeToString(encodedHeader) + "." + base64.RawURLEncoding.EncodeToString(payload)
	signature := ed25519.Sign(privateKey, []byte(signingInput))
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func stringPointer(value string) *string { return &value }

func uint64Pointer(value uint64) *uint64 { return &value }

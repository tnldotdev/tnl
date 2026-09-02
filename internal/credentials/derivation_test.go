package credentials

import "testing"

func TestDeterministicSessionDerivation(t *testing.T) {
	routeToken, _, _, err := NewRouteToken()
	if err != nil {
		t.Fatal(err)
	}
	first, firstID, firstHash, err := DeriveSessionToken(routeToken, "retry-1")
	if err != nil {
		t.Fatal(err)
	}
	retry, retryID, retryHash, err := DeriveSessionToken(routeToken, "retry-1")
	if err != nil {
		t.Fatal(err)
	}
	other, _, _, err := DeriveSessionToken(routeToken, "retry-2")
	if err != nil {
		t.Fatal(err)
	}
	if first != retry || firstID != retryID || firstHash != retryHash || first == other {
		t.Fatalf("derived credentials are not retry-stable and context-bound")
	}
	parsedID, parsedHash, err := ParseSessionToken(first)
	if err != nil || parsedID != firstID || parsedHash != firstHash {
		t.Fatalf("parse derived session token = %q, %x, %v", parsedID, parsedHash, err)
	}
	firstMaterial, err := DeriveSessionKeyMaterial(first)
	if err != nil {
		t.Fatal(err)
	}
	retryMaterial, err := DeriveSessionKeyMaterial(retry)
	if err != nil || firstMaterial != retryMaterial {
		t.Fatalf("derived key material differs: %v", err)
	}
}

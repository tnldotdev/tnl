package credentials

import (
	"bytes"
	"testing"
)

func TestDeterministicSessionDerivation(t *testing.T) {
	retrySecret := bytes.Repeat([]byte{7}, 32)
	first, firstID, firstHash, err := DeriveSessionToken(retrySecret, "retry-1")
	if err != nil {
		t.Fatal(err)
	}
	retry, retryID, retryHash, err := DeriveSessionToken(retrySecret, "retry-1")
	if err != nil {
		t.Fatal(err)
	}
	other, _, _, err := DeriveSessionToken(retrySecret, "retry-2")
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

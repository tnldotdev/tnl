package credentials

import (
	"bytes"
	"testing"
)

func TestDeterministicRouteSessionDerivation(t *testing.T) {
	retrySecret := bytes.Repeat([]byte{7}, 32)
	first, firstID, firstHash, err := DeriveRouteSessionToken(retrySecret, "retry-1")
	if err != nil {
		t.Fatal(err)
	}
	retry, retryID, retryHash, err := DeriveRouteSessionToken(retrySecret, "retry-1")
	if err != nil {
		t.Fatal(err)
	}
	other, _, _, err := DeriveRouteSessionToken(retrySecret, "retry-2")
	if err != nil {
		t.Fatal(err)
	}
	if first != retry || firstID != retryID || firstHash != retryHash || first == other {
		t.Fatalf("derived credentials are not retry-stable and context-bound")
	}
	parsedID, parsedHash, err := ParseRouteSessionToken(first)
	if err != nil || parsedID != firstID || parsedHash != firstHash {
		t.Fatalf("parse derived route session token = %q, %x, %v", parsedID, parsedHash, err)
	}
}

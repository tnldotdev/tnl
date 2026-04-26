package credentials

import (
	"errors"
	"strings"
	"testing"
)

func TestAccessTokenRoundTrip(t *testing.T) {
	token, lookupID, hash, err := NewAccessToken()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(token, accessPrefix) {
		t.Fatalf("token = %q, want access prefix", token)
	}

	parsedID, parsedHash, err := ParseAccessToken(token)
	if err != nil {
		t.Fatal(err)
	}
	if parsedID != lookupID {
		t.Fatalf("lookup ID = %q, want %q", parsedID, lookupID)
	}
	if parsedHash != hash {
		t.Fatal("parsed hash differs from generated hash")
	}
	if !SecretHashMatches(hash[:], parsedHash) {
		t.Fatal("matching hash rejected")
	}

	otherHash := hash
	otherHash[0] ^= 1
	if SecretHashMatches(hash[:], otherHash) {
		t.Fatal("different hash accepted")
	}
}

func TestParseAccessTokenRejectsMalformedAndWrongClass(t *testing.T) {
	token, _, _, err := NewAccessToken()
	if err != nil {
		t.Fatal(err)
	}

	for _, candidate := range []string{
		"",
		strings.Replace(token, accessPrefix, "tnl_route_", 1),
		accessPrefix,
		accessPrefix + "AA.AA",
		token + ".extra",
		token + "=",
	} {
		if _, _, err := ParseAccessToken(candidate); !errors.Is(err, ErrInvalidAccessToken) {
			t.Errorf("ParseAccessToken(%q) error = %v", candidate, err)
		}
	}
}

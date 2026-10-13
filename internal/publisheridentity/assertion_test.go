package publisheridentity

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestClientAssertionBindsClientKeyAudienceAndTime(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	const audience = "https://control.example/v1/publisher/token"
	token, err := Sign("pub_123", "key_123", audience, private, now)
	if err != nil {
		t.Fatal(err)
	}
	keyID, err := KeyID(token)
	if err != nil || keyID != "key_123" {
		t.Fatalf("key ID = %q, error = %v", keyID, err)
	}
	assertion, err := Verify(token, "pub_123", audience, keyID, public, now)
	if err != nil || assertion.ID == "" || assertion.KeyID != keyID || !assertion.Until.Equal(now.Add(time.Minute)) {
		t.Fatalf("assertion = %+v, error = %v", assertion, err)
	}
	other, err := Sign("pub_123", "key_123", audience, private, now)
	if err != nil || other == token {
		t.Fatal("assertion ID repeated")
	}
	wrongKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for _, check := range []struct {
		name, client, audience, key, token string
		public                             ed25519.PublicKey
		at                                 time.Time
	}{
		{"wrong client", "pub_other", audience, keyID, token, public, now},
		{"wrong audience", "pub_123", "https://other.example/v1/publisher/token", keyID, token, public, now},
		{"wrong key", "pub_123", audience, keyID, token, wrongKey, now},
		{"wrong key ID", "pub_123", audience, "key_other", token, public, now},
		{"expired", "pub_123", audience, keyID, token, public, now.Add(61 * time.Second)},
		{"tampered", "pub_123", audience, keyID, token + "a", public, now},
		{"oversized", "pub_123", audience, keyID, strings.Repeat("a", maxJWTBytes+1), public, now},
	} {
		t.Run(check.name, func(t *testing.T) {
			if _, err := Verify(check.token, check.client, check.audience, check.key, check.public, check.at); !errors.Is(err, ErrAssertion) {
				t.Fatalf("verification error = %v", err)
			}
		})
	}
}

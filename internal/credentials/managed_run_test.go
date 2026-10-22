package credentials

import (
	"crypto/sha256"
	"encoding/base64"
	"strings"
	"testing"
)

func TestManagedRunTokenCanonicalUnprefixedEncoding(t *testing.T) {
	secret := make([]byte, 32)
	for i := range secret {
		secret[i] = byte(i)
	}
	encoded := base64.RawURLEncoding.EncodeToString(secret)
	want := sha256.Sum256(secret)
	if digest, err := ParseManagedRunToken(ManagedRunToken(encoded)); err != nil || digest != want {
		t.Fatal("stored managed secret digest changed", digest, err)
	}
	for _, invalid := range []string{"", encoded + "=", encoded[:42], encoded + "A", "tnl_session_" + encoded, encoded[:42] + "9", strings.Repeat("!", 43)} {
		if digest, err := ParseManagedRunToken(ManagedRunToken(invalid)); err == nil || digest != (SecretHash{}) {
			t.Fatal("noncanonical managed token was accepted")
		}
	}
	token, digest, err := NewManagedRunToken()
	if err != nil {
		t.Fatal(err)
	}
	if parsed, err := ParseManagedRunToken(token); err != nil || parsed != digest {
		t.Fatal("new managed token did not round trip", err)
	}
	if _, _, err := ParsePublishRunToken(PublishRunToken(token)); err == nil {
		t.Fatal("managed token parsed as public run authority")
	}
}

func TestAssignmentSeedPreservesConnectionDerivation(t *testing.T) {
	const encoded = "tnl_session_AAECAwQFBgcICQoLDA0ODw.AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"
	credential, digest, err := DeriveAssignmentCredential(AssignmentSeed(encoded), "fixture/context")
	if err != nil || credential != "tnl_connection_6AKcUBa6UAEygj39eQnfmw.iMFSeiBcJTC0Khu3Kou81BCT9LYvxFRr9OlKYEZYrM8" {
		t.Fatal("assignment derivation bytes changed", err)
	}
	if parsed, err := ParsePublisherConnectionCredential(credential); err != nil || parsed != digest {
		t.Fatal("assignment credential digest changed", err)
	}
	if _, err := ParseManagedRunToken(ManagedRunToken(encoded)); err == nil {
		t.Fatal("assignment seed parsed as managed run authority")
	}
	seed, err := NewAssignmentSeed()
	if err != nil || ParseAssignmentSeed(seed) != nil {
		t.Fatal("new assignment seed did not round trip", err)
	}
}

package credentials

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
)

func TestServiceRunTokenCanonicalUnprefixedEncoding(t *testing.T) {
	secret := make([]byte, 32)
	for i := range secret {
		secret[i] = byte(i)
	}
	encoded := base64.RawURLEncoding.EncodeToString(secret)
	const tokenVector = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"
	const hashVector = "630dcd2966c4336691125448bbb25b4ff412a49c732db2c8abc1b8581bd710dd"
	if encoded != tokenVector {
		t.Fatal("service run encoding changed", encoded)
	}
	if digest, err := ParseServiceRunToken(ServiceRunToken(tokenVector)); err != nil || hex.EncodeToString(digest[:]) != hashVector {
		t.Fatal("stored service run secret digest changed", digest, err)
	}
	for _, invalid := range []string{"", encoded + "=", encoded[:42], encoded + "A", "tnl_publish_run_" + encoded, encoded[:42] + "9", strings.Repeat("!", 43)} {
		if digest, err := ParseServiceRunToken(ServiceRunToken(invalid)); !errors.Is(err, ErrInvalidServiceRunToken) || digest != (SecretHash{}) {
			t.Fatal("noncanonical service run token was accepted")
		}
	}
	token, digest, err := NewServiceRunToken()
	if err != nil {
		t.Fatal(err)
	}
	if parsed, err := ParseServiceRunToken(token); err != nil || parsed != digest {
		t.Fatal("new service run token did not round trip", err)
	}
}

func TestAssignmentSeedPreservesConnectionDerivation(t *testing.T) {
	const encoded = "tnl_assignment_seed_AAECAwQFBgcICQoLDA0ODw.AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"
	credential, digest, err := DeriveAssignmentCredential(AssignmentSeed(encoded), "fixture/context")
	if err != nil || credential != "tnl_connection_6AKcUBa6UAEygj39eQnfmw.iMFSeiBcJTC0Khu3Kou81BCT9LYvxFRr9OlKYEZYrM8" {
		t.Fatal("assignment derivation bytes changed", err)
	}
	if parsed, err := ParsePublisherConnectionCredential(credential); err != nil || parsed != digest {
		t.Fatal("assignment credential digest changed", err)
	}
	if _, err := ParseServiceRunToken(ServiceRunToken(encoded)); !errors.Is(err, ErrInvalidServiceRunToken) {
		t.Fatal("assignment seed parsed as service run authority")
	}
	seed, err := NewAssignmentSeed()
	if err != nil || ParseAssignmentSeed(seed) != nil || !strings.HasPrefix(seed.String(), "tnl_assignment_seed_") {
		t.Fatal("new assignment seed did not round trip", err)
	}
}

func TestAssignmentSeedRejectsMalformedAndWrongClass(t *testing.T) {
	const lookup = "AAECAwQFBgcICQoLDA0ODw"
	const secret = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"
	const encoded = "tnl_assignment_seed_" + lookup + "." + secret
	for name, invalid := range map[string]string{
		"empty":                "",
		"missing body":         "tnl_assignment_seed_",
		"missing secret":       "tnl_assignment_seed_" + lookup,
		"short lookup":         "tnl_assignment_seed_AA." + secret,
		"padded lookup":        "tnl_assignment_seed_" + lookup + "==." + secret,
		"noncanonical lookup":  "tnl_assignment_seed_" + lookup[:21] + "x." + secret,
		"short secret":         "tnl_assignment_seed_" + lookup + "." + secret[:42],
		"long secret":          encoded + "AA",
		"padded secret":        encoded + "=",
		"noncanonical secret":  encoded[:len(encoded)-1] + "9",
		"invalid alphabet":     "tnl_assignment_seed_" + lookup + "." + strings.Repeat("!", 43),
		"extra component":      encoded + ".extra",
		"old publication":      "tnl_publish_run_" + lookup + "." + secret,
		"service run":          secret,
		"publisher connection": "tnl_connection_" + lookup + "." + secret,
		"access":               "tnl_access_" + lookup + "." + secret,
	} {
		t.Run(name, func(t *testing.T) {
			seed := AssignmentSeed(invalid)
			if err := ParseAssignmentSeed(seed); !errors.Is(err, ErrInvalidAssignmentSeed) {
				t.Fatalf("invalid assignment seed parsed: %v", err)
			}
			if token, hash, err := DeriveAssignmentCredential(seed, "fixture/context"); !errors.Is(err, ErrInvalidAssignmentSeed) || token != "" || hash != (SecretHash{}) {
				t.Fatalf("invalid assignment seed derived a credential: %q, %x, %v", token, hash, err)
			}
		})
	}
}

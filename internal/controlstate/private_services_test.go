package controlstate

import (
	"bytes"
	"errors"
	"testing"
)

func TestPrivateServiceSecretsRequireCanonicalRandomBytes(t *testing.T) {
	first, digest, err := privateSecret()
	if err != nil {
		t.Fatal(err)
	}
	second, other, err := privateSecret()
	if err != nil {
		t.Fatal(err)
	}
	if first == second || bytes.Equal(digest, other) || len(digest) != 32 {
		t.Fatal("private credentials were reused")
	}
	parsed, err := privateSecretDigest(first)
	if err != nil || !bytes.Equal(parsed, digest) {
		t.Fatalf("valid credential: %v", err)
	}
	for _, invalid := range []string{"", first + "=", first[:len(first)-1], first[:2] + "!" + first[3:]} {
		if _, err := privateSecretDigest(invalid); !errors.Is(err, ErrPrivateServiceAccess) {
			t.Fatalf("accepted noncanonical credential %q: %v", invalid, err)
		}
	}
}

package opaqueid

import (
	"strings"
	"testing"
)

func TestNewAndValid(t *testing.T) {
	id, err := New("public_url_")
	if err != nil {
		t.Fatal(err)
	}
	if !Valid(id, "public_url_") {
		t.Fatalf("generated ID is invalid: %q", id)
	}
	for _, invalid := range []string{
		"public_url_",
		"public_url_" + strings.Repeat("0", 31),
		"public_url_" + strings.Repeat("0", 31) + "A",
		"session_" + strings.Repeat("0", 32),
	} {
		if Valid(invalid, "public_url_") {
			t.Fatalf("invalid ID accepted: %q", invalid)
		}
	}
}

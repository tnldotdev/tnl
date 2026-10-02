package opaqueid

import (
	"strings"
	"testing"
)

func TestNewAndValid(t *testing.T) {
	id, err := New(PublicURLPrefix)
	if err != nil {
		t.Fatal(err)
	}
	if !Valid(id, PublicURLPrefix) || len(id) != len(PublicURLPrefix)+22 {
		t.Fatalf("generated ID is invalid: %q", id)
	}
	for _, invalid := range []string{
		PublicURLPrefix,
		PublicURLPrefix + strings.Repeat("0", 21),
		PublicURLPrefix + strings.Repeat("0", 23),
		PublicURLPrefix + strings.Repeat("0", 21) + "_",
		"public_url_" + strings.Repeat("0", 32),
		TeamPrefix + strings.Repeat("0", 22),
	} {
		if Valid(invalid, PublicURLPrefix) {
			t.Fatalf("invalid ID accepted: %q", invalid)
		}
	}
}

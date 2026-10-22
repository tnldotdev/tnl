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

func TestPrivateIdentifiersAreDistinctFromPublicURLsAndEachOther(t *testing.T) {
	private := []string{
		ServicePrefix, ServiceRunPrefix, ConnectorSessionPrefix,
		ServiceInvitationPrefix, ServiceGrantPrefix,
	}
	for _, prefix := range private {
		t.Run(prefix, func(t *testing.T) {
			id, err := New(prefix)
			if err != nil || !Valid(id, prefix) {
				t.Fatalf("private ID %q: %v", id, err)
			}
			for _, other := range append([]string{PublicURLPrefix, PublishRunPrefix, InvitationPrefix}, private...) {
				if other != prefix && Valid(id, other) {
					t.Fatalf("%q accepted as %q", id, other)
				}
			}
			for _, invalid := range []string{prefix, prefix + strings.Repeat("a", 21), prefix + strings.Repeat("a", 23), prefix + strings.Repeat("a", 21) + "-"} {
				if Valid(invalid, prefix) {
					t.Fatalf("invalid private ID %q accepted", invalid)
				}
			}
		})
	}
}

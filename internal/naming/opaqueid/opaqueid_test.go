package opaqueid

import (
	"strings"
	"testing"
)

func TestNewAndValid(t *testing.T) {
	id, err := New(ServicePrefix)
	if err != nil {
		t.Fatal(err)
	}
	if !Valid(id, ServicePrefix) || len(id) != len(ServicePrefix)+22 {
		t.Fatalf("generated ID is invalid: %q", id)
	}
	for _, invalid := range []string{
		ServicePrefix,
		ServicePrefix + strings.Repeat("0", 21),
		ServicePrefix + strings.Repeat("0", 23),
		ServicePrefix + strings.Repeat("0", 21) + "_",
		"public_url_" + strings.Repeat("0", 32),
		TeamPrefix + strings.Repeat("0", 22),
	} {
		if Valid(invalid, ServicePrefix) {
			t.Fatalf("invalid ID accepted: %q", invalid)
		}
	}
}

func TestServiceIdentifiersAreDistinctFromRetiredIDsAndEachOther(t *testing.T) {
	services := []string{
		ServicePrefix, ServiceRunPrefix,
		ServiceInvitationPrefix, ServiceGrantPrefix,
	}
	for _, prefix := range services {
		t.Run(prefix, func(t *testing.T) {
			id, err := New(prefix)
			if err != nil || !Valid(id, prefix) {
				t.Fatalf("service ID %q: %v", id, err)
			}
			for _, other := range append([]string{"url_", "pr_", InvitationPrefix}, services...) {
				if other != prefix && Valid(id, other) {
					t.Fatalf("%q accepted as %q", id, other)
				}
			}
			for _, invalid := range []string{prefix, prefix + strings.Repeat("a", 21), prefix + strings.Repeat("a", 23), prefix + strings.Repeat("a", 21) + "-"} {
				if Valid(invalid, prefix) {
					t.Fatalf("invalid service ID %q accepted", invalid)
				}
			}
		})
	}
}

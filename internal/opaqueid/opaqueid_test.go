package opaqueid

import (
	"strings"
	"testing"
)

func TestNewAndValid(t *testing.T) {
	id, err := New("route_")
	if err != nil {
		t.Fatal(err)
	}
	if !Valid(id, "route_") {
		t.Fatalf("generated ID is invalid: %q", id)
	}
	for _, invalid := range []string{
		"route_",
		"route_" + strings.Repeat("0", 31),
		"route_" + strings.Repeat("0", 31) + "A",
		"session_" + strings.Repeat("0", 32),
	} {
		if Valid(invalid, "route_") {
			t.Fatalf("invalid ID accepted: %q", invalid)
		}
	}
}

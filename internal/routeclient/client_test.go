package routeclient

import (
	"testing"

	"github.com/tnldotdev/tnl/internal/controlclient"
)

func TestNewRequiresDependencies(t *testing.T) {
	control, err := controlclient.New("https://control.example", nil, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := New(nil); err == nil {
		t.Fatal("New accepted a nil control client")
	}
	if _, err := New(control); err != nil {
		t.Fatal(err)
	}
}

func TestCanonicalizeIPPrefixesPreservesOmission(t *testing.T) {
	if value, err := canonicalizeIPPrefixes(nil); err != nil || value != nil {
		t.Fatalf("nil prefixes = %v, %v", value, err)
	}
	values := []string{"192.0.2.4/24", "192.0.2.0/24"}
	canonical, err := canonicalizeIPPrefixes(&values)
	if err != nil {
		t.Fatal(err)
	}
	if canonical == nil || len(*canonical) != 1 || (*canonical)[0] != "192.0.2.0/24" {
		t.Fatalf("canonical prefixes = %#v", canonical)
	}
	invalid := []string{"not-an-address"}
	if _, err := canonicalizeIPPrefixes(&invalid); err == nil {
		t.Fatal("invalid prefix was accepted")
	}
}

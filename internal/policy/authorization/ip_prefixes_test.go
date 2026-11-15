package authorization

import (
	"slices"
	"strconv"
	"testing"
)

func TestCanonicalizeIPPrefixes(t *testing.T) {
	if prefixes, err := CanonicalizeIPPrefixes(nil); err != nil || prefixes != nil {
		t.Fatalf("omitted prefixes = %v, %v", prefixes, err)
	}
	if prefixes, err := CanonicalizeIPPrefixes([]string{}); err != nil || prefixes == nil || len(prefixes) != 0 {
		t.Fatalf("empty prefixes = %v, %v", prefixes, err)
	}
	prefixes, err := CanonicalizeIPPrefixes([]string{"2001:db8::1/64", "192.0.2.9/24"})
	if err != nil || !slices.Equal(prefixes, []string{"192.0.2.0/24", "2001:db8::/64"}) {
		t.Fatalf("canonical prefixes = %v, %v", prefixes, err)
	}
	for _, input := range [][]string{
		{"192.0.2.1/24", "192.0.2.0/24"},
		{"fe80::1%en0"},
		{"::ffff:192.0.2.0/95"},
		{"invalid"},
	} {
		if got, err := CanonicalizeIPPrefixes(input); err == nil {
			t.Fatalf("invalid prefixes %v accepted as %v", input, got)
		}
	}
	large := make([]string, 256)
	for index := range large {
		large[index] = "192.0.2." + strconv.Itoa(index)
	}
	if prefixes, err := CanonicalizeIPPrefixes(large); err != nil || len(prefixes) != len(large) {
		t.Fatalf("large prefix policy = %d entries, error = %v", len(prefixes), err)
	}
}

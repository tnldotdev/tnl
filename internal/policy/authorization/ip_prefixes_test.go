package authorization

import (
	"errors"
	"fmt"
	"slices"
	"strconv"
	"testing"
)

func TestCanonicalizeIPPrefixes(t *testing.T) {
	if prefixes, err := CanonicalizeIPPrefixes(nil); err != nil || prefixes != nil {
		t.Fatalf("omitted prefixes = %v, %v", prefixes, err)
	}
	for _, test := range []struct {
		name        string
		input, want []string
	}{
		{"masked IPv4", []string{"192.0.2.9/24", "192.0.2.0/24"}, []string{"192.0.2.0/24"}},
		{"address aliases", []string{"192.0.2.1", "192.0.2.1/32", "::ffff:192.0.2.1", "::ffff:192.0.2.1/128"}, []string{"192.0.2.1/32"}},
		{"mapped network aliases", []string{"192.0.2.0/24", "::ffff:192.0.2.9/120"}, []string{"192.0.2.0/24"}},
		{"IPv6 aliases", []string{"2001:0DB8::9/64", "2001:db8::/64", "2001:db8::1", "2001:db8::1/128"}, []string{"2001:db8::/64", "2001:db8::1/128"}},
		{"overlap is not equality", []string{"192.0.2.1", "192.0.2.9/24", "192.0.2.0/25", "192.0.2.128/25"}, []string{"192.0.2.0/24", "192.0.2.0/25", "192.0.2.1/32", "192.0.2.128/25"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			before := slices.Clone(test.input)
			got, err := CanonicalizeIPPrefixes(test.input)
			if err != nil || !slices.Equal(got, test.want) || !slices.Equal(before, test.input) {
				t.Fatalf("normalize %v = %v, %v; want %v without input mutation", before, got, err, test.want)
			}
			slices.Reverse(test.input)
			reversed, err := CanonicalizeIPPrefixes(test.input)
			if err != nil || !slices.Equal(reversed, test.want) {
				t.Fatalf("reordering changed canonical policy: %v, %v", reversed, err)
			}
		})
	}
	if prefixes, err := CanonicalizeIPPrefixes([]string{}); err != nil || prefixes == nil || len(prefixes) != 0 {
		t.Fatalf("empty prefixes = %v, %v", prefixes, err)
	}
	prefixes, err := CanonicalizeIPPrefixes([]string{"2001:db8::1/64", "192.0.2.9/24"})
	if err != nil || !slices.Equal(prefixes, []string{"192.0.2.0/24", "2001:db8::/64"}) {
		t.Fatalf("canonical prefixes = %v, %v", prefixes, err)
	}
	for _, input := range [][]string{
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

func TestCanonicalizeVisitorIPPrefixLimit(t *testing.T) {
	values := make([]string, 257)
	for index := range values {
		values[index] = fmt.Sprintf("2001:db8::%x", index)
	}
	withAliases := append(slices.Clone(values[:256]), values[0], values[0]+"/128")
	prefixes, err := CanonicalizeVisitorIPPrefixes(withAliases)
	if err != nil || len(prefixes) != 256 || !slices.IsSorted(prefixes) {
		t.Fatal("256 unique prefixes plus aliases must fit", len(prefixes), err)
	}
	if result, err := CanonicalizeVisitorIPPrefixes(values); result != nil || !errors.Is(err, ErrInvalid) || !errors.Is(err, ErrIPPrefixLimit) {
		t.Fatal("257 distinct prefixes lost the owned limit error or returned a partial policy", result, err)
	}
	duplicates := make([]string, 4096)
	for index := range duplicates {
		duplicates[index] = "192.0.2.9/24"
	}
	if result, err := CanonicalizeVisitorIPPrefixes(duplicates); err != nil || !slices.Equal(result, []string{"192.0.2.0/24"}) {
		t.Fatal("duplicate count consumed the normalized limit", result, err)
	}
	duplicates = append(duplicates, "::ffff:192.0.2.9/95")
	if result, err := CanonicalizeVisitorIPPrefixes(duplicates); result != nil || !errors.Is(err, ErrInvalid) || errors.Is(err, ErrIPPrefixLimit) {
		t.Fatal("deduplication hid an invalid mapped prefix", result, err)
	}
	// other consumers retain their own limits, such as webhook sender catalogs.
	if result, err := CanonicalizeIPPrefixes(values); err != nil || len(result) != len(values) {
		t.Fatal("visitor limit leaked into general IP normalization", len(result), err)
	}
}

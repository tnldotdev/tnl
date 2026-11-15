package ippolicy

import (
	"net/netip"
	"strings"
	"testing"
)

func TestAddressDigestsNormalizeAndSeparateKeys(t *testing.T) {
	first, second := [32]byte{1}, [32]byte{2}
	for _, pair := range [][2]string{
		{"192.0.2.1", "::ffff:192.0.2.1"},
		{"2001:db8::1", "2001:0db8:0:0::1"},
	} {
		a, err := HashAddress(first, netip.MustParseAddr(pair[0]))
		b, otherErr := HashAddress(first, netip.MustParseAddr(pair[1]))
		c, thirdErr := HashAddress(second, netip.MustParseAddr(pair[0]))
		if err != nil || otherErr != nil || thirdErr != nil || a != b || a == c {
			t.Fatal("address normalization or key isolation changed")
		}
		if _, err := ParseDigest(a); err != nil {
			t.Fatal(err)
		}
	}
	for _, address := range []netip.Addr{{}, netip.MustParseAddr("0.0.0.0"), netip.MustParseAddr("::"), netip.MustParseAddr("fe80::1%en0")} {
		if _, err := HashAddress(first, address); err == nil {
			t.Fatal("accepted invalid exact address", address)
		}
	}
	if _, err := HashAddress([32]byte{}, netip.MustParseAddr("192.0.2.1")); err == nil {
		t.Fatal("accepted missing key")
	}
	for _, invalid := range []string{"192.0.2.1", strings.Repeat("A", 42), strings.Repeat("A", 44), strings.Repeat("A", 42) + "B"} {
		if _, err := ParseDigest(invalid); err == nil {
			t.Fatal("accepted invalid or noncanonical digest", invalid)
		}
	}
}

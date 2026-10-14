package ippolicy

import (
	"net/netip"
	"testing"
	"time"
)

func TestHashedPrefixesMatchTheirNetworksWithoutTheOriginalAddress(t *testing.T) {
	key := [32]byte{1}
	var entries []Entry
	for _, value := range []string{"192.0.2.0/24", "192.0.2.40/32", "2001:db8::/64", "2001:db8:1::7/128"} {
		entry, err := Hash(key, netip.MustParsePrefix(value))
		if err != nil {
			t.Fatal(err)
		}
		entries = append(entries, entry)
	}
	policy, err := New(key, entries)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		address string
		allowed bool
	}{
		{"192.0.2.41", true}, {"192.0.3.40", false},
		{"::ffff:192.0.2.41", true}, {"2001:db8::9", true},
		{"2001:db8:1::7", true}, {"2001:db8:1::8", false},
	} {
		if got := policy.Allows(netip.MustParseAddr(test.address)); got != test.allowed {
			t.Errorf("allow %s = %t, want %t", test.address, got, test.allowed)
		}
	}
	if _, err := New([32]byte{2}, entries); err != nil {
		t.Fatal(err)
	}
	other, _ := New([32]byte{2}, entries)
	if other.Allows(netip.MustParseAddr("192.0.2.41")) {
		t.Fatal("policy accepted an address with the wrong verifier key")
	}
}

func TestTemporaryIPEntryStopsAdmittingNewVisitorsAtExpiry(t *testing.T) {
	key := [32]byte{1}
	address := netip.MustParseAddr("192.0.2.7")
	entry, err := Hash(key, netip.PrefixFrom(address, 32))
	if err != nil {
		t.Fatal(err)
	}
	expires := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	entry.ExpiresAt = &expires
	policy, err := New(key, []Entry{entry})
	if err != nil {
		t.Fatal(err)
	}
	if !policy.AllowsAt(address, expires.Add(-time.Nanosecond)) || policy.AllowsAt(address, expires) ||
		policy.AllowsAt(address, expires.Add(time.Minute)) {
		t.Fatal("expired entry still admits new visitors")
	}
	permanent := entry
	permanent.ExpiresAt = nil
	policy, err = New(key, []Entry{entry, permanent})
	if err != nil || !policy.AllowsAt(address, expires.Add(time.Minute)) {
		t.Fatalf("durable source entry lost to expiring duplicate: %v", err)
	}
}

func TestInvalidHashedPolicyFailsClosed(t *testing.T) {
	entry, err := Hash([32]byte{1}, netip.MustParsePrefix("0.0.0.0/0"))
	if err != nil {
		t.Fatal(err)
	}
	for _, invalid := range [][]Entry{nil, {{Family: "ipv4", Bits: 33, Digest: entry.Digest}},
		{{Family: "ipv6", Bits: 24, Digest: "not a digest"}}} {
		if _, err := New([32]byte{1}, invalid); err == nil {
			t.Fatalf("invalid policy accepted: %+v", invalid)
		}
	}
	policy, err := New([32]byte{1}, []Entry{entry})
	if err != nil || !policy.Allows(netip.MustParseAddr("192.0.2.7")) || policy.Allows(netip.MustParseAddr("2001:db8::1")) {
		t.Fatalf("IPv4 /0 policy = %+v, %v", policy, err)
	}
}

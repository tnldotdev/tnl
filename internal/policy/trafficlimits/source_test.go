package trafficlimits

import (
	"net/netip"
	"testing"
)

func TestSourceNetworkGroupsCanonicalVisitorAddresses(t *testing.T) {
	for _, test := range []struct{ address, network string }{
		{"192.0.2.1", "192.0.2.1/32"},
		{"::ffff:192.0.2.1", "192.0.2.1/32"},
		{"192.0.2.2", "192.0.2.2/32"},
		{"2001:db8::1", "2001:db8::/64"},
		{"2001:db8::ffff", "2001:db8::/64"},
		{"2001:db8:0:1::1", "2001:db8:0:1::/64"},
		{"fe80::1%en0", ""},
		{"", ""},
	} {
		address, _ := netip.ParseAddr(test.address)
		network, _ := netip.ParsePrefix(test.network)
		if got := SourceNetwork(address); got != network {
			t.Errorf("%q: got %v, want %v", test.address, got, network)
		}
	}
}

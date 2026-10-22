package state

import "testing"

func TestPublicPublisherAddress(t *testing.T) {
	for _, tc := range []struct{ source, address, family string }{
		{"8.8.8.8", "8.8.8.8", "ipv4"}, {"::ffff:8.8.4.4", "8.8.4.4", "ipv4"},
		{"2606:4700:4700:0000::1111", "2606:4700:4700::1111", "ipv6"},
	} {
		if a, f := publicPublisherAddress(tc.source); a != tc.address || f != tc.family {
			t.Errorf("%s: %s %s", tc.source, a, f)
		}
	}
	for _, source := range []string{"", "invalid", "8.8.8.8/32", "8.8.8.8:443", "127.0.0.1", "::1", "::ffff:127.0.0.1", "10.0.0.1", "172.16.0.1", "192.168.1.1", "fc00::1", "fe80::1", "fe80::1%en0", "169.254.169.254", "100.64.1.1", "0.0.0.0", "0.1.2.3", "::", "224.0.0.1", "ff02::1", "255.255.255.255", "240.1.2.3", "192.0.2.1", "198.51.100.2", "203.0.113.3", "198.19.0.1", "192.0.0.8", "192.88.99.1", "2001:db8::1", "2001::1", "2002:0808:0808::1", "3fff::1", "64:ff9b::808:808", "100::1", "5f00::1"} {
		if a, f := publicPublisherAddress(source); a != "" || f != "unknown" {
			t.Errorf("non-public %s: %s %s", source, a, f)
		}
	}
}

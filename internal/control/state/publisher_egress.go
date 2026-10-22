package state

import "net/netip"

// publicPublisherAddress accepts only globally routable host evidence. netip's
// global-unicast predicate alone includes documentation and reserved ranges.
func publicPublisherAddress(source string) (string, string) {
	a, err := netip.ParseAddr(source)
	if err != nil || a.Zone() != "" {
		return "", "unknown"
	}
	a = a.Unmap()
	if !a.IsGlobalUnicast() || a.IsPrivate() || a.IsLoopback() || a.IsLinkLocalUnicast() {
		return "", "unknown"
	}
	for _, p := range publisherNonPublicPrefixes {
		if p.Contains(a) {
			return "", "unknown"
		}
	}
	if a.Is4() {
		return a.String(), "ipv4"
	}
	// currently allocated global IPv6 unicast; exclude special-purpose blocks.
	if !netip.MustParsePrefix("2000::/3").Contains(a) {
		return "", "unknown"
	}
	return a.String(), "ipv6"
}

var publisherNonPublicPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"), netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("192.0.0.0/24"), netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("192.88.99.0/24"), netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"), netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("240.0.0.0/4"), netip.MustParsePrefix("2001::/23"),
	netip.MustParsePrefix("2001:db8::/32"), netip.MustParsePrefix("2002::/16"),
	netip.MustParsePrefix("3fff::/20"),
}

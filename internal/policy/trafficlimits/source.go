package trafficlimits

import "net/netip"

// SourceNetwork groups visitor capacity by IPv4 /32 or IPv6 /64.
func SourceNetwork(addr netip.Addr) netip.Prefix {
	addr = addr.Unmap()
	if !addr.IsValid() || addr.Zone() != "" {
		return netip.Prefix{}
	}
	bits := addr.BitLen()
	if addr.Is6() {
		bits = 64
	}
	return netip.PrefixFrom(addr, bits).Masked()
}

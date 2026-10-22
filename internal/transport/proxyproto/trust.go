package proxyproto

import (
	"errors"
	"net"
	"net/netip"
)

func TrustedPeers(values []string) ([]netip.Prefix, error) {
	if len(values) == 0 {
		return nil, errors.New("PROXY metadata requires explicit trusted peer CIDRs")
	}
	result := make([]netip.Prefix, len(values))
	for index, value := range values {
		prefix, err := netip.ParsePrefix(value)
		if err != nil || prefix != prefix.Masked() || prefix.Bits() == 0 || prefix.Addr().Is4In6() {
			return nil, errors.New("PROXY peer must be a canonical bounded CIDR")
		}
		result[index] = prefix
	}
	return result, nil
}

func Trusted(address net.Addr, prefixes []netip.Prefix) bool {
	peer, err := netip.ParseAddrPort(address.String())
	if err != nil {
		return false
	}
	for _, prefix := range prefixes {
		if prefix.Contains(peer.Addr().Unmap()) {
			return true
		}
	}
	return false
}

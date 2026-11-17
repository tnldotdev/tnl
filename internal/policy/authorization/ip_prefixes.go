package authorization

import (
	"errors"
	"net/netip"
	"slices"
)

const MaxVisitorIPPrefixes = 256

var ErrIPPrefixLimit = errors.New("IP list must contain at most 256 normalized prefixes")

// CanonicalizeIPPrefixes parses, masks, deduplicates, and sorts an IP
// policy. it preserves nil so an omitted policy differs from an empty policy.
func CanonicalizeIPPrefixes(values []string) ([]string, error) {
	return canonicalizeIPPrefixes(values, len(values))
}

// CanonicalizeVisitorIPPrefixes bounds the normalized visitor policy, not the raw
// aliases. transport owners bound input bytes; only 256 distinct values are kept.
func CanonicalizeVisitorIPPrefixes(values []string) ([]string, error) {
	return canonicalizeIPPrefixes(values, MaxVisitorIPPrefixes)
}

func canonicalizeIPPrefixes(values []string, maximum int) ([]string, error) {
	if values == nil {
		return nil, nil
	}
	capacity := min(len(values), maximum)
	result := make([]string, 0, capacity)
	seen := make(map[netip.Prefix]struct{}, capacity)
	for _, value := range values {
		prefix, err := canonicalIPPrefix(value)
		if err != nil {
			return nil, errors.Join(ErrInvalid, err)
		}
		if _, exists := seen[prefix]; exists {
			continue
		}
		if len(result) == maximum {
			return nil, errors.Join(ErrInvalid, ErrIPPrefixLimit)
		}
		seen[prefix] = struct{}{}
		result = append(result, prefix.String())
	}
	slices.Sort(result)
	return result, nil
}

func canonicalIPPrefix(value string) (netip.Prefix, error) {
	if address, err := netip.ParseAddr(value); err == nil {
		if address.Zone() != "" {
			return netip.Prefix{}, errors.New("zoned IP address")
		}
		address = address.Unmap()
		return netip.PrefixFrom(address, address.BitLen()), nil
	}
	prefix, err := netip.ParsePrefix(value)
	if err != nil {
		return netip.Prefix{}, err
	}
	address := prefix.Addr()
	bits := prefix.Bits()
	if address.Is4In6() {
		if bits < 96 {
			return netip.Prefix{}, errors.New("IPv4-mapped prefix includes non-IPv4 addresses")
		}
		address = address.Unmap()
		bits -= 96
	}
	return netip.PrefixFrom(address, bits).Masked(), nil
}

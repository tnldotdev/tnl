package ippolicy

import (
	"crypto/sha256"
	"encoding/base64"
	"net/netip"
)

// HashAddress uses the same canonical full-length prefix as exact IP policies.
// callers separate purposes and scopes when deriving keys.
func HashAddress(key [32]byte, address netip.Addr) (string, error) {
	address, err := NormalizeAddress(address)
	if err != nil {
		return "", err
	}
	entry, err := Hash(key, netip.PrefixFrom(address, address.BitLen()))
	return entry.Digest, err
}

// NormalizeAddress accepts one exact source address, never a zone or unspecified IP.
func NormalizeAddress(address netip.Addr) (netip.Addr, error) {
	if !address.IsValid() || address.Zone() != "" || address.Unmap().IsUnspecified() {
		return netip.Addr{}, ErrInvalidPolicy
	}
	return address.Unmap(), nil
}

// ParseDigest accepts only canonical, unpadded SHA-256 digest encodings.
func ParseDigest(encoded string) ([32]byte, error) {
	var digest [32]byte
	value, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil || len(value) != sha256.Size || base64.RawURLEncoding.EncodeToString(value) != encoded {
		return digest, ErrInvalidPolicy
	}
	copy(digest[:], value)
	return digest, nil
}

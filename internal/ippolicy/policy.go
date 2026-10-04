// package ippolicy verifies allowed CIDRs without exposing their network addresses.
package ippolicy

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/netip"
)

type Entry struct {
	Family string `json:"family"`
	Bits   int    `json:"prefix_length"`
	Digest string `json:"digest"`
}

type length struct {
	family byte
	bits   uint8
}

type Policy struct {
	key     [32]byte
	allowed map[length]map[[32]byte]struct{}
}

var ErrInvalidPolicy = errors.New("ippolicy: invalid allowed IP policy")

func Hash(key [32]byte, prefix netip.Prefix) (Entry, error) {
	if key == [32]byte{} || !prefix.IsValid() || prefix.Addr().Zone() != "" {
		return Entry{}, ErrInvalidPolicy
	}
	address, bits := prefix.Addr(), prefix.Bits()
	if address.Is4In6() {
		if bits < 96 {
			return Entry{}, ErrInvalidPolicy
		}
		address, bits = address.Unmap(), bits-96
	}
	masked := netip.PrefixFrom(address, bits).Masked()
	family := "ipv6"
	if address.Is4() {
		family = "ipv4"
	}
	digest := hash(key, masked)
	return Entry{Family: family, Bits: bits, Digest: base64.RawURLEncoding.EncodeToString(digest[:])}, nil
}

func New(key [32]byte, entries []Entry) (Policy, error) {
	if key == [32]byte{} || len(entries) == 0 {
		return Policy{}, ErrInvalidPolicy
	}
	policy := Policy{key: key, allowed: make(map[length]map[[32]byte]struct{})}
	for _, entry := range entries {
		family := byte(6)
		maximum := 128
		if entry.Family == "ipv4" {
			family, maximum = 4, 32
		} else if entry.Family != "ipv6" {
			return Policy{}, ErrInvalidPolicy
		}
		if entry.Bits < 0 || entry.Bits > maximum {
			return Policy{}, ErrInvalidPolicy
		}
		bytes, err := base64.RawURLEncoding.DecodeString(entry.Digest)
		if err != nil || len(bytes) != sha256.Size || base64.RawURLEncoding.EncodeToString(bytes) != entry.Digest {
			return Policy{}, ErrInvalidPolicy
		}
		group := length{family: family, bits: uint8(entry.Bits)}
		if policy.allowed[group] == nil {
			policy.allowed[group] = make(map[[32]byte]struct{})
		}
		var digest [32]byte
		copy(digest[:], bytes)
		policy.allowed[group][digest] = struct{}{}
	}
	return policy, nil
}

func (p Policy) Allows(source netip.Addr) bool {
	if !source.IsValid() || source.Zone() != "" {
		return false
	}
	source = source.Unmap()
	family := byte(6)
	if source.Is4() {
		family = 4
	}
	for size, digests := range p.allowed {
		if size.family != family {
			continue
		}
		masked := netip.PrefixFrom(source, int(size.bits)).Masked()
		if _, ok := digests[hash(p.key, masked)]; ok {
			return true
		}
	}
	return false
}

func hash(key [32]byte, prefix netip.Prefix) [32]byte {
	mac := hmac.New(sha256.New, key[:])
	_, _ = mac.Write([]byte("tnl/ip-allowlist/v1\x00"))
	address := prefix.Addr()
	if address.Is4() {
		_, _ = mac.Write([]byte{4, byte(prefix.Bits())})
		value := address.As4()
		_, _ = mac.Write(value[:])
	} else {
		_, _ = mac.Write([]byte{6, byte(prefix.Bits())})
		value := address.As16()
		_, _ = mac.Write(value[:])
	}
	return [32]byte(mac.Sum(nil))
}

package authorization

import (
	"crypto/sha256"
	"errors"
	"net/netip"
	"slices"
	"strconv"
	"unicode/utf8"
)

const MaxIPPrefixes = 64

// CoreRequest is one of the three fixed request bodies covered by the
// authorization protocol. SignedAuthorization is intentionally absent.
type CoreRequest struct {
	Operation         Operation
	Hostname          string
	LocalTarget       string
	RouteToken        string
	AllowedIPPrefixes []string
	Version           uint64
}

// CanonicalRequestHash hashes the RFC 8785 representation of an exact Core
// request shape. It intentionally does not implement general JSON canonicalization.
func CanonicalRequestHash(request CoreRequest) (Digest, error) {
	var canonical []byte
	var err error
	switch request.Operation {
	case OperationRouteCreate:
		canonical, err = appendObject(nil, request.AllowedIPPrefixes,
			[]field{{"hostname", request.Hostname}, {"local_target", request.LocalTarget}, {"route_token", request.RouteToken}})
	case OperationRouteSessionCreate:
		canonical, err = appendObject(nil, request.AllowedIPPrefixes, []field{{"route_token", request.RouteToken}})
	case OperationRenew:
		if request.Version == 0 {
			return Digest{}, invalid("renewal version is required")
		}
		canonical = strconv.AppendUint([]byte(`{"version":`), request.Version, 10)
		canonical = append(canonical, '}')
	default:
		return Digest{}, invalid("unknown request operation")
	}
	if err != nil {
		return Digest{}, err
	}
	return Digest(sha256.Sum256(canonical)), nil
}

// CanonicalizeIPPrefixes parses, masks, deduplicates, and sorts an IP policy.
// A nil slice remains nil so omission differs from an explicitly empty policy.
func CanonicalizeIPPrefixes(values []string) ([]string, error) {
	if values == nil {
		return nil, nil
	}
	result := make([]string, 0, min(len(values), MaxIPPrefixes))
	seen := make(map[string]struct{}, min(len(values), MaxIPPrefixes))
	for _, value := range values {
		prefix, err := canonicalIPPrefix(value)
		if err != nil {
			return nil, invalid("invalid IP prefix")
		}
		canonical := prefix.String()
		if _, exists := seen[canonical]; exists {
			continue
		}
		seen[canonical] = struct{}{}
		result = append(result, canonical)
		if len(result) > MaxIPPrefixes {
			return nil, invalid("too many IP prefixes")
		}
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

// IPPolicyHash hashes the RFC 8785 representation of the canonical prefix
// array. A nil policy has no hash; an explicitly empty policy hashes "[]".
func IPPolicyHash(prefixes []string) (*Digest, error) {
	if prefixes == nil {
		return nil, nil
	}
	canonical, err := CanonicalizeIPPrefixes(prefixes)
	if err != nil {
		return nil, err
	}
	encoded, err := appendStringArray(nil, canonical)
	if err != nil {
		return nil, err
	}
	digest := Digest(sha256.Sum256(encoded))
	return &digest, nil
}

type field struct {
	name  string
	value string
}

func appendObject(destination []byte, prefixes []string, fields []field) ([]byte, error) {
	destination = append(destination, '{')
	wrote := false
	if prefixes != nil {
		destination = append(destination, `"allowed_ip_prefixes":`...)
		var err error
		destination, err = appendStringArray(destination, prefixes)
		if err != nil {
			return nil, err
		}
		wrote = true
	}
	for _, field := range fields {
		if wrote {
			destination = append(destination, ',')
		}
		destination = append(destination, '"')
		destination = append(destination, field.name...)
		destination = append(destination, '"', ':')
		var err error
		destination, err = appendJSONString(destination, field.value)
		if err != nil {
			return nil, err
		}
		wrote = true
	}
	return append(destination, '}'), nil
}

func appendStringArray(destination []byte, values []string) ([]byte, error) {
	destination = append(destination, '[')
	for index, value := range values {
		if index != 0 {
			destination = append(destination, ',')
		}
		var err error
		destination, err = appendJSONString(destination, value)
		if err != nil {
			return nil, err
		}
	}
	return append(destination, ']'), nil
}

func appendJSONString(destination []byte, value string) ([]byte, error) {
	if !utf8.ValidString(value) {
		return nil, errors.New("authorization: request contains invalid UTF-8")
	}
	destination = append(destination, '"')
	for _, char := range value {
		switch char {
		case '"', '\\':
			destination = append(destination, '\\', byte(char))
		case '\b':
			destination = append(destination, `\b`...)
		case '\t':
			destination = append(destination, `\t`...)
		case '\n':
			destination = append(destination, `\n`...)
		case '\f':
			destination = append(destination, `\f`...)
		case '\r':
			destination = append(destination, `\r`...)
		default:
			if char >= 0 && char <= 0x1f {
				destination = append(destination, `\u00`...)
				destination = append(destination, "0123456789abcdef"[char>>4], "0123456789abcdef"[char&0xf])
			} else {
				destination = utf8.AppendRune(destination, char)
			}
		}
	}
	return append(destination, '"'), nil
}

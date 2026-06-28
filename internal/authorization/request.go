// Package authorization defines direct operation authorization and canonical request helpers.
package authorization

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/netip"
	"slices"
)

const MaxIPPrefixes = 64

type Operation string

const (
	OperationRouteCreate        Operation = "route.create"
	OperationRouteSessionCreate Operation = "route_session.create"
	OperationRouteDelete        Operation = "route.delete"
)

var (
	ErrInvalid         = errors.New("authorization: invalid request")
	ErrUnauthenticated = errors.New("authorization: unauthenticated")
	ErrForbidden       = errors.New("authorization: forbidden")
	ErrUnavailable     = errors.New("authorization: unavailable")
)

type Digest [sha256.Size]byte

func (d Digest) String() string { return base64.RawURLEncoding.EncodeToString(d[:]) }

type CertificatePlan struct {
	CacheKey        string   `json:"cache_key"`
	Scope           string   `json:"scope"`
	Identifiers     []string `json:"identifiers"`
	ChallengeMethod string   `json:"challenge_method"`
}

// Request contains the user credential and exact operation facts control asks
// the authority to authorize.
type Request struct {
	AccessToken        string
	Operation          Operation
	TeamID             string
	ActingMembershipID string
	RouteMembershipID  string
	DomainID           string
	CanonicalHostname  string
	RouteScope         string
	Target             string
	AllowedIPPrefixes  []string
	RouteID            string
	RouteVersion       uint64
}

// Decision contains current authority state accepted by control. RetrySecret is
// internal key material and is never part of the authority wire response.
type Decision struct {
	IdentityID            string
	TeamID                string
	ActingMembershipID    string
	ActingRole            string
	RouteMembershipID     string
	TeamPolicyRevision    uint64
	DomainID              string
	CanonicalHostname     string
	RouteScope            string
	DNSAuthorityReference string
	CertificatePlan       *CertificatePlan
	RetrySecret           [32]byte
}

type Authorizer interface {
	Authorize(context.Context, Request) (Decision, error)
}

// OperationRequest contains every value covered by a canonical mutation digest.
type OperationRequest struct {
	Operation         Operation
	TeamID            string
	MembershipID      string
	DomainID          string
	CanonicalHostname string
	RouteScope        string
	RouteID           string
	RouteVersion      uint64
	PolicyRevision    uint64
	Target            string
	AllowedIPPrefixes []string
	CertificatePlan   *CertificatePlan
}

func invalid(message string) error { return errors.New("authorization: " + message) }

// CanonicalRequestHash hashes the fixed JSON shape for one authorized control mutation.
func CanonicalRequestHash(request OperationRequest) (Digest, error) {
	var value any
	switch request.Operation {
	case OperationRouteCreate:
		value = struct {
			AllowedIPPrefixes []string `json:"allowed_ip_prefixes,omitempty"`
			CanonicalHostname string   `json:"canonical_hostname"`
			DomainID          string   `json:"domain_id"`
			MembershipID      string   `json:"membership_id,omitempty"`
			RouteScope        string   `json:"route_scope"`
			Target            string   `json:"target"`
			TeamID            string   `json:"team_id"`
		}{request.AllowedIPPrefixes, request.CanonicalHostname, request.DomainID, request.MembershipID, request.RouteScope, request.Target, request.TeamID}
	case OperationRouteSessionCreate:
		if request.RouteID == "" || request.RouteVersion == 0 || request.CertificatePlan == nil || request.AllowedIPPrefixes == nil {
			return Digest{}, invalid("route session bindings are required")
		}
		value = struct {
			AllowedIPPrefixes []string        `json:"allowed_ip_prefixes"`
			CertificatePlan   CertificatePlan `json:"certificate_plan"`
			MembershipID      string          `json:"membership_id,omitempty"`
			PolicyRevision    uint64          `json:"policy_revision"`
			RouteID           string          `json:"route_id"`
			RouteVersion      uint64          `json:"route_version"`
			TeamID            string          `json:"team_id"`
		}{request.AllowedIPPrefixes, *request.CertificatePlan, request.MembershipID, request.PolicyRevision, request.RouteID, request.RouteVersion, request.TeamID}
	case OperationRouteDelete:
		if request.RouteID == "" {
			return Digest{}, invalid("route ID is required")
		}
		value = struct {
			RouteID string `json:"route_id"`
		}{request.RouteID}
	default:
		return Digest{}, invalid("unknown request operation")
	}
	canonical, err := json.Marshal(value)
	if err != nil {
		return Digest{}, invalid("encode request")
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

// IPPolicyHash hashes the canonical prefix array. A nil policy has no digest.
func IPPolicyHash(prefixes []string) (*Digest, error) {
	if prefixes == nil {
		return nil, nil
	}
	canonical, err := CanonicalizeIPPrefixes(prefixes)
	if err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(canonical)
	if err != nil {
		return nil, invalid("encode IP policy")
	}
	digest := Digest(sha256.Sum256(encoded))
	return &digest, nil
}

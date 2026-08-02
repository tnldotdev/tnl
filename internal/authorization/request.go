// Package authorization authorizes control operations and builds stable request hashes.
package authorization

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/netip"
	"slices"

	"github.com/tnldotdev/tnl/internal/localproxy"
)

const MaxIPPrefixes = 64

type Operation string

const (
	OperationRouteCreate        Operation = "route.create"
	OperationRouteUpdate        Operation = "route.update"
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
	AccessToken           string
	Operation             Operation
	TeamID                string
	ActingMembershipID    string
	RouteMembershipID     string
	DomainID              string
	CanonicalHostname     string
	RouteScope            string
	Target                string
	AllowedIPPrefixes     []string
	Ephemeral             bool
	RouteID               string
	RouteVersion          uint64
	RouteMutationRevision uint64
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

// OperationRequest contains every value included in a mutation hash.
type OperationRequest struct {
	Operation             Operation
	TeamID                string
	MembershipID          string
	DomainID              string
	CanonicalHostname     string
	RouteScope            string
	RouteID               string
	RouteVersion          uint64
	RouteMutationRevision uint64
	PolicyRevision        uint64
	Target                string
	AllowedIPPrefixes     []string
	Ephemeral             bool
	CertificatePlan       *CertificatePlan
}

func invalid(message string) error { return errors.New("authorization: " + message) }

// CanonicalRequestHash returns a stable hash for one authorized control change.
func CanonicalRequestHash(request OperationRequest) (Digest, error) {
	var value any
	switch request.Operation {
	case OperationRouteCreate:
		value = struct {
			AllowedIPPrefixes []string `json:"allowed_ip_prefixes,omitempty"`
			CanonicalHostname string   `json:"canonical_hostname"`
			DomainID          string   `json:"domain_id"`
			Ephemeral         bool     `json:"ephemeral,omitempty"`
			MembershipID      string   `json:"membership_id,omitempty"`
			RouteScope        string   `json:"route_scope"`
			Target            string   `json:"target"`
			TeamID            string   `json:"team_id"`
		}{request.AllowedIPPrefixes, request.CanonicalHostname, request.DomainID, request.Ephemeral, request.MembershipID, request.RouteScope, request.Target, request.TeamID}
	case OperationRouteUpdate:
		if request.TeamID == "" || request.DomainID == "" || request.CanonicalHostname == "" || request.RouteScope == "" ||
			request.RouteID == "" || request.RouteMutationRevision == 0 || request.PolicyRevision == 0 ||
			request.Target == "" || request.AllowedIPPrefixes == nil {
			return Digest{}, invalid("route update bindings are required")
		}
		value = struct {
			AllowedIPPrefixes     []string `json:"allowed_ip_prefixes"`
			CanonicalHostname     string   `json:"canonical_hostname"`
			DomainID              string   `json:"domain_id"`
			Ephemeral             bool     `json:"ephemeral"`
			MembershipID          string   `json:"membership_id,omitempty"`
			PolicyRevision        uint64   `json:"policy_revision"`
			RouteID               string   `json:"route_id"`
			RouteMutationRevision uint64   `json:"route_mutation_revision"`
			RouteScope            string   `json:"route_scope"`
			Target                string   `json:"target"`
			TeamID                string   `json:"team_id"`
		}{
			request.AllowedIPPrefixes, request.CanonicalHostname, request.DomainID, request.Ephemeral,
			request.MembershipID, request.PolicyRevision, request.RouteID, request.RouteMutationRevision,
			request.RouteScope, request.Target, request.TeamID,
		}
	case OperationRouteSessionCreate:
		if request.TeamID == "" || request.DomainID == "" || request.CanonicalHostname == "" || request.RouteScope == "" ||
			request.RouteID == "" || request.RouteVersion == 0 || request.PolicyRevision == 0 ||
			request.Target == "" || request.CertificatePlan == nil || request.AllowedIPPrefixes == nil {
			return Digest{}, invalid("route session bindings are required")
		}
		value = struct {
			AllowedIPPrefixes []string        `json:"allowed_ip_prefixes"`
			CanonicalHostname string          `json:"canonical_hostname"`
			CertificatePlan   CertificatePlan `json:"certificate_plan"`
			DomainID          string          `json:"domain_id"`
			Ephemeral         bool            `json:"ephemeral"`
			MembershipID      string          `json:"membership_id,omitempty"`
			PolicyRevision    uint64          `json:"policy_revision"`
			RouteID           string          `json:"route_id"`
			RouteScope        string          `json:"route_scope"`
			RouteVersion      uint64          `json:"route_version"`
			Target            string          `json:"target"`
			TeamID            string          `json:"team_id"`
		}{
			request.AllowedIPPrefixes, request.CanonicalHostname, *request.CertificatePlan, request.DomainID,
			request.Ephemeral, request.MembershipID, request.PolicyRevision, request.RouteID, request.RouteScope,
			request.RouteVersion, request.Target, request.TeamID,
		}
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

// CanonicalizeIPPrefixes parses, masks, rejects duplicates, and sorts an IP
// policy. It preserves nil so an omitted policy differs from an empty policy.
func CanonicalizeIPPrefixes(values []string) ([]string, error) {
	if values == nil {
		return nil, nil
	}
	if len(values) > MaxIPPrefixes {
		return nil, invalid("too many IP prefixes")
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
			return nil, invalid("duplicate IP prefix")
		}
		seen[canonical] = struct{}{}
		result = append(result, canonical)
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

// ValidateRouteTarget accepts the loopback HTTP target format used by routes.
func ValidateRouteTarget(target string) error {
	canonical, err := localproxy.NormalizeTarget(target)
	if err != nil || canonical != target {
		return invalid("invalid route target")
	}
	return nil
}

// IPPolicyHash hashes the normalized prefix list. A nil policy has no hash.
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

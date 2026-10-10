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

	"github.com/tnldotdev/tnl/internal/certificateidentity"
	"github.com/tnldotdev/tnl/internal/localproxy"
)

type Operation string

const (
	OperationPublicURLCreate  Operation = "public_url.create"
	OperationCredentialCreate Operation = "credential.create"
	OperationCredentialRevoke Operation = "credential.revoke"
	OperationPublicURLUpdate  Operation = "public_url.update"
	OperationPublishRunCreate Operation = "publish_run.create"
	OperationPublicURLDelete  Operation = "public_url.delete"
	OperationShareCreate      Operation = "share.create"
	OperationFeedbackManage   Operation = "feedback.manage"
	OperationPreviewVisit     Operation = "preview.visit"
)

// PublicURLScope identifies the ownership boundary for an authorized public URL.
type PublicURLScope string

const (
	PublicURLScopeMember PublicURLScope = "member"
	PublicURLScopeShared PublicURLScope = "shared"
)

func (scope PublicURLScope) Valid() bool {
	return scope == PublicURLScopeMember || scope == PublicURLScopeShared
}

var (
	ErrInvalid         = errors.New("authorization: invalid request")
	ErrUnauthenticated = errors.New("authorization: unauthenticated")
	ErrForbidden       = errors.New("authorization: forbidden")
	ErrGuestDemoOnly   = errors.New("authorization: guest demo options require sign-in")
	ErrGuestIPChanged  = errors.New("authorization: guest demo source IP changed")
	ErrUnavailable     = errors.New("authorization: unavailable")
)

type Digest [sha256.Size]byte

func (d Digest) String() string { return base64.RawURLEncoding.EncodeToString(d[:]) }

type CertificatePlan struct {
	CacheKey        string                              `json:"cache_key"`
	Scope           string                              `json:"scope"`
	Identifiers     []string                            `json:"identifiers"`
	ChallengeMethod certificateidentity.ChallengeMethod `json:"challenge_method"`
}

// Request contains the user credential and exact operation facts control asks
// the authority to authorize.
type Request struct {
	AccessToken               string
	Operation                 Operation
	TeamID                    string
	ActingMembershipID        string
	PublicURLMembershipID     string
	DomainID                  string
	CanonicalHostname         string
	PublicURLScope            PublicURLScope
	Target                    string
	AllowedIPPrefixes         []string
	Ephemeral                 bool
	PublicURLID               string
	PublishRunNumber          uint64
	PublicURLMutationRevision uint64
}

// Decision contains current authority state accepted by control. RetrySecret is
// internal key material and is never part of the authority wire response.
type Decision struct {
	GuestID               string
	IdentityID            string
	TeamID                string
	ActingMembershipID    string
	ActingRole            string
	PublicURLMembershipID string
	PolicyRevision        uint64
	DomainID              string
	CanonicalHostname     string
	Namespace             string
	PublicURLScope        PublicURLScope
	DNSAuthorityReference string
	CertificatePlan       *CertificatePlan
	RetrySecret           [32]byte
}

type Authorizer interface {
	Authorize(context.Context, Request) (Decision, error)
}

// OperationRequest contains every value included in a mutation hash.
type OperationRequest struct {
	Operation                 Operation
	TeamID                    string
	MembershipID              string
	DomainID                  string
	CanonicalHostname         string
	PublicURLScope            PublicURLScope
	PublicURLPurpose          string
	PublicURLID               string
	PublishRunNumber          uint64
	PublicURLMutationRevision uint64
	PolicyRevision            uint64
	Target                    string
	AllowedIPPrefixes         []string
	Ephemeral                 bool
	CertificatePlan           *CertificatePlan
}

func invalid(message string) error { return errors.New("authorization: " + message) }

// CanonicalRequestHash returns a stable hash for one authorized control change.
func CanonicalRequestHash(request OperationRequest) (Digest, error) {
	var value any
	switch request.Operation {
	case OperationPublicURLCreate:
		if !request.PublicURLScope.Valid() {
			return Digest{}, invalid("public URL scope is invalid")
		}
		value = struct {
			AllowedIPPrefixes []string `json:"allowed_ip_prefixes,omitempty"`
			CanonicalHostname string   `json:"canonical_hostname"`
			DomainID          string   `json:"domain_id"`
			Ephemeral         bool     `json:"ephemeral,omitempty"`
			MembershipID      string   `json:"membership_id,omitempty"`
			PublicURLScope    string   `json:"public_url_scope"`
			PublicURLPurpose  string   `json:"purpose,omitempty"`
			Target            string   `json:"target"`
			TeamID            string   `json:"team_id"`
		}{request.AllowedIPPrefixes, request.CanonicalHostname, request.DomainID, request.Ephemeral, request.MembershipID, string(request.PublicURLScope), request.PublicURLPurpose, request.Target, request.TeamID}
	case OperationPublicURLUpdate:
		if request.TeamID == "" || request.DomainID == "" || request.CanonicalHostname == "" || request.PublicURLScope == "" ||
			request.PublicURLID == "" || request.PublicURLMutationRevision == 0 || request.PolicyRevision == 0 ||
			request.AllowedIPPrefixes == nil {
			return Digest{}, invalid("public URL update bindings are required")
		}
		if !request.PublicURLScope.Valid() {
			return Digest{}, invalid("public URL scope is invalid")
		}
		value = struct {
			AllowedIPPrefixes         []string `json:"allowed_ip_prefixes"`
			CanonicalHostname         string   `json:"canonical_hostname"`
			DomainID                  string   `json:"domain_id"`
			Ephemeral                 bool     `json:"ephemeral"`
			MembershipID              string   `json:"membership_id,omitempty"`
			PolicyRevision            uint64   `json:"policy_revision"`
			PublicURLID               string   `json:"public_url_id"`
			PublicURLMutationRevision uint64   `json:"public_url_mutation_revision"`
			PublicURLScope            string   `json:"public_url_scope"`
			Target                    string   `json:"target"`
			TeamID                    string   `json:"team_id"`
		}{
			request.AllowedIPPrefixes, request.CanonicalHostname, request.DomainID, request.Ephemeral,
			request.MembershipID, request.PolicyRevision, request.PublicURLID, request.PublicURLMutationRevision,
			string(request.PublicURLScope), request.Target, request.TeamID,
		}
	case OperationPublishRunCreate:
		if request.TeamID == "" || request.DomainID == "" || request.CanonicalHostname == "" || request.PublicURLScope == "" ||
			request.PublicURLID == "" || request.PublishRunNumber == 0 || request.PolicyRevision == 0 ||
			request.CertificatePlan == nil || request.AllowedIPPrefixes == nil {
			return Digest{}, invalid("publish run bindings are required")
		}
		if !request.PublicURLScope.Valid() {
			return Digest{}, invalid("public URL scope is invalid")
		}
		value = struct {
			AllowedIPPrefixes []string        `json:"allowed_ip_prefixes"`
			CanonicalHostname string          `json:"canonical_hostname"`
			CertificatePlan   CertificatePlan `json:"certificate_plan"`
			DomainID          string          `json:"domain_id"`
			Ephemeral         bool            `json:"ephemeral"`
			MembershipID      string          `json:"membership_id,omitempty"`
			PolicyRevision    uint64          `json:"policy_revision"`
			PublicURLID       string          `json:"public_url_id"`
			PublicURLScope    string          `json:"public_url_scope"`
			PublishRunNumber  uint64          `json:"publish_run_number"`
			Target            string          `json:"target"`
			TeamID            string          `json:"team_id"`
		}{
			request.AllowedIPPrefixes, request.CanonicalHostname, *request.CertificatePlan, request.DomainID,
			request.Ephemeral, request.MembershipID, request.PolicyRevision, request.PublicURLID, string(request.PublicURLScope),
			request.PublishRunNumber, request.Target, request.TeamID,
		}
	case OperationPublicURLDelete:
		if request.PublicURLID == "" {
			return Digest{}, invalid("public URL ID is required")
		}
		value = struct {
			PublicURLID string `json:"public_url_id"`
		}{request.PublicURLID}
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
// policy. it preserves nil so an omitted policy differs from an empty policy.
func CanonicalizeIPPrefixes(values []string) ([]string, error) {
	if values == nil {
		return nil, nil
	}
	result := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
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

// ValidateTarget accepts the canonical HTTP or HTTPS target format used by public URLs.
func ValidateTarget(target string) error {
	canonical, err := localproxy.NormalizeTarget(target)
	if err != nil || canonical != target {
		return invalid("invalid public URL target")
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

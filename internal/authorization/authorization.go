// Package authorization verifies authority-issued operation authorizations.
package authorization

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"slices"
	"strings"
	"time"

	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/opaqueid"
)

const (
	// Type is the required explicit type of an authorization JWS.
	Type = "tnl-authorization+jwt"
	// UserAssertionType is the required explicit type of an authority access-token JWS.
	UserAssertionType = "tnl-user-assertion+jwt"

	Algorithm        = "EdDSA"
	MaxTokenBytes    = 4096
	MaxLifetime      = time.Hour
	AllowedClockSkew = 30 * time.Second
)

type Operation string

const (
	OperationRouteCreate        Operation = "route.create"
	OperationRouteSessionCreate Operation = "route_session.create"
	OperationRouteDelete        Operation = "route.delete"
)

// ErrInvalid is returned for every malformed, invalid, or mismatched authorization.
var ErrInvalid = errors.New("authorization: invalid authorization")

// Digest is a SHA-256 digest serialized as unpadded base64url in the authority protocol.
type Digest [sha256.Size]byte

func (d Digest) String() string { return base64.RawURLEncoding.EncodeToString(d[:]) }

// Config identifies the one authority and key trusted by a verifier.
type Config struct {
	Issuer    string
	Receiver  string
	KeyID     string
	PublicKey ed25519.PublicKey
	Now       func() time.Time
}

// Expected binds a signed authorization to one exact authorized operation.
type Expected struct {
	Operation         Operation
	TeamID            string
	MembershipID      string
	DomainID          string
	CanonicalHostname string
	RouteScope        string
	RouteID           string
	RouteVersion      uint64
	PolicyRevision    uint64
	CertificatePlan   *CertificatePlan
	RequestDigest     Digest
	IPPolicyDigest    *Digest
}

// Claims are authenticated authority claims. Callers using Authenticate must call
// Validate before using the claims to mutate state.
type Claims struct {
	Version           uint64
	KeyID             string
	Algorithm         string
	Operation         Operation
	Issuer            string
	Receiver          string
	AuthorizationID   string
	TeamID            string
	IdentityID        string
	MembershipID      string
	DomainID          string
	CanonicalHostname string
	RouteScope        string
	RouteID           string
	RouteVersion      uint64
	PolicyRevision    uint64
	CertificatePlan   *CertificatePlan
	IssuedAt          time.Time
	ExpiresAt         time.Time
	RetryID           string
	RequestDigest     Digest
	IPPolicyDigest    *Digest
}

// UserAssertionMembership is one current membership authenticated by an authority.
type UserAssertionMembership struct {
	TeamID         string `json:"team_id"`
	MembershipID   string `json:"membership_id"`
	Role           string `json:"role"`
	PolicyRevision uint64 `json:"team_policy_revision"`
}

// UserAssertion is a short-lived authority access token accepted by control.
type UserAssertion struct {
	Version       uint64
	KeyID         string
	Algorithm     string
	Issuer        string
	Receiver      string
	IdentityID    string
	Administrator bool
	Memberships   []UserAssertionMembership
	IssuedAt      time.Time
	ExpiresAt     time.Time
}

// Membership returns the assertion's current membership for teamID.
func (a UserAssertion) Membership(teamID string) (UserAssertionMembership, bool) {
	for _, membership := range a.Memberships {
		if membership.TeamID == teamID {
			return membership, true
		}
	}
	return UserAssertionMembership{}, false
}

type Verifier struct {
	issuer    string
	receiver  string
	keyID     string
	publicKey ed25519.PublicKey
	now       func() time.Time
}

// NewVerifier validates and copies authority verification configuration.
func NewVerifier(config Config) (*Verifier, error) {
	if strings.TrimSpace(config.Issuer) != config.Issuer || config.Issuer == "" ||
		strings.TrimSpace(config.Receiver) != config.Receiver || config.Receiver == "" ||
		strings.TrimSpace(config.KeyID) != config.KeyID || config.KeyID == "" || len(config.KeyID) > 128 {
		return nil, errors.New("authorization: issuer, receiver, and key ID are required")
	}
	if len(config.PublicKey) != ed25519.PublicKeySize {
		return nil, errors.New("authorization: Ed25519 public key must be 32 bytes")
	}
	now := config.Now
	if now == nil {
		now = time.Now
	}
	return &Verifier{
		issuer: config.Issuer, receiver: config.Receiver, keyID: config.KeyID,
		publicKey: append(ed25519.PublicKey(nil), config.PublicKey...), now: now,
	}, nil
}

// Verify authenticates token and validates every operation binding in expected.
func (v *Verifier) Verify(token string, expected Expected) (Claims, error) {
	claims, err := v.Authenticate(token)
	if err != nil {
		return Claims{}, err
	}
	if err := claims.Validate(expected); err != nil {
		return Claims{}, err
	}
	return claims, nil
}

// Authenticate verifies the compact JWS and intrinsic claim constraints. It is
// exposed for transactional consumers that must resolve an idempotent retry
// before selecting the exact expected route version.
func (v *Verifier) Authenticate(token string) (Claims, error) {
	payload, err := v.authenticate(token, Type)
	if err != nil {
		return Claims{}, ErrInvalid
	}
	var wire struct {
		Version            uint64           `json:"version"`
		KeyID              string           `json:"kid"`
		Algorithm          string           `json:"alg"`
		Operation          Operation        `json:"operation"`
		Issuer             string           `json:"issuer"`
		Receiver           string           `json:"receiver"`
		AuthorizationID    string           `json:"authorization_id"`
		TeamID             string           `json:"team_id"`
		IdentityID         string           `json:"identity_id"`
		MembershipID       *string          `json:"membership_id,omitempty"`
		DomainID           string           `json:"domain_id"`
		CanonicalHostname  string           `json:"canonical_hostname"`
		RouteScope         string           `json:"route_scope"`
		RouteID            *string          `json:"route_id,omitempty"`
		RouteVersion       *uint64          `json:"route_version,omitempty"`
		TeamPolicyRevision uint64           `json:"team_policy_revision"`
		CertificatePlan    *CertificatePlan `json:"certificate_plan,omitempty"`
		IssuedAt           *time.Time       `json:"issued_at"`
		ExpiresAt          *time.Time       `json:"expires_at"`
		RetryID            string           `json:"retry_id"`
		RequestDigest      string           `json:"request_digest"`
		IPPolicyDigest     *string          `json:"ip_policy_digest,omitempty"`
	}
	if err := decodeStrictObject(payload, &wire); err != nil || wire.IssuedAt == nil || wire.ExpiresAt == nil {
		return Claims{}, ErrInvalid
	}
	requestDigest, err := ParseDigest(wire.RequestDigest)
	if err != nil {
		return Claims{}, ErrInvalid
	}
	var ipPolicyDigest *Digest
	if wire.IPPolicyDigest != nil {
		digest, err := ParseDigest(*wire.IPPolicyDigest)
		if err != nil {
			return Claims{}, ErrInvalid
		}
		ipPolicyDigest = &digest
	}
	claims := Claims{
		Version: wire.Version, KeyID: wire.KeyID, Algorithm: wire.Algorithm,
		Operation: wire.Operation, Issuer: wire.Issuer, Receiver: wire.Receiver,
		AuthorizationID: wire.AuthorizationID, TeamID: wire.TeamID, IdentityID: wire.IdentityID, DomainID: wire.DomainID,
		CanonicalHostname: wire.CanonicalHostname, RouteScope: wire.RouteScope,
		PolicyRevision: wire.TeamPolicyRevision, CertificatePlan: wire.CertificatePlan,
		IssuedAt: wire.IssuedAt.UTC(), ExpiresAt: wire.ExpiresAt.UTC(), RetryID: wire.RetryID,
		RequestDigest: requestDigest, IPPolicyDigest: ipPolicyDigest,
	}
	if wire.MembershipID != nil {
		claims.MembershipID = *wire.MembershipID
	}
	if wire.RouteID != nil {
		claims.RouteID = *wire.RouteID
	}
	if wire.RouteVersion != nil {
		claims.RouteVersion = *wire.RouteVersion
	}
	now := v.now().UTC()
	canonicalHostname, hostnameErr := naming.CanonicalizeHostname(claims.CanonicalHostname)
	if claims.Version != 1 || claims.KeyID != v.keyID || claims.Algorithm != Algorithm ||
		claims.Issuer != v.issuer || claims.Receiver != v.receiver ||
		!validID(claims.AuthorizationID, "authorization") || !validID(claims.RetryID, "retry") ||
		!validID(claims.TeamID, "team") || !validID(claims.IdentityID, "identity") || !validID(claims.DomainID, "domain") ||
		hostnameErr != nil || canonicalHostname != claims.CanonicalHostname ||
		(claims.RouteScope != "member" && claims.RouteScope != "shared") ||
		claims.PolicyRevision == 0 || claims.PolicyRevision > math.MaxInt64 ||
		claims.IssuedAt.IsZero() || claims.ExpiresAt.IsZero() ||
		claims.IssuedAt.After(now.Add(AllowedClockSkew)) || claims.IssuedAt.Before(now.Add(-MaxLifetime)) ||
		!claims.ExpiresAt.After(now) || !claims.ExpiresAt.After(claims.IssuedAt) ||
		claims.ExpiresAt.Sub(claims.IssuedAt) > MaxLifetime {
		return Claims{}, ErrInvalid
	}
	if claims.MembershipID != "" && !validID(claims.MembershipID, "membership") ||
		claims.RouteScope == "member" && claims.MembershipID == "" {
		return Claims{}, ErrInvalid
	}
	switch claims.Operation {
	case OperationRouteCreate:
		if wire.RouteID != nil || wire.RouteVersion != nil || wire.CertificatePlan != nil {
			return Claims{}, ErrInvalid
		}
	case OperationRouteSessionCreate:
		if wire.RouteID == nil || !validID(claims.RouteID, "route") ||
			wire.RouteVersion == nil || claims.RouteVersion == 0 || claims.RouteVersion > math.MaxInt32 ||
			wire.CertificatePlan == nil || !validCertificatePlan(*wire.CertificatePlan, claims.CanonicalHostname) {
			return Claims{}, ErrInvalid
		}
	case OperationRouteDelete:
		if wire.RouteID == nil || !validID(claims.RouteID, "route") || wire.RouteVersion != nil || wire.CertificatePlan != nil {
			return Claims{}, ErrInvalid
		}
	default:
		return Claims{}, ErrInvalid
	}
	return claims, nil
}

// AuthenticateUserAssertion verifies one authority-issued access-token assertion.
func (v *Verifier) AuthenticateUserAssertion(token string) (UserAssertion, error) {
	payload, err := v.authenticate(token, UserAssertionType)
	if err != nil {
		return UserAssertion{}, err
	}
	var wire struct {
		Version       uint64 `json:"version"`
		KeyID         string `json:"kid"`
		Algorithm     string `json:"alg"`
		Issuer        string `json:"issuer"`
		Receiver      string `json:"receiver"`
		IdentityID    string `json:"identity_id"`
		Administrator bool   `json:"administrator"`
		Memberships   []struct {
			TeamID         string `json:"team_id"`
			MembershipID   string `json:"membership_id"`
			Role           string `json:"role"`
			PolicyRevision uint64 `json:"team_policy_revision"`
		} `json:"memberships"`
		IssuedAt  *time.Time `json:"issued_at"`
		ExpiresAt *time.Time `json:"expires_at"`
	}
	if err := decodeStrictObject(payload, &wire); err != nil || wire.IssuedAt == nil || wire.ExpiresAt == nil || len(wire.Memberships) > 1000 {
		return UserAssertion{}, ErrInvalid
	}
	assertion := UserAssertion{
		Version: wire.Version, KeyID: wire.KeyID, Algorithm: wire.Algorithm,
		Issuer: wire.Issuer, Receiver: wire.Receiver, IdentityID: wire.IdentityID,
		Administrator: wire.Administrator, IssuedAt: wire.IssuedAt.UTC(), ExpiresAt: wire.ExpiresAt.UTC(),
		Memberships: make([]UserAssertionMembership, len(wire.Memberships)),
	}
	if assertion.Version != 1 || assertion.KeyID != v.keyID || assertion.Algorithm != Algorithm ||
		assertion.Issuer != v.issuer || assertion.Receiver != v.receiver || !validID(assertion.IdentityID, "identity") ||
		!validTimes(assertion.IssuedAt, assertion.ExpiresAt, v.now().UTC()) {
		return UserAssertion{}, ErrInvalid
	}
	teams := make(map[string]struct{}, len(wire.Memberships))
	memberships := make(map[string]struct{}, len(wire.Memberships))
	for index, value := range wire.Memberships {
		if !validID(value.TeamID, "team") || !validID(value.MembershipID, "membership") ||
			(value.Role != "member" && value.Role != "admin" && value.Role != "owner") ||
			value.PolicyRevision == 0 || value.PolicyRevision > math.MaxInt64 {
			return UserAssertion{}, ErrInvalid
		}
		if _, duplicate := teams[value.TeamID]; duplicate {
			return UserAssertion{}, ErrInvalid
		}
		if _, duplicate := memberships[value.MembershipID]; duplicate {
			return UserAssertion{}, ErrInvalid
		}
		teams[value.TeamID] = struct{}{}
		memberships[value.MembershipID] = struct{}{}
		assertion.Memberships[index] = UserAssertionMembership{
			TeamID: value.TeamID, MembershipID: value.MembershipID, Role: value.Role,
			PolicyRevision: value.PolicyRevision,
		}
	}
	return assertion, nil
}

func (v *Verifier) authenticate(token, tokenType string) ([]byte, error) {
	if v == nil || token == "" || len(token) > MaxTokenBytes {
		return nil, ErrInvalid
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return nil, ErrInvalid
	}
	headerJSON, err := decodeBase64URL(parts[0])
	if err != nil {
		return nil, ErrInvalid
	}
	var header struct {
		Algorithm string `json:"alg"`
		KeyID     string `json:"kid"`
		Type      string `json:"typ"`
	}
	if err := decodeStrictObject(headerJSON, &header); err != nil ||
		header.Algorithm != Algorithm || header.KeyID != v.keyID || header.Type != tokenType {
		return nil, ErrInvalid
	}
	signature, err := decodeBase64URL(parts[2])
	if err != nil || len(signature) != ed25519.SignatureSize ||
		!ed25519.Verify(v.publicKey, []byte(parts[0]+"."+parts[1]), signature) {
		return nil, ErrInvalid
	}
	payload, err := decodeBase64URL(parts[1])
	if err != nil {
		return nil, ErrInvalid
	}
	return payload, nil
}

func validTimes(issuedAt, expiresAt, now time.Time) bool {
	return !issuedAt.IsZero() && !expiresAt.IsZero() && !issuedAt.After(now.Add(AllowedClockSkew)) &&
		!issuedAt.Before(now.Add(-MaxLifetime)) && expiresAt.After(now) && expiresAt.After(issuedAt) &&
		expiresAt.Sub(issuedAt) <= MaxLifetime
}

// Validate checks exact operation, resource, request, and policy bindings.
func (c Claims) Validate(expected Expected) error {
	if c.Operation != expected.Operation || c.TeamID != expected.TeamID || c.MembershipID != expected.MembershipID ||
		c.DomainID != expected.DomainID || c.CanonicalHostname != expected.CanonicalHostname || c.RouteScope != expected.RouteScope ||
		c.RouteID != expected.RouteID || c.RouteVersion != expected.RouteVersion ||
		c.PolicyRevision != expected.PolicyRevision || !sameCertificatePlan(c.CertificatePlan, expected.CertificatePlan) ||
		subtle.ConstantTimeCompare(c.RequestDigest[:], expected.RequestDigest[:]) != 1 ||
		!sameOptionalDigest(c.IPPolicyDigest, expected.IPPolicyDigest) {
		return ErrInvalid
	}
	if expected.Operation == OperationRouteCreate {
		if expected.RouteID != "" || expected.RouteVersion != 0 {
			return ErrInvalid
		}
	} else if expected.RouteID == "" || expected.Operation == OperationRouteSessionCreate && expected.RouteVersion == 0 {
		return ErrInvalid
	}
	return nil
}

func validCertificatePlan(plan CertificatePlan, hostname string) bool {
	if plan.CacheKey == "" || plan.Scope == "" || len(plan.Identifiers) == 0 || len(plan.Identifiers) > 2 ||
		(plan.ChallengeMethod != "dns-01" && plan.ChallengeMethod != "tls-alpn-01") {
		return false
	}
	hostnameCovered := false
	for _, identifier := range plan.Identifiers {
		canonical := identifier
		if strings.HasPrefix(identifier, "*.") {
			canonical = strings.TrimPrefix(identifier, "*.")
			if plan.ChallengeMethod != "dns-01" || !strings.HasSuffix(hostname, "."+canonical) {
				return false
			}
			hostnameCovered = true
		} else if identifier == hostname {
			hostnameCovered = true
		}
		parsed, err := naming.CanonicalizeHostname(canonical)
		if err != nil || parsed != canonical {
			return false
		}
	}
	return hostnameCovered
}

func sameCertificatePlan(left, right *CertificatePlan) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return left.CacheKey == right.CacheKey && left.Scope == right.Scope &&
		left.ChallengeMethod == right.ChallengeMethod && slices.Equal(left.Identifiers, right.Identifiers)
}

func ParseDigest(value string) (Digest, error) {
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || len(decoded) != sha256.Size || base64.RawURLEncoding.EncodeToString(decoded) != value {
		return Digest{}, ErrInvalid
	}
	return Digest(decoded), nil
}

func sameOptionalDigest(left, right *Digest) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return subtle.ConstantTimeCompare(left[:], right[:]) == 1
}

func decodeBase64URL(value string) ([]byte, error) {
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || base64.RawURLEncoding.EncodeToString(decoded) != value {
		return nil, ErrInvalid
	}
	return decoded, nil
}

func decodeStrictObject(data []byte, destination any) error {
	duplicateDecoder := json.NewDecoder(bytes.NewReader(data))
	token, err := duplicateDecoder.Token()
	if err != nil || token != json.Delim('{') {
		return ErrInvalid
	}
	seen := make(map[string]struct{})
	for duplicateDecoder.More() {
		name, err := duplicateDecoder.Token()
		key, ok := name.(string)
		if err != nil || !ok {
			return ErrInvalid
		}
		if _, exists := seen[key]; exists {
			return ErrInvalid
		}
		seen[key] = struct{}{}
		var value json.RawMessage
		if err := duplicateDecoder.Decode(&value); err != nil {
			return ErrInvalid
		}
	}
	if token, err := duplicateDecoder.Token(); err != nil || token != json.Delim('}') {
		return ErrInvalid
	}
	if token, err := duplicateDecoder.Token(); !errors.Is(err, io.EOF) || token != nil {
		return ErrInvalid
	}

	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return ErrInvalid
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return ErrInvalid
	}
	return nil
}

func validID(value, prefix string) bool {
	return opaqueid.Valid(value, prefix+"_")
}

func invalid(reason string) error { return fmt.Errorf("%w: %s", ErrInvalid, reason) }

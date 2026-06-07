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
	"strings"
	"time"

	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/opaqueid"
)

const (
	// Type is the required explicit type of an authorization JWS.
	Type = "tnl-authorization+jwt"

	Algorithm        = "EdDSA"
	MaxTokenBytes    = 4096
	MaxLifetime      = time.Hour
	AllowedClockSkew = 30 * time.Second
)

type Operation string

const (
	OperationRouteCreate        Operation = "route.create"
	OperationRouteSessionCreate Operation = "route_session.create"
	OperationRenew              Operation = "authorization.renew"
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
// RouteID and RouteVersion must both be empty for route.create and present otherwise.
type Expected struct {
	Operation            Operation
	Hostname             string
	RouteID              string
	RouteVersion         uint64
	CanonicalRequestHash Digest
	IPPolicyHash         *Digest
}

// Claims are authenticated authority claims. Callers using Authenticate must call
// Validate before using the claims to mutate state.
type Claims struct {
	Version              uint64
	KeyID                string
	Algorithm            string
	Operation            Operation
	Issuer               string
	Receiver             string
	AuthorizationID      string
	Hostname             string
	RouteID              string
	RouteVersion         uint64
	Revision             uint64
	IssuedAt             time.Time
	ExpiresAt            time.Time
	RetryID              string
	CanonicalRequestHash Digest
	IPPolicyHash         *Digest
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
	if v == nil || token == "" || len(token) > MaxTokenBytes {
		return Claims{}, ErrInvalid
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return Claims{}, ErrInvalid
	}
	headerJSON, err := decodeBase64URL(parts[0])
	if err != nil {
		return Claims{}, ErrInvalid
	}
	var header struct {
		Algorithm string `json:"alg"`
		KeyID     string `json:"kid"`
		Type      string `json:"typ"`
	}
	if err := decodeStrictObject(headerJSON, &header); err != nil ||
		header.Algorithm != Algorithm || header.KeyID != v.keyID || header.Type != Type {
		return Claims{}, ErrInvalid
	}
	signature, err := decodeBase64URL(parts[2])
	if err != nil || len(signature) != ed25519.SignatureSize ||
		!ed25519.Verify(v.publicKey, []byte(parts[0]+"."+parts[1]), signature) {
		return Claims{}, ErrInvalid
	}
	payload, err := decodeBase64URL(parts[1])
	if err != nil {
		return Claims{}, ErrInvalid
	}
	var wire struct {
		Version              uint64     `json:"version"`
		KeyID                string     `json:"kid"`
		Algorithm            string     `json:"alg"`
		Operation            Operation  `json:"operation"`
		Issuer               string     `json:"issuer"`
		Receiver             string     `json:"receiver"`
		AuthorizationID      string     `json:"authorization_id"`
		Hostname             string     `json:"hostname"`
		RouteID              *string    `json:"route_id,omitempty"`
		RouteVersion         *uint64    `json:"route_version,omitempty"`
		Revision             uint64     `json:"revision"`
		IssuedAt             *time.Time `json:"issued_at"`
		ExpiresAt            *time.Time `json:"expires_at"`
		RetryID              string     `json:"retry_id"`
		CanonicalRequestHash string     `json:"canonical_request_hash"`
		IPPolicyHash         *string    `json:"ip_policy_hash,omitempty"`
	}
	if err := decodeStrictObject(payload, &wire); err != nil || wire.IssuedAt == nil || wire.ExpiresAt == nil {
		return Claims{}, ErrInvalid
	}
	requestHash, err := ParseDigest(wire.CanonicalRequestHash)
	if err != nil {
		return Claims{}, ErrInvalid
	}
	var ipPolicyHash *Digest
	if wire.IPPolicyHash != nil {
		digest, err := ParseDigest(*wire.IPPolicyHash)
		if err != nil {
			return Claims{}, ErrInvalid
		}
		ipPolicyHash = &digest
	}
	claims := Claims{
		Version: wire.Version, KeyID: wire.KeyID, Algorithm: wire.Algorithm,
		Operation: wire.Operation, Issuer: wire.Issuer, Receiver: wire.Receiver,
		AuthorizationID: wire.AuthorizationID, Hostname: wire.Hostname,
		Revision: wire.Revision, IssuedAt: wire.IssuedAt.UTC(), ExpiresAt: wire.ExpiresAt.UTC(),
		RetryID: wire.RetryID, CanonicalRequestHash: requestHash, IPPolicyHash: ipPolicyHash,
	}
	if wire.RouteID != nil {
		claims.RouteID = *wire.RouteID
	}
	if wire.RouteVersion != nil {
		claims.RouteVersion = *wire.RouteVersion
	}
	now := v.now().UTC()
	canonicalHostname, hostnameErr := naming.CanonicalizeHostname(claims.Hostname)
	if claims.Version != 1 || claims.KeyID != v.keyID || claims.Algorithm != Algorithm ||
		claims.Issuer != v.issuer || claims.Receiver != v.receiver ||
		!validID(claims.AuthorizationID, "authorization") || !validID(claims.RetryID, "retry") ||
		hostnameErr != nil || canonicalHostname != claims.Hostname ||
		claims.Revision == 0 || claims.Revision > math.MaxInt64 ||
		claims.IssuedAt.IsZero() || claims.ExpiresAt.IsZero() ||
		claims.IssuedAt.After(now.Add(AllowedClockSkew)) || claims.IssuedAt.Before(now.Add(-MaxLifetime)) ||
		!claims.ExpiresAt.After(now) || !claims.ExpiresAt.After(claims.IssuedAt) ||
		claims.ExpiresAt.Sub(claims.IssuedAt) > MaxLifetime {
		return Claims{}, ErrInvalid
	}
	switch claims.Operation {
	case OperationRouteCreate:
		if wire.RouteID != nil || wire.RouteVersion != nil {
			return Claims{}, ErrInvalid
		}
	case OperationRouteSessionCreate, OperationRenew:
		if wire.RouteID == nil || !validID(claims.RouteID, "route") ||
			wire.RouteVersion == nil || claims.RouteVersion == 0 || claims.RouteVersion > math.MaxInt32 {
			return Claims{}, ErrInvalid
		}
	default:
		return Claims{}, ErrInvalid
	}
	return claims, nil
}

// Validate checks exact operation, resource, request, and policy bindings.
func (c Claims) Validate(expected Expected) error {
	if c.Operation != expected.Operation || c.Hostname != expected.Hostname ||
		c.RouteID != expected.RouteID || c.RouteVersion != expected.RouteVersion ||
		subtle.ConstantTimeCompare(c.CanonicalRequestHash[:], expected.CanonicalRequestHash[:]) != 1 ||
		!sameOptionalDigest(c.IPPolicyHash, expected.IPPolicyHash) {
		return ErrInvalid
	}
	if expected.Operation == OperationRouteCreate {
		if expected.RouteID != "" || expected.RouteVersion != 0 {
			return ErrInvalid
		}
	} else if expected.RouteID == "" || expected.RouteVersion == 0 {
		return ErrInvalid
	}
	return nil
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

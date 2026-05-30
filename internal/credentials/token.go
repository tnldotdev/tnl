package credentials

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
)

const (
	accessPrefix  = "tnl_access_"
	loginPrefix   = "tnl_login_"
	refreshPrefix = "tnl_refresh_"
	routePrefix   = "tnl_route_"
	sessionPrefix = "tnl_session_"
	workerPrefix  = "tnl_worker_"
	servicePrefix = "tnl_service_"
	lookupBytes   = 16
	secretBytes   = 32
)

var (
	// ErrInvalidAccessToken is returned for malformed or rejected access tokens.
	ErrInvalidAccessToken = errors.New("invalid access token")
	// ErrInvalidLoginToken is returned for malformed login tokens.
	ErrInvalidLoginToken = errors.New("invalid login token")
	// ErrInvalidRefreshToken is returned for malformed or rejected refresh tokens.
	ErrInvalidRefreshToken = errors.New("invalid refresh token")
	// ErrInvalidRouteToken is returned for malformed or rejected route tokens.
	ErrInvalidRouteToken = errors.New("invalid route token")
	// ErrInvalidSessionToken is returned for malformed or rejected session tokens.
	ErrInvalidSessionToken = errors.New("invalid session token")
	// ErrInvalidWorkerToken is returned for malformed or rejected worker tokens.
	ErrInvalidWorkerToken = errors.New("invalid worker token")
	// ErrInvalidServiceToken is returned for malformed service tokens.
	ErrInvalidServiceToken = errors.New("invalid service token")
)

// AccessToken authenticates a identity to the tnl server API.
type AccessToken string

// LoginToken authenticates only to the standalone token exchange.
type LoginToken string

// RefreshToken rotates one control session's access and refresh credentials.
type RefreshToken string

// RouteToken authorizes session acquisition for one route.
type RouteToken string

// SessionToken authorizes operations on one session version.
type SessionToken string

// WorkerToken authenticates one worker session to an edge.
type WorkerToken string

// ServiceToken authenticates one service-to-service request.
type ServiceToken string

// CredentialID is the nonsecret lookup portion of a credential.
type CredentialID string

// SecretHash is the stored digest of a random token secret.
type SecretHash [sha256.Size]byte

// LoginVerifier is the verification material for one login token.
type LoginVerifier struct {
	id   CredentialID
	hash SecretHash
}

// WorkerVerifier is the nonsecret verification material for one worker token.
type WorkerVerifier struct {
	id   CredentialID
	hash SecretHash
}

// ID returns the nonsecret lookup ID for this worker credential.
func (v WorkerVerifier) ID() CredentialID { return v.id }

// ServiceVerifier is the nonsecret verification material for one service token.
type ServiceVerifier struct {
	id   CredentialID
	hash SecretHash
}

// NewAccessToken creates an access token and its storage values.
func NewAccessToken() (AccessToken, CredentialID, SecretHash, error) {
	token, lookupID, hash, err := newToken(accessPrefix)
	return AccessToken(token), lookupID, hash, err
}

// ParseAccessToken validates an access token and returns its storage lookup values.
func ParseAccessToken(token AccessToken) (CredentialID, SecretHash, error) {
	return parseToken(string(token), accessPrefix, ErrInvalidAccessToken)
}

// NewLoginToken creates a local login token.
func NewLoginToken() (LoginToken, error) {
	token, _, _, err := newToken(loginPrefix)
	return LoginToken(token), err
}

// ParseLoginToken validates a login token and returns its verifier.
func ParseLoginToken(token LoginToken) (LoginVerifier, error) {
	lookupID, hash, err := parseToken(string(token), loginPrefix, ErrInvalidLoginToken)
	return LoginVerifier{id: lookupID, hash: hash}, err
}

// NewRefreshToken creates a control-session refresh token and its storage values.
func NewRefreshToken() (RefreshToken, CredentialID, SecretHash, error) {
	token, lookupID, hash, err := newToken(refreshPrefix)
	return RefreshToken(token), lookupID, hash, err
}

// ParseRefreshToken validates a refresh token and returns its storage lookup values.
func ParseRefreshToken(token RefreshToken) (CredentialID, SecretHash, error) {
	return parseToken(string(token), refreshPrefix, ErrInvalidRefreshToken)
}

// NewRouteToken creates a route token and its storage values.
func NewRouteToken() (RouteToken, CredentialID, SecretHash, error) {
	token, lookupID, hash, err := newToken(routePrefix)
	return RouteToken(token), lookupID, hash, err
}

// ParseRouteToken validates a route token and returns its storage lookup values.
func ParseRouteToken(token RouteToken) (CredentialID, SecretHash, error) {
	return parseToken(string(token), routePrefix, ErrInvalidRouteToken)
}

// NewSessionToken creates a session token and its storage values.
func NewSessionToken() (SessionToken, CredentialID, SecretHash, error) {
	token, lookupID, hash, err := newToken(sessionPrefix)
	return SessionToken(token), lookupID, hash, err
}

// DeriveSessionToken deterministically derives a session credential for one
// authenticated retry. The route token remains the only secret input.
func DeriveSessionToken(routeToken RouteToken, retryContext string) (SessionToken, CredentialID, SecretHash, error) {
	_, _, err := ParseRouteToken(routeToken)
	if err != nil || retryContext == "" {
		return "", "", SecretHash{}, ErrInvalidRouteToken
	}
	routeSecret := validatedTokenSecret(routeToken.String(), routePrefix)
	idMAC := hmac.New(sha256.New, routeSecret)
	_, _ = idMAC.Write([]byte("tnl/session-id/v1\x00" + retryContext))
	lookupID := CredentialID(base64.RawURLEncoding.EncodeToString(idMAC.Sum(nil)[:lookupBytes]))
	secretMAC := hmac.New(sha256.New, routeSecret)
	_, _ = secretMAC.Write([]byte("tnl/session-secret/v1\x00" + retryContext))
	secret := secretMAC.Sum(nil)
	hash := sha256.Sum256(secret)
	token := sessionPrefix + lookupID.String() + "." + base64.RawURLEncoding.EncodeToString(secret)
	return SessionToken(token), lookupID, hash, nil
}

// DeriveSessionKeyMaterial derives secret process-independent key material
// without making it recoverable from the session hash stored in the database.
func DeriveSessionKeyMaterial(token SessionToken) ([secretBytes]byte, error) {
	if _, _, err := ParseSessionToken(token); err != nil {
		return [secretBytes]byte{}, err
	}
	secret := validatedTokenSecret(token.String(), sessionPrefix)
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write([]byte("tnl/ingress-key/v1"))
	var material [secretBytes]byte
	copy(material[:], mac.Sum(nil))
	return material, nil
}

// DeriveSessionSourceKey derives an edge-to-publisher source authentication key.
func DeriveSessionSourceKey(token SessionToken) ([secretBytes]byte, error) {
	if _, _, err := ParseSessionToken(token); err != nil {
		return [secretBytes]byte{}, err
	}
	secret := validatedTokenSecret(token.String(), sessionPrefix)
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write([]byte("tnl/source-auth-key/v1"))
	var material [secretBytes]byte
	copy(material[:], mac.Sum(nil))
	return material, nil
}

func validatedTokenSecret(token, prefix string) []byte {
	value, _ := strings.CutPrefix(token, prefix)
	_, encodedSecret, _ := strings.Cut(value, ".")
	secret, _ := base64.RawURLEncoding.DecodeString(encodedSecret)
	return secret
}

// ParseSessionToken validates a session token and returns its storage lookup values.
func ParseSessionToken(token SessionToken) (CredentialID, SecretHash, error) {
	return parseToken(string(token), sessionPrefix, ErrInvalidSessionToken)
}

// NewWorkerToken creates a worker token and its verifier.
func NewWorkerToken() (WorkerToken, WorkerVerifier, error) {
	token, lookupID, hash, err := newToken(workerPrefix)
	return WorkerToken(token), WorkerVerifier{id: lookupID, hash: hash}, err
}

// ParseWorkerToken validates a worker token and returns its verifier.
func ParseWorkerToken(token WorkerToken) (WorkerVerifier, error) {
	lookupID, hash, err := parseToken(string(token), workerPrefix, ErrInvalidWorkerToken)
	return WorkerVerifier{id: lookupID, hash: hash}, err
}

// NewServiceToken creates a service-to-service credential.
func NewServiceToken() (ServiceToken, ServiceVerifier, error) {
	token, lookupID, hash, err := newToken(servicePrefix)
	return ServiceToken(token), ServiceVerifier{id: lookupID, hash: hash}, err
}

// ParseServiceToken validates a service token and returns its verifier.
func ParseServiceToken(token ServiceToken) (ServiceVerifier, error) {
	lookupID, hash, err := parseToken(string(token), servicePrefix, ErrInvalidServiceToken)
	return ServiceVerifier{id: lookupID, hash: hash}, err
}

// Matches reports whether token matches this verifier.
func (v LoginVerifier) Matches(token LoginToken) bool {
	candidate, err := ParseLoginToken(token)
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(v.id), []byte(candidate.id)) == 1 &&
		SecretHashMatches(v.hash[:], candidate.hash)
}

// Matches reports whether token matches this verifier.
func (v WorkerVerifier) Matches(token WorkerToken) bool {
	candidate, err := ParseWorkerToken(token)
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(v.id), []byte(candidate.id)) == 1 &&
		SecretHashMatches(v.hash[:], candidate.hash)
}

// Matches reports whether token matches this verifier.
func (v ServiceVerifier) Matches(token ServiceToken) bool {
	candidate, err := ParseServiceToken(token)
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(v.id), []byte(candidate.id)) == 1 &&
		SecretHashMatches(v.hash[:], candidate.hash)
}

// String returns the serialized access token.
func (t AccessToken) String() string { return string(t) }

// String returns the serialized login token.
func (t LoginToken) String() string { return string(t) }

// String returns the serialized refresh token.
func (t RefreshToken) String() string { return string(t) }

// String returns the serialized route token.
func (t RouteToken) String() string { return string(t) }

// String returns the serialized session token.
func (t SessionToken) String() string { return string(t) }

// String returns the serialized worker token.
func (t WorkerToken) String() string { return string(t) }

// String returns the serialized service token.
func (t ServiceToken) String() string { return string(t) }

// String returns the nonsecret credential ID.
func (id CredentialID) String() string { return string(id) }

func newToken(prefix string) (token string, lookupID CredentialID, hash SecretHash, err error) {
	material := make([]byte, lookupBytes+secretBytes)
	if _, err := rand.Read(material); err != nil {
		return "", "", SecretHash{}, fmt.Errorf("generate credential: %w", err)
	}
	lookupID = CredentialID(base64.RawURLEncoding.EncodeToString(material[:lookupBytes]))
	secret := material[lookupBytes:]
	hash = sha256.Sum256(secret)
	token = prefix + lookupID.String() + "." + base64.RawURLEncoding.EncodeToString(secret)
	return token, lookupID, hash, nil
}

func parseToken(token, prefix string, invalid error) (CredentialID, SecretHash, error) {
	body, ok := strings.CutPrefix(token, prefix)
	if !ok {
		return "", SecretHash{}, invalid
	}
	encodedID, encodedSecret, ok := strings.Cut(body, ".")
	if !ok || strings.Contains(encodedSecret, ".") {
		return "", SecretHash{}, invalid
	}
	id, err := base64.RawURLEncoding.DecodeString(encodedID)
	if err != nil || len(id) != lookupBytes || base64.RawURLEncoding.EncodeToString(id) != encodedID {
		return "", SecretHash{}, invalid
	}
	secret, err := base64.RawURLEncoding.DecodeString(encodedSecret)
	if err != nil || len(secret) != secretBytes || base64.RawURLEncoding.EncodeToString(secret) != encodedSecret {
		return "", SecretHash{}, invalid
	}
	return CredentialID(encodedID), sha256.Sum256(secret), nil
}

// SecretHashMatches compares a stored digest without data-dependent timing.
func SecretHashMatches(stored []byte, candidate SecretHash) bool {
	return subtle.ConstantTimeCompare(stored, candidate[:]) == 1
}

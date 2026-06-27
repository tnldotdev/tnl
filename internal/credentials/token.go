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
	accessPrefix     = "tnl_access_"
	loginPrefix      = "tnl_login_"
	refreshPrefix    = "tnl_refresh_"
	sessionPrefix    = "tnl_session_"
	connectionPrefix = "tnl_connection_"
	servicePrefix    = "tnl_service_"
	enrollmentPrefix = "tnl_enrollment_"
	lookupBytes      = 16
	secretBytes      = 32
)

var (
	// ErrInvalidAccessToken is returned for malformed or rejected access tokens.
	ErrInvalidAccessToken = errors.New("invalid access token")
	// ErrInvalidLoginToken is returned for malformed login tokens.
	ErrInvalidLoginToken = errors.New("invalid login token")
	// ErrInvalidRefreshToken is returned for malformed or rejected refresh tokens.
	ErrInvalidRefreshToken = errors.New("invalid refresh token")
	// ErrInvalidSessionToken is returned for malformed or rejected session tokens.
	ErrInvalidSessionToken = errors.New("invalid session token")
	// ErrInvalidPublisherConnectionCredential is returned for malformed publisher connection credentials.
	ErrInvalidPublisherConnectionCredential = errors.New("invalid publisher connection credential")
	// ErrInvalidServiceToken is returned for malformed service tokens.
	ErrInvalidServiceToken = errors.New("invalid service token")
	// ErrInvalidServiceEnrollmentToken is returned for malformed service enrollment tokens.
	ErrInvalidServiceEnrollmentToken = errors.New("invalid service enrollment token")
)

// AccessToken authenticates a identity to the tnl server API.
type AccessToken string

// LoginToken authenticates only to the standalone token exchange.
type LoginToken string

// RefreshToken rotates one control session's access and refresh credentials.
type RefreshToken string

// SessionToken authorizes operations on one route version.
type SessionToken string

// PublisherConnectionCredential authorizes one publisher connection assignment claim.
type PublisherConnectionCredential string

// ServiceToken authenticates one service-to-service request.
type ServiceToken string

// ServiceEnrollmentToken authorizes service certificate enrollment.
type ServiceEnrollmentToken string

// CredentialID is the nonsecret lookup portion of a credential.
type CredentialID string

// SecretHash is the stored digest of a random token secret.
type SecretHash [sha256.Size]byte

// LoginVerifier is the verification material for one login token.
type LoginVerifier struct {
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

// NewSessionToken creates a session token and its storage values.
func NewSessionToken() (SessionToken, CredentialID, SecretHash, error) {
	token, lookupID, hash, err := newToken(sessionPrefix)
	return SessionToken(token), lookupID, hash, err
}

// DeriveSessionToken deterministically derives a session credential from the
// authenticated request so retrying the same idempotent mutation is stable.
func DeriveSessionToken(retrySecret []byte, retryContext string) (SessionToken, CredentialID, SecretHash, error) {
	if len(retrySecret) < secretBytes || retryContext == "" {
		return "", "", SecretHash{}, ErrInvalidSessionToken
	}
	idMAC := hmac.New(sha256.New, retrySecret)
	_, _ = idMAC.Write([]byte("tnl/session-id/v1\x00" + retryContext))
	lookupID := CredentialID(base64.RawURLEncoding.EncodeToString(idMAC.Sum(nil)[:lookupBytes]))
	secretMAC := hmac.New(sha256.New, retrySecret)
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

// NewPublisherConnectionCredential creates an opaque credential for one publisher connection assignment.
func NewPublisherConnectionCredential() (PublisherConnectionCredential, SecretHash, error) {
	token, _, hash, err := newToken(connectionPrefix)
	return PublisherConnectionCredential(token), hash, err
}

// ParsePublisherConnectionCredential validates a publisher connection credential and returns its storage digest.
func ParsePublisherConnectionCredential(credential PublisherConnectionCredential) (SecretHash, error) {
	_, hash, err := parseToken(string(credential), connectionPrefix, ErrInvalidPublisherConnectionCredential)
	return hash, err
}

// DerivePublisherConnectionCredential deterministically derives one assignment credential
// from its route-session token so retrying session setup returns the same secret.
func DerivePublisherConnectionCredential(sessionToken SessionToken, assignmentContext string) (PublisherConnectionCredential, SecretHash, error) {
	if _, _, err := ParseSessionToken(sessionToken); err != nil || assignmentContext == "" {
		return "", SecretHash{}, ErrInvalidSessionToken
	}
	sessionSecret := validatedTokenSecret(sessionToken.String(), sessionPrefix)
	idMAC := hmac.New(sha256.New, sessionSecret)
	_, _ = idMAC.Write([]byte("tnl/publisher-connection-id/v1\x00" + assignmentContext))
	lookupID := CredentialID(base64.RawURLEncoding.EncodeToString(idMAC.Sum(nil)[:lookupBytes]))
	secretMAC := hmac.New(sha256.New, sessionSecret)
	_, _ = secretMAC.Write([]byte("tnl/publisher-connection-secret/v1\x00" + assignmentContext))
	secret := secretMAC.Sum(nil)
	hash := sha256.Sum256(secret)
	credential := connectionPrefix + lookupID.String() + "." + base64.RawURLEncoding.EncodeToString(secret)
	return PublisherConnectionCredential(credential), hash, nil
}

// NewServiceToken creates a service-to-service credential.
func NewServiceToken() (ServiceToken, error) {
	token, _, _, err := newToken(servicePrefix)
	return ServiceToken(token), err
}

// ParseServiceToken validates a service token.
func ParseServiceToken(token ServiceToken) error {
	_, _, err := parseToken(string(token), servicePrefix, ErrInvalidServiceToken)
	return err
}

// NewServiceEnrollmentToken creates a reusable enrollment token and its storage values.
func NewServiceEnrollmentToken() (ServiceEnrollmentToken, CredentialID, SecretHash, error) {
	token, lookupID, hash, err := newToken(enrollmentPrefix)
	return ServiceEnrollmentToken(token), lookupID, hash, err
}

// ParseServiceEnrollmentToken validates an enrollment token and returns its storage values.
func ParseServiceEnrollmentToken(token ServiceEnrollmentToken) (CredentialID, SecretHash, error) {
	return parseToken(string(token), enrollmentPrefix, ErrInvalidServiceEnrollmentToken)
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

// String returns the serialized access token.
func (t AccessToken) String() string { return string(t) }

// String returns the serialized login token.
func (t LoginToken) String() string { return string(t) }

// String returns the serialized refresh token.
func (t RefreshToken) String() string { return string(t) }

// String returns the serialized session token.
func (t SessionToken) String() string { return string(t) }

// String returns the serialized publisher connection credential.
func (t PublisherConnectionCredential) String() string { return string(t) }

// String returns the serialized service token.
func (t ServiceToken) String() string { return string(t) }

// String returns the serialized service enrollment token.
func (t ServiceEnrollmentToken) String() string { return string(t) }

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

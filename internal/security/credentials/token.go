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
	refreshPrefix    = "tnl_refresh_"
	invitationPrefix = "tnl_invitation_"
	sessionPrefix    = "tnl_session_"
	connectionPrefix = "tnl_connection_"
	lookupBytes      = 16
	secretBytes      = 32
)

var (
	// ErrInvalidAccessToken is returned for malformed or rejected access tokens.
	ErrInvalidAccessToken = errors.New("invalid access token")
	// ErrInvalidRefreshToken is returned for malformed or rejected refresh tokens.
	ErrInvalidRefreshToken = errors.New("invalid refresh token")
	// ErrInvalidInvitationToken is returned for malformed or rejected invitation tokens.
	ErrInvalidInvitationToken = errors.New("invalid invitation token")
	// ErrInvalidPublishRunToken is returned for malformed or rejected publish run tokens.
	ErrInvalidPublishRunToken = errors.New("invalid publish run token")
	// ErrInvalidPublisherConnectionCredential is returned for malformed publisher connection credentials.
	ErrInvalidPublisherConnectionCredential = errors.New("invalid publisher connection credential")
)

// AccessToken authenticates an identity to the tnl server API.
type AccessToken string

// RefreshToken rotates one control session's access and refresh credentials.
type RefreshToken string

// InvitationToken authorizes accepting one team invitation.
type InvitationToken string

// PublishRunToken authorizes operations on one publish run.
type PublishRunToken string

// PublisherConnectionCredential authorizes one publisher connection assignment claim.
type PublisherConnectionCredential string

// CredentialID is the nonsecret lookup portion of a credential.
type CredentialID string

// SecretHash is the stored digest of a random token secret.
type SecretHash [sha256.Size]byte

// NewAccessToken creates an access token and its storage values.
func NewAccessToken() (AccessToken, CredentialID, SecretHash, error) {
	token, lookupID, hash, err := newToken(accessPrefix)
	return AccessToken(token), lookupID, hash, err
}

// ParseAccessToken validates an access token and returns its storage lookup values.
func ParseAccessToken(token AccessToken) (CredentialID, SecretHash, error) {
	return parseToken(string(token), accessPrefix, ErrInvalidAccessToken)
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

// NewInvitationToken creates a one-time team invitation token.
func NewInvitationToken() (InvitationToken, SecretHash, error) {
	token, _, hash, err := newToken(invitationPrefix)
	return InvitationToken(token), hash, err
}

// DeriveInvitationToken returns the same one-time invitation secret when a
// request is retried with the same secret and context.
func DeriveInvitationToken(retrySecret []byte, retryContext string) (InvitationToken, SecretHash, error) {
	if len(retrySecret) < secretBytes || retryContext == "" {
		return "", SecretHash{}, ErrInvalidInvitationToken
	}
	idMAC := hmac.New(sha256.New, retrySecret)
	_, _ = idMAC.Write([]byte("tnl/invitation-id/v1\x00" + retryContext))
	lookupID := CredentialID(base64.RawURLEncoding.EncodeToString(idMAC.Sum(nil)[:lookupBytes]))
	secretMAC := hmac.New(sha256.New, retrySecret)
	_, _ = secretMAC.Write([]byte("tnl/invitation-secret/v1\x00" + retryContext))
	secret := secretMAC.Sum(nil)
	hash := sha256.Sum256(secret)
	token := invitationPrefix + lookupID.String() + "." + base64.RawURLEncoding.EncodeToString(secret)
	return InvitationToken(token), hash, nil
}

// ParseInvitationToken validates an invitation token and returns its stored digest.
func ParseInvitationToken(token InvitationToken) (SecretHash, error) {
	_, hash, err := parseToken(string(token), invitationPrefix, ErrInvalidInvitationToken)
	return hash, err
}

// NewPublishRunToken creates a publish run token and its storage values.
func NewPublishRunToken() (PublishRunToken, CredentialID, SecretHash, error) {
	token, lookupID, hash, err := newToken(sessionPrefix)
	return PublishRunToken(token), lookupID, hash, err
}

// DerivePublishRunToken returns the same publish run token when a request is
// retried with the same secret and context.
func DerivePublishRunToken(retrySecret []byte, retryContext string) (PublishRunToken, CredentialID, SecretHash, error) {
	if len(retrySecret) < secretBytes || retryContext == "" {
		return "", "", SecretHash{}, ErrInvalidPublishRunToken
	}
	idMAC := hmac.New(sha256.New, retrySecret)
	_, _ = idMAC.Write([]byte("tnl/session-id/v1\x00" + retryContext))
	lookupID := CredentialID(base64.RawURLEncoding.EncodeToString(idMAC.Sum(nil)[:lookupBytes]))
	secretMAC := hmac.New(sha256.New, retrySecret)
	_, _ = secretMAC.Write([]byte("tnl/session-secret/v1\x00" + retryContext))
	secret := secretMAC.Sum(nil)
	hash := sha256.Sum256(secret)
	token := sessionPrefix + lookupID.String() + "." + base64.RawURLEncoding.EncodeToString(secret)
	return PublishRunToken(token), lookupID, hash, nil
}

func validatedTokenSecret(token, prefix string) []byte {
	value, _ := strings.CutPrefix(token, prefix)
	_, encodedSecret, _ := strings.Cut(value, ".")
	secret, _ := base64.RawURLEncoding.DecodeString(encodedSecret)
	return secret
}

// ParsePublishRunToken validates a publish run token and returns its storage lookup values.
func ParsePublishRunToken(token PublishRunToken) (CredentialID, SecretHash, error) {
	return parseToken(string(token), sessionPrefix, ErrInvalidPublishRunToken)
}

// NewPublisherConnectionCredential creates a credential for one connection assignment.
func NewPublisherConnectionCredential() (PublisherConnectionCredential, SecretHash, error) {
	token, _, hash, err := newToken(connectionPrefix)
	return PublisherConnectionCredential(token), hash, err
}

// ParsePublisherConnectionCredential validates a publisher connection
// credential and returns its stored hash.
func ParsePublisherConnectionCredential(credential PublisherConnectionCredential) (SecretHash, error) {
	_, hash, err := parseToken(string(credential), connectionPrefix, ErrInvalidPublisherConnectionCredential)
	return hash, err
}

// DerivePublisherConnectionCredential returns the same assignment credential
// for the same publish run token and assignment context.
func DerivePublisherConnectionCredential(publishRunToken PublishRunToken, assignmentContext string) (PublisherConnectionCredential, SecretHash, error) {
	if _, _, err := ParsePublishRunToken(publishRunToken); err != nil || assignmentContext == "" {
		return "", SecretHash{}, ErrInvalidPublishRunToken
	}
	sessionSecret := validatedTokenSecret(publishRunToken.String(), sessionPrefix)
	return deriveConnectionCredential(sessionSecret, assignmentContext)
}

func deriveConnectionCredential(sessionSecret []byte, assignmentContext string) (PublisherConnectionCredential, SecretHash, error) {
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

// String returns the serialized access token.
func (t AccessToken) String() string { return string(t) }

// String returns the serialized refresh token.
func (t RefreshToken) String() string { return string(t) }

// String returns the serialized invitation token.
func (t InvitationToken) String() string { return string(t) }

// String returns the serialized publish run token.
func (t PublishRunToken) String() string { return string(t) }

// String returns the serialized publisher connection credential.
func (t PublisherConnectionCredential) String() string { return string(t) }

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

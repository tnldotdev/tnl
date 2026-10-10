package credentials

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
)

const (
	accessPrefix              = "tnl_access_"
	loginPrefix               = "tnl_login_"
	refreshPrefix             = "tnl_refresh_"
	invitationPrefix          = "tnl_invitation_"
	sessionPrefix             = "tnl_session_"
	connectionPrefix          = "tnl_connection_"
	publishCredentialPrefix   = "tnl_url_"
	ephemeralCredentialPrefix = "tnl_eph_"
	lookupBytes               = 16
	secretBytes               = 32
)

var (
	// ErrInvalidAccessToken is returned for malformed or rejected access tokens.
	ErrInvalidAccessToken = errors.New("invalid access token")
	// ErrInvalidLoginToken is returned for malformed login tokens.
	ErrInvalidLoginToken = errors.New("invalid login token")
	// ErrInvalidRefreshToken is returned for malformed or rejected refresh tokens.
	ErrInvalidRefreshToken = errors.New("invalid refresh token")
	// ErrInvalidInvitationToken is returned for malformed or rejected invitation tokens.
	ErrInvalidInvitationToken = errors.New("invalid invitation token")
	// ErrInvalidPublishRunToken is returned for malformed or rejected publish run tokens.
	ErrInvalidPublishRunToken = errors.New("invalid publish run token")
	// ErrInvalidPublisherConnectionCredential is returned for malformed publisher connection credentials.
	ErrInvalidPublisherConnectionCredential = errors.New("invalid publisher connection credential")
	ErrInvalidPublicURLPublishCredential    = errors.New("invalid public URL publish credential")
	ErrInvalidEphemeralCredential           = errors.New("invalid ephemeral public URL credential")
)

// AccessToken authenticates an identity to the tnl server API.
type AccessToken string

// LoginToken authenticates only to the built-in authority's token exchange.
type LoginToken string

// RefreshToken rotates one control session's access and refresh credentials.
type RefreshToken string

// InvitationToken authorizes accepting one team invitation.
type InvitationToken string

// PublishRunToken authorizes operations on one publish run.
type PublishRunToken string

// PublisherConnectionCredential authorizes one publisher connection assignment claim.
type PublisherConnectionCredential string

// PublicURLPublishCredential authorizes starting publish runs for one saved public URL.
type PublicURLPublishCredential string

// EphemeralCredential authorizes allocating and publishing ad-hoc public URLs.
type EphemeralCredential string

// CredentialID is the nonsecret lookup portion of a credential.
type CredentialID string

// SecretHash is the stored digest of a random token secret.
type SecretHash [sha256.Size]byte

// LoginVerifier is the verification material for one login token.
type LoginVerifier struct {
	id             CredentialID
	hash           SecretHash
	sourceRevision int64
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
	if err != nil {
		return LoginVerifier{}, err
	}
	return LoginVerifier{id: lookupID, hash: hash, sourceRevision: loginSourceRevision(token)}, nil
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

// NewPublicURLPublishCredential creates a revocable, public URL-scoped credential.
func NewPublicURLPublishCredential() (PublicURLPublishCredential, CredentialID, SecretHash, error) {
	token, id, hash, err := newToken(publishCredentialPrefix)
	return PublicURLPublishCredential(token), id, hash, err
}

// ParsePublicURLPublishCredential returns its lookup ID, verifier, and retry secret.
func ParsePublicURLPublishCredential(token PublicURLPublishCredential) (CredentialID, SecretHash, []byte, error) {
	id, hash, err := parseToken(string(token), publishCredentialPrefix, ErrInvalidPublicURLPublishCredential)
	if err != nil {
		return "", SecretHash{}, nil, err
	}
	return id, hash, validatedTokenSecret(string(token), publishCredentialPrefix), nil
}

// NewEphemeralCredential creates a revocable ad-hoc public URL credential.
func NewEphemeralCredential() (EphemeralCredential, CredentialID, SecretHash, error) {
	token, id, hash, err := newToken(ephemeralCredentialPrefix)
	return EphemeralCredential(token), id, hash, err
}

// ParseEphemeralCredential returns its lookup ID, verifier, and retry secret.
func ParseEphemeralCredential(token EphemeralCredential) (CredentialID, SecretHash, []byte, error) {
	id, hash, err := parseToken(string(token), ephemeralCredentialPrefix, ErrInvalidEphemeralCredential)
	if err != nil {
		return "", SecretHash{}, nil, err
	}
	return id, hash, validatedTokenSecret(string(token), ephemeralCredentialPrefix), nil
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

// Matches reports whether token matches this verifier.
func (v LoginVerifier) Matches(token LoginToken) bool {
	candidate, err := ParseLoginToken(token)
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(v.id), []byte(candidate.id)) == 1 &&
		SecretHashMatches(v.hash[:], candidate.hash)
}

// SourceRevision identifies the login-token source used to issue sessions.
func (v LoginVerifier) SourceRevision() int64 { return v.sourceRevision }

// String returns the serialized access token.
func (t AccessToken) String() string { return string(t) }

// String returns the serialized login token.
func (t LoginToken) String() string { return string(t) }

// String returns the serialized refresh token.
func (t RefreshToken) String() string { return string(t) }

// String returns the serialized invitation token.
func (t InvitationToken) String() string { return string(t) }

// String returns the serialized publish run token.
func (t PublishRunToken) String() string { return string(t) }

// String returns the serialized publisher connection credential.
func (t PublisherConnectionCredential) String() string { return string(t) }

// String returns the serialized public URL publish credential.
func (t PublicURLPublishCredential) String() string { return string(t) }
func (t EphemeralCredential) String() string        { return string(t) }

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

func loginSourceRevision(token LoginToken) int64 {
	digest := sha256.Sum256([]byte(token))
	revision := int64(binary.BigEndian.Uint64(digest[:8]) & uint64(^uint64(0)>>1))
	if revision == 0 {
		return 1
	}
	return revision
}

// SecretHashMatches compares a stored digest without data-dependent timing.
func SecretHashMatches(stored []byte, candidate SecretHash) bool {
	return subtle.ConstantTimeCompare(stored, candidate[:]) == 1
}

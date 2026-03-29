// Package credentials creates and validates typed credentials.
package credentials

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
)

const (
	accessPrefix    = "tnl_access_"
	bootstrapPrefix = "tnl_bootstrap_"
	lookupBytes     = 16
	secretBytes     = 32
)

var (
	// ErrInvalidAccessToken is returned for malformed or rejected access tokens.
	ErrInvalidAccessToken = errors.New("invalid access token")
	// ErrInvalidBootstrapToken is returned for malformed bootstrap tokens.
	ErrInvalidBootstrapToken = errors.New("invalid bootstrap token")
)

// AccessToken authenticates a local principal to the standalone core API.
type AccessToken string

// BootstrapToken authenticates only to the standalone token exchange.
type BootstrapToken string

// CredentialID is the nonsecret lookup portion of a credential.
type CredentialID string

// SecretHash is the stored digest of a random token secret.
type SecretHash [sha256.Size]byte

// BootstrapVerifier is the verification material for one bootstrap token.
type BootstrapVerifier struct {
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

// NewBootstrapToken creates a deployment bootstrap token.
func NewBootstrapToken() (BootstrapToken, error) {
	token, _, _, err := newToken(bootstrapPrefix)
	return BootstrapToken(token), err
}

// ParseBootstrapToken validates a bootstrap token and returns its verifier.
func ParseBootstrapToken(token BootstrapToken) (BootstrapVerifier, error) {
	lookupID, hash, err := parseToken(string(token), bootstrapPrefix, ErrInvalidBootstrapToken)
	return BootstrapVerifier{id: lookupID, hash: hash}, err
}

// Matches reports whether token matches this verifier.
func (v BootstrapVerifier) Matches(token BootstrapToken) bool {
	candidate, err := ParseBootstrapToken(token)
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(v.id), []byte(candidate.id)) == 1 &&
		SecretHashMatches(v.hash[:], candidate.hash)
}

// String returns the serialized access token.
func (t AccessToken) String() string { return string(t) }

// String returns the serialized bootstrap token.
func (t BootstrapToken) String() string { return string(t) }

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

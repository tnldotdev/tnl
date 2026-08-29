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
	accessPrefix = "tnl_access_"
	lookupBytes  = 16
	secretBytes  = 32
)

// ErrInvalidAccessToken is returned for malformed or rejected access tokens.
var ErrInvalidAccessToken = errors.New("invalid access token")

// SecretHash is the stored digest of a random token secret.
type SecretHash [sha256.Size]byte

// NewAccessToken creates an access token and its storage values.
func NewAccessToken() (token, lookupID string, hash SecretHash, err error) {
	material := make([]byte, lookupBytes+secretBytes)
	if _, err := rand.Read(material); err != nil {
		return "", "", SecretHash{}, fmt.Errorf("generate access token: %w", err)
	}
	lookupID = base64.RawURLEncoding.EncodeToString(material[:lookupBytes])
	secret := material[lookupBytes:]
	hash = sha256.Sum256(secret)
	token = accessPrefix + lookupID + "." + base64.RawURLEncoding.EncodeToString(secret)
	return token, lookupID, hash, nil
}

// ParseAccessToken validates a token and returns its storage lookup values.
func ParseAccessToken(token string) (lookupID string, hash SecretHash, err error) {
	body, ok := strings.CutPrefix(token, accessPrefix)
	if !ok {
		return "", SecretHash{}, ErrInvalidAccessToken
	}
	encodedID, encodedSecret, ok := strings.Cut(body, ".")
	if !ok || strings.Contains(encodedSecret, ".") {
		return "", SecretHash{}, ErrInvalidAccessToken
	}
	id, err := base64.RawURLEncoding.DecodeString(encodedID)
	if err != nil || len(id) != lookupBytes || base64.RawURLEncoding.EncodeToString(id) != encodedID {
		return "", SecretHash{}, ErrInvalidAccessToken
	}
	secret, err := base64.RawURLEncoding.DecodeString(encodedSecret)
	if err != nil || len(secret) != secretBytes || base64.RawURLEncoding.EncodeToString(secret) != encodedSecret {
		return "", SecretHash{}, ErrInvalidAccessToken
	}
	return encodedID, sha256.Sum256(secret), nil
}

// SecretHashMatches compares a stored digest without data-dependent timing.
func SecretHashMatches(stored []byte, candidate SecretHash) bool {
	return subtle.ConstantTimeCompare(stored, candidate[:]) == 1
}

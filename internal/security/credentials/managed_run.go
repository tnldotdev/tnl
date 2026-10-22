package credentials

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
)

// ManagedRunToken authorizes one managed service run, independently of public
// URL publish run tokens and publisher connection derivation seeds.
type ManagedRunToken string

var ErrInvalidManagedRunToken = errors.New("invalid managed run token")

func (t ManagedRunToken) String() string { return string(t) }

func NewManagedRunToken() (ManagedRunToken, SecretHash, error) {
	var secret [secretBytes]byte
	if _, err := rand.Read(secret[:]); err != nil {
		return "", SecretHash{}, err
	}
	return ManagedRunToken(base64.RawURLEncoding.EncodeToString(secret[:])), sha256.Sum256(secret[:]), nil
}

// ParseManagedRunToken accepts only the existing canonical, unprefixed secret.
func ParseManagedRunToken(token ManagedRunToken) (SecretHash, error) {
	if len(token) != base64.RawURLEncoding.EncodedLen(secretBytes) {
		return SecretHash{}, ErrInvalidManagedRunToken
	}
	secret, err := base64.RawURLEncoding.Strict().DecodeString(token.String())
	if err != nil || len(secret) != secretBytes {
		return SecretHash{}, ErrInvalidManagedRunToken
	}
	return sha256.Sum256(secret), nil
}

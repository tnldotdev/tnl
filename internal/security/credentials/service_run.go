package credentials

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
)

// ServiceRunToken authorizes one service run, independently of public
// URL publish run tokens and publisher connection derivation seeds.
type ServiceRunToken string

var ErrInvalidServiceRunToken = errors.New("invalid managed run token")

func (t ServiceRunToken) String() string { return string(t) }

func NewServiceRunToken() (ServiceRunToken, SecretHash, error) {
	var secret [secretBytes]byte
	if _, err := rand.Read(secret[:]); err != nil {
		return "", SecretHash{}, err
	}
	return ServiceRunToken(base64.RawURLEncoding.EncodeToString(secret[:])), sha256.Sum256(secret[:]), nil
}

// ParseServiceRunToken accepts only the existing canonical, unprefixed secret.
func ParseServiceRunToken(token ServiceRunToken) (SecretHash, error) {
	if len(token) != base64.RawURLEncoding.EncodedLen(secretBytes) {
		return SecretHash{}, ErrInvalidServiceRunToken
	}
	secret, err := base64.RawURLEncoding.Strict().DecodeString(token.String())
	if err != nil || len(secret) != secretBytes {
		return SecretHash{}, ErrInvalidServiceRunToken
	}
	return sha256.Sum256(secret), nil
}

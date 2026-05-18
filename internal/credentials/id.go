package credentials

import (
	"encoding/base64"
	"errors"
)

// ErrInvalidCredentialID is returned for malformed credential lookup IDs.
var ErrInvalidCredentialID = errors.New("invalid credential ID")

// ParseCredentialID validates a canonical nonsecret credential lookup ID.
func ParseCredentialID(value string) (CredentialID, error) {
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || len(decoded) != lookupBytes || base64.RawURLEncoding.EncodeToString(decoded) != value {
		return "", ErrInvalidCredentialID
	}
	return CredentialID(value), nil
}

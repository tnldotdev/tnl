// Package opaqueid creates and validates opaque 128-bit identifiers.
package opaqueid

import (
	"crypto/rand"
	"encoding/hex"
)

const encodedLength = 32

// New returns prefix followed by 128 random bits encoded as lowercase hex.
func New(prefix string) (string, error) {
	var material [16]byte
	if _, err := rand.Read(material[:]); err != nil {
		return "", err
	}
	return prefix + hex.EncodeToString(material[:]), nil
}

// Valid reports whether value is prefix followed by exactly 32 lowercase hex characters.
func Valid(value, prefix string) bool {
	if len(value) != len(prefix)+encodedLength || value[:len(prefix)] != prefix {
		return false
	}
	for _, character := range value[len(prefix):] {
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}

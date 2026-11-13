package naming

import (
	"crypto/rand"
	"encoding/base32"
	"strings"
)

// RandomHostnameLabel encodes 128 random bits as 26 lowercase base32 characters.
// lifetime and visitor policy belong to the saved record, not this label.
func RandomHostnameLabel() (string, error) {
	var entropy [16]byte
	if _, err := rand.Read(entropy[:]); err != nil {
		return "", err
	}
	return strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(entropy[:])), nil
}

package naming

import (
	"crypto/rand"
	"encoding/base32"
	"io"
	"strings"
)

// RandomHostnameLabel encodes 128 random bits as 26 lowercase base32 characters.
// the label has no prefix or padding; lifetime is not encoded in a hostname.
func RandomHostnameLabel() (string, error) {
	return randomHostnameLabel(rand.Reader)
}

func randomHostnameLabel(source io.Reader) (string, error) {
	var entropy [16]byte
	if _, err := io.ReadFull(source, entropy[:]); err != nil {
		return "", err
	}
	return strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(entropy[:])), nil
}

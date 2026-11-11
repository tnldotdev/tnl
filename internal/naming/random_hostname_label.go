package naming

import (
	"encoding/base32"
	"strings"
)

// ValidRandomHostnameLabel accepts the canonical lowercase, unpadded base32
// encoding of exactly 128 bits. it checks the representation, not its entropy.
func ValidRandomHostnameLabel(label string) bool {
	if len(label) != 26 || strings.ToLower(label) != label {
		return false
	}
	encoding := base32.StdEncoding.WithPadding(base32.NoPadding)
	value, err := encoding.DecodeString(strings.ToUpper(label))
	return err == nil && len(value) == 16 && strings.ToLower(encoding.EncodeToString(value)) == label
}

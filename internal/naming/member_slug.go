package naming

import (
	"strings"
	"unicode"

	"golang.org/x/text/unicode/norm"
)

// ValidAuthorityLabel checks one lowercase ASCII DNS label without normalization.
func ValidAuthorityLabel(value string) bool {
	canonical, err := CanonicalizeHostname(value)
	return err == nil && canonical == value && len(value) <= MaxLabelBytes && !strings.Contains(value, ".")
}

// MemberSlugFromDisplayName makes a stable candidate from one identity name.
// an empty result means the caller needs an explicit slug or a fallback.
func MemberSlugFromDisplayName(name string) string {
	var slug strings.Builder
	separator := false
	for _, character := range norm.NFKD.String(name) {
		if unicode.Is(unicode.Mn, character) {
			continue
		}
		character = unicode.ToLower(character)
		if character >= 'a' && character <= 'z' || character >= '0' && character <= '9' {
			if separator && slug.Len() > 0 && slug.Len() < MaxLabelBytes-1 {
				slug.WriteByte('-')
			}
			if slug.Len() == MaxLabelBytes {
				break
			}
			slug.WriteByte(byte(character))
			separator = false
		} else if slug.Len() != 0 {
			separator = true
		}
	}
	return slug.String()
}

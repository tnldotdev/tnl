package naming

import (
	"encoding/base32"
	"regexp"
	"strings"
	"testing"
)

func TestRandomHostnameLabelsEncode128BitsWithoutLifetimePrefix(t *testing.T) {
	pattern := regexp.MustCompile(`^[a-z2-7]{26}$`)
	for range 128 {
		label, err := RandomHostnameLabel()
		if err != nil {
			t.Fatal(err)
		}
		if !pattern.MatchString(label) {
			t.Fatal("random label has padding, prefix, or wrong alphabet", label)
		}
		data, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(label))
		if err != nil || len(data) != 16 {
			t.Fatal("random label lost entropy", err)
		}
		if canonical, err := CanonicalizeHostname(label + ".example.test"); err != nil || canonical != label+".example.test" {
			t.Fatal("random label is not a canonical DNS label", err)
		}
	}
}

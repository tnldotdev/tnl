package naming

import (
	"bytes"
	"encoding/base32"
	"errors"
	"io"
	"regexp"
	"strings"
	"testing"
)

func TestRandomHostnameLabelPreservesEveryEntropyBit(t *testing.T) {
	seen := make(map[string]bool)
	for bit := -1; bit < 128; bit++ {
		var entropy [16]byte
		if bit >= 0 {
			entropy[bit/8] = 1 << (bit % 8)
		}
		label, err := randomHostnameLabel(bytes.NewReader(entropy[:]))
		if err != nil {
			t.Fatal(err)
		}
		if !regexp.MustCompile(`^[a-z2-7]{26}$`).MatchString(label) || seen[label] {
			t.Fatalf("prefixed, truncated, or duplicate label: %q", label)
		}
		seen[label] = true
		decoded, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(label))
		if err != nil || !bytes.Equal(decoded, entropy[:]) {
			t.Fatalf("lost entropy at bit %d: %x %v", bit, decoded, err)
		}
		if canonical, err := CanonicalizeHostname(label + ".example.test"); err != nil || canonical != label+".example.test" {
			t.Fatalf("invalid hostname label: %q %v", label, err)
		}
	}
}

func TestRandomHostnameLabelRejectsIncompleteEntropy(t *testing.T) {
	label, err := randomHostnameLabel(bytes.NewReader(make([]byte, 15)))
	if label != "" || !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("partial entropy: %q %v", label, err)
	}
}

func TestRandomHostnameLabelsAreFreshAndPrefixFree(t *testing.T) {
	seen := make(map[string]bool)
	for range 256 {
		label, err := RandomHostnameLabel()
		if err != nil || !regexp.MustCompile(`^[a-z2-7]{26}$`).MatchString(label) || seen[label] {
			t.Fatalf("invalid or repeated random label: %q %v", label, err)
		}
		seen[label] = true
	}
}

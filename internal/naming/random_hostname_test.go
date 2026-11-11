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
	shape := regexp.MustCompile(`^[a-z2-7]{25}[aeimquy4]$`)
	seen := map[string]bool{}
	for bit := -1; bit < 128; bit++ {
		var entropy [16]byte
		if bit >= 0 {
			entropy[bit/8] = 1 << (bit % 8)
		}
		label, err := randomHostnameLabel(bytes.NewReader(entropy[:]))
		if err != nil {
			t.Fatal(err)
		}
		if !shape.MatchString(label) || seen[label] {
			t.Fatalf("noncanonical or repeated label at bit %d: %q", bit, label)
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

func TestRandomHostnameLabelKnownEncodings(t *testing.T) {
	for _, tc := range []struct {
		value byte
		want  string
	}{
		{0, strings.Repeat("a", 26)},
		{255, strings.Repeat("7", 25) + "4"},
	} {
		label, err := randomHostnameLabel(bytes.NewReader(bytes.Repeat([]byte{tc.value}, 16)))
		if err != nil || label != tc.want {
			t.Fatalf("byte %d encoded as %q: %v; want %q", tc.value, label, err, tc.want)
		}
	}
}

func TestRandomHostnameLabelRejectsIncompleteEntropy(t *testing.T) {
	for size := range 16 {
		label, err := randomHostnameLabel(bytes.NewReader(make([]byte, size)))
		if label != "" || !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
			t.Fatalf("partial entropy (%d bytes): %q %v", size, label, err)
		}
	}
}

func TestRandomHostnameLabelsAreFresh(t *testing.T) {
	shape := regexp.MustCompile(`^[a-z2-7]{25}[aeimquy4]$`)
	seen := map[string]bool{}
	for range 256 {
		label, err := RandomHostnameLabel()
		if err != nil || !shape.MatchString(label) || seen[label] {
			t.Fatalf("invalid or repeated label: %q %v", label, err)
		}
		seen[label] = true
	}
}

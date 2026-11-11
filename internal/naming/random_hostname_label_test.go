package naming

import (
	"encoding/base32"
	"strings"
	"testing"
)

func TestRandomHostnameLabelValidatesEncodingWithoutInferringEntropy(t *testing.T) {
	encoding := base32.StdEncoding.WithPadding(base32.NoPadding)
	for _, value := range [][16]byte{{}, {0xff, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc}} {
		label := strings.ToLower(encoding.EncodeToString(value[:]))
		if !ValidRandomHostnameLabel(label) {
			t.Fatalf("canonical 128-bit encoding rejected: %q", label)
		}
	}
	// predictable all-zero bits still have a valid representation. randomness
	// belongs to the generator; a consumer cannot prove it from a returned label.
	zero := strings.Repeat("a", 26)
	for _, label := range []string{
		"", "random", "eph-" + zero, zero[:25], zero + "a", strings.ToUpper(zero),
		zero[:25] + "b", zero[:25] + "7", zero[:25] + "0", zero + "=", zero[:12] + "." + zero[13:],
	} {
		if ValidRandomHostnameLabel(label) {
			t.Fatalf("noncanonical encoding accepted: %q", label)
		}
	}
}

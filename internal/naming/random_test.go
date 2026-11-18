package naming

import (
	"encoding/base32"
	"errors"
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

func TestRandomHostnamesUseResourceKindsAndSharedLabelFormat(t *testing.T) {
	seen := map[string]bool{}
	for _, kind := range []HostnameKind{ServiceHostnameKind, PublisherHostnameKind} {
		pattern := regexp.MustCompile(`^` + string(kind) + `-([a-z2-7]{26})\.example\.test$`)
		for range 128 {
			hostname, err := RandomHostname(kind, "example.test")
			match := pattern.FindStringSubmatch(hostname)
			if err != nil || len(match) != 2 || seen[hostname] {
				t.Fatal("generated hostname has an invalid kind, label, or duplicate", hostname, err)
			}
			seen[hostname] = true
			raw, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(match[1]))
			if err != nil || len(raw) != 16 {
				t.Fatal("generated hostname lost its 128-bit label", err)
			}
			if canonical, err := CanonicalizeHostname(hostname); err != nil || canonical != hostname {
				t.Fatal("generated hostname is not canonical", err)
			}
		}
	}
}

func TestRandomHostnamesRejectInvalidKindsAndParents(t *testing.T) {
	for _, parent := range []string{"", "Example.test", "*.example.test", "example.test.", "https://example.test", "example.test:443",
		strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 35)} {
		if _, err := RandomHostname(ServiceHostnameKind, parent); !errors.Is(err, ErrGeneratedHostname) {
			t.Fatal("invalid or overlong parent accepted", parent, err)
		}
	}
	for _, kind := range []HostnameKind{"", "ephemeral", "s-", "s.example", "R"} {
		if _, err := RandomHostname(kind, "example.test"); !errors.Is(err, ErrGeneratedHostname) {
			t.Fatal("invalid hostname kind accepted", kind, err)
		}
	}
	parent := strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 32)
	hostname, err := RandomHostname(ServiceHostnameKind, parent)
	if err != nil || len(hostname) != MaxHostnameBytes {
		t.Fatal("maximum valid hostname length was rejected", len(hostname), err)
	}
}

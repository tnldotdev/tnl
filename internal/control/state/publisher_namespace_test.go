package state

import (
	"errors"
	"regexp"
	"strings"
	"testing"
)

func TestRandomPublicURLHostnameHasNoPrefixAndStaysWithinNamespace(t *testing.T) {
	for range 64 {
		hostname, err := newRandomPublicURLHostname("member.example.test")
		if err != nil || !regexp.MustCompile(`^[a-z2-7]{26}\.member\.example\.test$`).MatchString(hostname) {
			t.Fatalf("unexpected random hostname: %q %v", hostname, err)
		}
	}
}

func TestRandomPublicURLHostnameValidatesNamespaceAndFullDNSLength(t *testing.T) {
	namespace := strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 34)
	if hostname, err := newRandomPublicURLHostname(namespace); err != nil || len(hostname) != 253 {
		t.Fatalf("maximum hostname: %q %v", hostname, err)
	}
	for _, invalid := range []string{"", "EXAMPLE.test", "example.test.", "*.example.test", namespace + "d"} {
		if hostname, err := newRandomPublicURLHostname(invalid); hostname != "" || !errors.Is(err, ErrPublicURLInvalid) {
			t.Fatalf("invalid namespace %q produced %q: %v", invalid, hostname, err)
		}
	}
}

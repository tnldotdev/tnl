package state

import (
	"errors"
	"regexp"
	"strings"
	"testing"
	"time"
)

func TestPublisherPublicURLAllocationRequiresExplicitAccessMode(t *testing.T) {
	d := &Database{}
	p := PublisherIdentity{Scope: PublisherScope{Kind: "namespace"}}
	for _, mode := range []VisitorAccessMode{"", "unknown"} {
		if _, err := d.AllocatePublisherPublicURL(t.Context(), p, "invocation", "http://localhost:3000", nil, nil, time.Now(), PublisherPublicURLOptions{AccessMode: mode}); !errors.Is(err, ErrPublicURLInvalid) {
			t.Fatalf("access mode %q = %v; want invalid public URL without consulting storage", mode, err)
		}
	}
}

func TestRandomPublicURLHostnameStaysWithinNamespace(t *testing.T) {
	shape := regexp.MustCompile(`^[a-z2-7]{25}[aeimquy4]\.member\.example\.test$`)
	for range 64 {
		hostname, err := newRandomPublicURLHostname("member.example.test")
		if err != nil || !shape.MatchString(hostname) {
			t.Fatalf("unexpected random hostname: %q %v", hostname, err)
		}
	}
}

func TestRandomPublicURLHostnameValidatesNamespaceAndDNSLength(t *testing.T) {
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

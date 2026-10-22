package team

import (
	"strings"
	"testing"

	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/pkg/api/authorityv1"
)

func TestDomainSelectionKeepsReadinessAndHostnameBoundaries(t *testing.T) {
	current := NewContext(authorityv1.Team{DefaultDomainId: "pending"}, authorityv1.Membership{}, []authorityv1.Domain{
		{Id: "pending", CanonicalDomain: "pending.example.test", State: authorityv1.DomainStatePending},
		{Id: "ready", CanonicalDomain: "example.test", State: authorityv1.DomainStateReady},
		{Id: "nested", CanonicalDomain: "nested.example.test", State: authorityv1.DomainStateReady},
	}, "")
	for _, test := range []struct {
		selected string
		reason   failure.Reason
		message  string
	}{
		{"", failure.DomainNotReady, "default domain pending.example.test is not ready"},
		{"pending.example.test", failure.DomainNotReady, "domain pending.example.test is not ready"},
		{"outside.test", failure.DomainNotAvailable, "domain outside.test is not available to the selected team"},
		{"EXAMPLE.test", failure.InvalidDomainName, "domain must use lowercase ASCII DNS labels without a trailing dot"},
	} {
		_, err := current.ReadyDomain(test.selected)
		if reason, _, ok := failure.Describe(err); !ok || reason != test.reason || !strings.Contains(err.Error(), test.message) {
			t.Fatalf("ready domain %q: %v", test.selected, err)
		}
	}
	if domain, err := current.Domain("pending"); err != nil || domain.Id != "pending" {
		t.Fatalf("status lookup excluded a pending domain: %+v, %v", domain, err)
	}
	for _, hostname := range []string{"api.nested.example.test", "nested.example.test"} {
		if domain, err := ReadyDomainForHostname(current.Domains(), hostname); err != nil || domain.Id != "nested" {
			t.Fatalf("longest ready domain for %s: %+v, %v", hostname, domain, err)
		}
	}
	if _, err := ReadyDomainForHostname(current.Domains(), "notexample.test"); err == nil {
		t.Fatal("hostname suffix crossed a DNS label boundary")
	}
}

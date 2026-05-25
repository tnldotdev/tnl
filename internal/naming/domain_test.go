package naming

import (
	"errors"
	"strings"
	"testing"

	"golang.org/x/net/publicsuffix"
)

func TestCustomDomainUsesPrivatePublicSuffixes(t *testing.T) {
	for _, test := range []struct {
		input string
		apex  bool
	}{
		{input: "example.com", apex: true},
		{input: "docs.example.com", apex: false},
		{input: "user.github.io", apex: true},
	} {
		domain, apex, err := CustomDomain(test.input, "routes.test")
		if err != nil || domain != test.input || apex != test.apex {
			t.Fatalf("CustomDomain(%q) = %q, %v, %v", test.input, domain, apex, err)
		}
	}
	for _, input := range []string{"com", "dev", "co.uk", "github.io", "routes.test", "api.routes.test"} {
		if _, _, err := CustomDomain(input, "routes.test"); !errors.Is(err, ErrUnclaimableDomain) {
			t.Fatalf("CustomDomain(%q) error = %v", input, err)
		}
	}
	if _, _, err := CustomDomain("example.com", "routes.example.com"); !errors.Is(err, ErrUnclaimableDomain) {
		t.Fatalf("managed suffix ancestor error = %v", err)
	}
}

func TestChildDepth(t *testing.T) {
	if depth, ok := ChildDepth("preview.v2.api.chase.example", "chase.example"); !ok || depth != 3 {
		t.Fatalf("depth = %d, %v", depth, ok)
	}
	if _, ok := ChildDepth("notchase.example", "chase.example"); ok {
		t.Fatal("non-descendant accepted")
	}
}

func FuzzDomainPolicy(f *testing.F) {
	for _, seed := range []struct {
		hostname string
		base     string
	}{
		{hostname: "example.com", base: "routes.test"},
		{hostname: "docs.example.com", base: "routes.test"},
		{hostname: "user.github.io", base: "routes.test"},
		{hostname: "github.io", base: "routes.test"},
		{hostname: "api.routes.test", base: "routes.test"},
		{hostname: "preview.v2.api.chase.example", base: "chase.example"},
		{hostname: "notchase.example", base: "chase.example"},
		{hostname: "Example.COM.", base: "example.com"},
	} {
		f.Add(seed.hostname, seed.base)
	}

	f.Fuzz(func(t *testing.T, hostnameInput, baseInput string) {
		hostname, hostnameErr := CanonicalizeHostname(hostnameInput)
		base, baseErr := CanonicalizeHostname(baseInput)
		if hostnameErr == nil && baseErr == nil {
			within := IsWithin(hostname, base)
			depth, hasDepth := ChildDepth(hostname, base)
			if hasDepth != within {
				t.Fatalf("relationship mismatch for hostname %q and base %q", hostname, base)
			}
			if hasDepth {
				wantDepth := 0
				if hostname != base {
					relative, found := strings.CutSuffix(hostname, "."+base)
					if !found {
						t.Fatalf("descendant %q has no relative labels beneath %q", hostname, base)
					}
					wantDepth = strings.Count(relative, ".") + 1
				}
				if depth != wantDepth {
					t.Fatalf("ChildDepth(%q, %q) = %d, want %d", hostname, base, depth, wantDepth)
				}
				if _, _, err := CustomDomain(hostname, base); !errors.Is(err, ErrUnclaimableDomain) {
					t.Fatalf("hostname-suffix descendant %q was claimable beneath %q: %v", hostname, base, err)
				}
			}
		}

		domain, apex, err := CustomDomain(hostnameInput, "routes.test")
		if err != nil {
			return
		}
		canonical, err := CanonicalizeHostname(domain)
		if err != nil || canonical != domain || IsWithin(domain, "routes.test") {
			t.Fatalf("unsafe custom domain %q: canonical %q, error %v", domain, canonical, err)
		}
		roundTrip, roundTripApex, err := CustomDomain(domain, "routes.test")
		if err != nil || roundTrip != domain || roundTripApex != apex {
			t.Fatalf("custom domain is not idempotent: %q, %v, %v", roundTrip, roundTripApex, err)
		}
		registrable, err := publicsuffix.EffectiveTLDPlusOne(domain)
		if err != nil || apex != (domain == registrable) {
			t.Fatalf("custom domain apex mismatch: domain %q, registrable %q, apex %v, error %v", domain, registrable, apex, err)
		}

		child := "child." + domain
		if _, err := CanonicalizeHostname(child); err != nil {
			return
		}
		childDomain, childApex, err := CustomDomain(child, "routes.test")
		if err != nil || childDomain != child || childApex {
			t.Fatalf("valid custom-domain child = %q, %v, %v", childDomain, childApex, err)
		}
	})
}

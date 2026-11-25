package main

import (
	"bytes"
	"strings"
	"testing"

	clientteam "github.com/tnldotdev/tnl/internal/client/team"
	authorityv1 "github.com/tnldotdev/tnl/pkg/api/control/authority/v1"
)

func TestDomainClaimPresentation(t *testing.T) {
	records := []authorityv1.DNSRecord{{Name: "claimed.example", Type: "NS", Value: "ns-1.example"}}
	for _, test := range []struct {
		name        string
		domain      authorityv1.Domain
		makeDefault bool
		state       string
		footer      string
	}{
		{
			name: "provisioning", domain: authorityv1.Domain{State: authorityv1.DomainStatePending},
			state: "provisioning",
		},
		{
			name: "provisioning_default", domain: authorityv1.Domain{State: authorityv1.DomainStatePending}, makeDefault: true,
			state: "provisioning",
		},
		{
			name: "verification", domain: authorityv1.Domain{State: authorityv1.DomainStatePending, RequiredRecords: records},
			state: "verification required", footer: "add the DNS records to continue",
		},
		{
			name: "verification_default", domain: authorityv1.Domain{State: authorityv1.DomainStatePending, RequiredRecords: records}, makeDefault: true,
			state: "verification required", footer: "add the DNS records; this domain will become the default",
		},
		{
			name: "ready_default", domain: authorityv1.Domain{State: authorityv1.DomainStateReady}, makeDefault: true,
			state: "ready", footer: "selected as the default domain",
		},
		{
			name: "failed", domain: authorityv1.Domain{State: authorityv1.DomainStateFailed}, makeDefault: true,
			state: "failed", footer: "ask your team admin to check DNS setup",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			state, footer := domainClaimPresentation(test.domain, test.makeDefault)
			if state != test.state || footer != test.footer {
				t.Fatalf("presentation = %q, %q; want %q, %q", state, footer, test.state, test.footer)
			}
		})
	}
}

func TestDomainClaimResultPresentation(t *testing.T) {
	records := []authorityv1.DNSRecord{{Name: "claimed.example", Type: "NS", Value: "ns-1.example"}}
	pending := authorityv1.Domain{CanonicalDomain: "claimed.example", Id: "domain_1", State: authorityv1.DomainStatePending}
	withRecords := pending
	withRecords.RequiredRecords = records
	failed := pending
	failed.State = authorityv1.DomainStateFailed
	for _, test := range []struct {
		name   string
		claim  authorityv1.Domain
		wantNS bool
	}{
		{name: "immediate", claim: withRecords, wantNS: true},
		{name: "delayed", claim: withRecords, wantNS: true},
		{name: "failed", claim: failed},
		{name: "failed_response", claim: failed},
	} {
		t.Run(test.name, func(t *testing.T) {
			var output bytes.Buffer
			if err := writeDomainClaim(&output, test.claim, true, false); err != nil {
				t.Fatal(err)
			}
			if test.wantNS && !strings.Contains(output.String(), "ns-1.example") || test.claim.State == authorityv1.DomainStateFailed && output.String() != "claimed.example  failed\nask your team admin to check DNS setup\n" {
				t.Fatalf("claim output: %s", output.String())
			}
		})
	}
}

func TestDomainClaimTimeoutPresentation(t *testing.T) {
	pending := authorityv1.Domain{CanonicalDomain: "claimed.example", Id: "domain_1", State: authorityv1.DomainStatePending}
	var output bytes.Buffer
	if err := writeDomainClaim(&output, pending, true, true); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"claim saved", "DNS records not yet available", "tnl domain status claimed.example", "default"} {
		if !strings.Contains(output.String(), want) {
			t.Fatalf("claim output missing %q:\n%s", want, output.String())
		}
	}
}

func TestDomainClaimFollowupRetainsServerAndTeam(t *testing.T) {
	var output bytes.Buffer
	claimed := authorityv1.Domain{CanonicalDomain: "studio.example.test", Id: "dom_1", State: authorityv1.DomainStatePending}
	if err := writeDomainClaimWithContext(&output, claimed, false, true, commandScope{server: "https://control.example.test", team: "tm_studio"}); err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{"--server=https://control.example.test", "--team=tm_studio", "studio.example.test"} {
		if !strings.Contains(output.String(), value) {
			t.Fatalf("follow-up missing %q: %s", value, output.String())
		}
	}
}

func TestDomainStatusFindsOneDomainAndShowsAction(t *testing.T) {
	claimed := authorityv1.Domain{CanonicalDomain: "custom.example", Id: "domain_1", Kind: "custom", State: authorityv1.DomainStatePending, RequiredRecords: []authorityv1.DNSRecord{{Name: "custom.example", Type: "NS", Value: "ns-1.example"}}}
	domains := []authorityv1.Domain{{CanonicalDomain: "other.example", Id: "domain_2"}, claimed}
	for _, value := range []string{"custom.example", "domain_1"} {
		found, ok := clientteam.FindDomain(domains, value)
		if !ok || found.Id != claimed.Id {
			t.Fatalf("lookup %q: %#v, %t", value, found, ok)
		}
		var output bytes.Buffer
		if err := writeDomainStatus(&output, found, true); err != nil {
			t.Fatal(err)
		}
		for _, want := range []string{"custom.example  verification required (default)\n", "ns-1.example", "add the DNS records"} {
			if !strings.Contains(output.String(), want) {
				t.Fatalf("status missing %q:\n%s", want, output.String())
			}
		}
		if strings.Contains(output.String(), "other.example") || strings.Contains(output.String(), "domain_1") {
			t.Fatalf("status included another domain:\n%s", output.String())
		}
	}
	if _, ok := clientteam.FindDomain(domains, "missing.example"); ok {
		t.Fatal("missing domain resolved")
	}
	for _, test := range []struct {
		state   authorityv1.DomainState
		heading string
		action  string
	}{
		{authorityv1.DomainStatePending, "provisioning", "check again later"},
		{authorityv1.DomainStateFailed, "failed", "team admin"},
		{authorityv1.DomainStateReady, "ready", "ready for public URLs"},
	} {
		domain := claimed
		domain.State = test.state
		domain.RequiredRecords = nil
		var output bytes.Buffer
		if err := writeDomainStatus(&output, domain, false); err != nil {
			t.Fatal(err)
		}
		if !strings.HasPrefix(output.String(), "custom.example  "+test.heading+"\n") || !strings.Contains(output.String(), test.action) || strings.Contains(output.String(), "(default)") {
			t.Fatalf("status for %s:\n%s", test.state, output.String())
		}
	}
}

func TestDomainStatusShowsDelegationStageAndBothRequiredRecords(t *testing.T) {
	domain := authorityv1.Domain{
		CanonicalDomain:  "claimed.example",
		Id:               "domain_0123456789abcdef0123456789abcdef",
		Kind:             "custom",
		State:            authorityv1.DomainStatePending,
		ClaimStage:       new(authorityv1.WaitingForDelegation),
		DelegationTarget: new("example"),
		RequiredRecords: []authorityv1.DNSRecord{
			{Name: "claimed.example", Type: "NS", Value: "ns-1.example"},
			{Name: "claimed.example", Type: "NS", Value: "ns-2.example"},
		},
	}
	var out bytes.Buffer
	if err := writeDomainStatus(&out, domain, false); err != nil {
		t.Fatal(err)
	}
	text := strings.Join(strings.Fields(out.String()), " ")
	for _, want := range []string{"claimed.example waiting for delegation", "add records under example", "leave the parent domain's nameservers unchanged", "claimed.example NS ns-1.example", "claimed.example NS ns-2.example", "add the nameservers shown above"} {
		if !strings.Contains(text, want) {
			t.Fatalf("delegation status missing %q:\n%s", want, &out)
		}
	}
	domain.DelegationTarget = nil
	out.Reset()
	if err := writeDomainStatus(&out, domain, false); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), "registrar") || !strings.Contains(out.String(), "add the nameservers shown above") {
		t.Fatalf("unknown delegation target: %s", &out)
	}
}

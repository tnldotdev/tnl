package main

import (
	"bytes"
	"strings"
	"testing"

	clientteam "github.com/tnldotdev/tnl/internal/client/team"
	"github.com/tnldotdev/tnl/internal/clioutput"
	"github.com/tnldotdev/tnl/pkg/api/authorityv1"
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
			state: "provisioning", footer: "run tnl domain status to check DNS setup",
		},
		{
			name: "provisioning_default", domain: authorityv1.Domain{State: authorityv1.DomainStatePending}, makeDefault: true,
			state: "provisioning", footer: "will become default; run tnl domain status",
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
			if test.wantNS && !strings.Contains(output.String(), "ns-1.example") || test.claim.State == authorityv1.DomainStateFailed && !strings.Contains(output.String(), "-- failed ") {
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
	if err := writeDomainClaimWithContext(&output, claimed, false, true, "https://control.example.test", "tm_studio"); err != nil {
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
		for _, want := range []string{"tnl domain status", "verification required", "domain_1", "default  yes", "ns-1.example", "add the DNS records"} {
			if !strings.Contains(output.String(), want) {
				t.Fatalf("status missing %q:\n%s", want, output.String())
			}
		}
		if strings.Contains(output.String(), "other.example") {
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
		if !strings.Contains(output.String(), test.heading) || !strings.Contains(output.String(), test.action) || !strings.Contains(output.String(), "default  no") {
			t.Fatalf("status for %s:\n%s", test.state, output.String())
		}
	}
}

func TestDomainDNSRecordBlocksRenderRequiredRecords(t *testing.T) {
	domain := authorityv1.Domain{
		CanonicalDomain: "claimed.example",
		Id:              "domain_0123456789abcdef0123456789abcdef",
		Kind:            "custom",
		State:           authorityv1.DomainStatePending,
		RequiredRecords: []authorityv1.DNSRecord{
			{Name: "claimed.example", Type: "NS", Value: "ns-1.example"},
			{Name: "claimed.example", Type: "NS", Value: "ns-2.example"},
		},
	}
	details := []clioutput.Block{clioutput.Fields(
		clioutput.Field{Label: "kind", Value: string(domain.Kind)},
		clioutput.Field{Label: "state", Value: string(domain.State)},
		clioutput.Field{Label: "id", Value: domain.Id},
	)}
	details = append(details, domainDNSRecordBlocks(domain.RequiredRecords)...)
	output, err := clioutput.Render(clioutput.Frame{
		Command: "tnl domain list", State: "1 domain", Footer: "* default",
		Blocks: []clioutput.Block{clioutput.Section(domain.CanonicalDomain, details...)},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"claimed.example", "pending", "ns-1.example", "ns-2.example"} {
		if !strings.Contains(output, want) {
			t.Fatalf("output does not contain %q:\n%s", want, output)
		}
	}
	if strings.Count(output, "DNS record") != 2 {
		t.Fatalf("output does not contain both DNS record sections:\n%s", output)
	}
}

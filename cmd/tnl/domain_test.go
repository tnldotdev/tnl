package main

import (
	"strings"
	"testing"

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
			state: "provisioning", footer: "run tnl domain list to check DNS setup",
		},
		{
			name: "provisioning_default", domain: authorityv1.Domain{State: authorityv1.DomainStatePending}, makeDefault: true,
			state: "provisioning", footer: "run tnl domain list; this domain will become the default",
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
			state: "failed",
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

func TestDomainDNSRecordBlocksRenderRequiredRecords(t *testing.T) {
	domain := authorityv1.Domain{
		CanonicalDomain: "claimed.example",
		Id:              "domain_0123456789abcdef0123456789abcdef",
		Kind:            "claimed",
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
	for _, want := range []string{"claimed.example", "state  pending", "value  ns-1.example", "value  ns-2.example"} {
		if !strings.Contains(output, want) {
			t.Fatalf("output does not contain %q:\n%s", want, output)
		}
	}
	if strings.Count(output, "DNS record") != 2 {
		t.Fatalf("output does not contain both DNS record sections:\n%s", output)
	}
}

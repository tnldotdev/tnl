package main

import (
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/tnldotdev/tnl/internal/clioutput"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/pkg/api/authorityv1"
)

type domainCommand struct {
	Claim   domainClaimCommand   `cmd:"" help:"Claim a domain for the selected team."`
	Default domainDefaultCommand `cmd:"" help:"Set the selected team's default domain."`
	List    domainListCommand    `cmd:"" help:"List domains available to the selected team."`
	Release domainReleaseCommand `cmd:"" help:"Release a claimed domain."`
}

type domainClaimCommand struct {
	remoteFlags `embed:""`
	Domain      string `arg:"" name:"domain" required:"" help:"Canonical domain name to claim."`
	Default     bool   `name:"default" help:"Make the domain the team default after it becomes ready."`
}

type domainDefaultCommand struct {
	remoteFlags `embed:""`
	Domain      string `arg:"" name:"domain" required:"" help:"Domain ID or domain name."`
}

type domainListCommand struct {
	remoteFlags `embed:""`
}

type domainReleaseCommand struct {
	remoteFlags `embed:""`
	Domain      string `arg:"" name:"domain" required:"" help:"Domain ID or domain name."`
}

func runDomainClaim(ctx context.Context, command domainClaimCommand, output, diagnostics io.Writer) error {
	domain, err := naming.CanonicalizeHostname(command.Domain)
	if err != nil || domain != command.Domain {
		return errors.New("domain must use lowercase ASCII DNS labels without a trailing dot")
	}
	session, err := openTeamSession(ctx, command.remoteFlags, "tnl domain claim", diagnostics)
	if err != nil {
		return err
	}
	defer session.Close()
	current, err := session.current(ctx)
	if err != nil {
		return err
	}
	key, err := randomIdempotencyKey()
	if err != nil {
		return err
	}
	claimed, err := session.api.ClaimTeamDomain(ctx, current.team.Id, domain, key, command.Default)
	if err != nil {
		return err
	}
	blocks := []clioutput.Block{clioutput.Fields(
		clioutput.Field{Label: "domain", Value: claimed.CanonicalDomain},
		clioutput.Field{Label: "state", Value: string(claimed.State)},
		clioutput.Field{Label: "id", Value: claimed.Id},
	)}
	blocks = append(blocks, domainDNSRecordBlocks(claimed.RequiredRecords)...)
	state, footer := domainClaimPresentation(claimed, command.Default)
	return writeHumanFrame(output, "tnl domain claim", state, footer, blocks...)
}

func runDomainList(ctx context.Context, command domainListCommand, output, diagnostics io.Writer) error {
	session, err := openTeamSession(ctx, command.remoteFlags, "tnl domain list", diagnostics)
	if err != nil {
		return err
	}
	defer session.Close()
	current, err := session.current(ctx)
	if err != nil {
		return err
	}
	blocks := make([]clioutput.Block, 0, len(current.domains))
	for _, domain := range current.domains {
		title := domain.CanonicalDomain
		if domain.Id == current.team.DefaultDomainId {
			title = "* " + title
		}
		details := []clioutput.Block{clioutput.Fields(
			clioutput.Field{Label: "kind", Value: string(domain.Kind)},
			clioutput.Field{Label: "state", Value: string(domain.State)},
			clioutput.Field{Label: "id", Value: domain.Id},
		)}
		details = append(details, domainDNSRecordBlocks(domain.RequiredRecords)...)
		blocks = append(blocks, clioutput.Section(title, details...))
	}
	return writeHumanFrame(output, "tnl domain list", countState(len(blocks), "domain", "domains"), "* default", blocks...)
}

func domainDNSRecordBlocks(records []authorityv1.DNSRecord) []clioutput.Block {
	blocks := make([]clioutput.Block, 0, len(records))
	for _, record := range records {
		blocks = append(blocks, clioutput.Section("DNS record", clioutput.Fields(
			clioutput.Field{Label: "name", Value: record.Name},
			clioutput.Field{Label: "type", Value: string(record.Type)},
			clioutput.Field{Label: "value", Value: record.Value},
		)))
	}
	return blocks
}

func domainClaimPresentation(domain authorityv1.Domain, makeDefault bool) (string, string) {
	state, footer := string(domain.State), ""
	if domain.State == authorityv1.DomainStatePending {
		if len(domain.RequiredRecords) == 0 {
			state, footer = "provisioning", "run tnl domain list to check DNS setup"
			if makeDefault {
				footer = "run tnl domain list; this domain will become the default"
			}
			return state, footer
		}
		state, footer = "verification required", "add the DNS records to continue"
		if makeDefault {
			footer = "add the DNS records; this domain will become the default"
		}
		return state, footer
	}
	if domain.State == authorityv1.DomainStateReady && makeDefault {
		footer = "selected as the default domain"
	}
	return state, footer
}

func runDomainDefault(ctx context.Context, command domainDefaultCommand, output, diagnostics io.Writer) error {
	return mutateDomain(ctx, command.remoteFlags, "tnl domain default", command.Domain, output, diagnostics, func(session *teamSession, current teamContext, domain authorityv1.Domain) error {
		team, err := session.api.SetTeamDefaultDomain(ctx, current.team.Id, domain.Id)
		if err != nil {
			return err
		}
		return writeHumanTransition(output, "tnl domain default", "updated", domain.CanonicalDomain, "", "default domain", "",
			clioutput.Field{Label: "id", Value: team.DefaultDomainId})
	})
}

func runDomainRelease(ctx context.Context, command domainReleaseCommand, output, diagnostics io.Writer) error {
	return mutateDomain(ctx, command.remoteFlags, "tnl domain release", command.Domain, output, diagnostics, func(session *teamSession, current teamContext, domain authorityv1.Domain) error {
		if err := session.api.ReleaseTeamDomain(ctx, current.team.Id, domain.Id); err != nil {
			return err
		}
		return writeHumanTransition(output, "tnl domain release", "released", domain.CanonicalDomain, "", "domain released", "",
			clioutput.Field{Label: "id", Value: domain.Id})
	})
}

func mutateDomain(ctx context.Context, flags remoteFlags, command, value string, output, diagnostics io.Writer, mutate func(*teamSession, teamContext, authorityv1.Domain) error) error {
	session, err := openTeamSession(ctx, flags, command, diagnostics)
	if err != nil {
		return err
	}
	defer session.Close()
	current, err := session.current(ctx)
	if err != nil {
		return err
	}
	for _, domain := range current.domains {
		if domain.Id == value || domain.CanonicalDomain == value {
			return mutate(session, current, domain)
		}
	}
	return fmt.Errorf("domain %q is not available to the selected team", value)
}

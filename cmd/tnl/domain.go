package main

import (
	"context"
	"errors"
	"io"
	"time"

	clientteam "github.com/tnldotdev/tnl/internal/client/team"
	"github.com/tnldotdev/tnl/internal/clioutput"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/naming"
	authorityv1 "github.com/tnldotdev/tnl/pkg/api/control/authority/v1"
)

type domainCommand struct {
	Claim   domainClaimCommand   `cmd:"" help:"Claim a team domain; use tnl domain status to check its DNS records."`
	Default domainDefaultCommand `cmd:"" help:"Set the selected team's default domain."`
	List    domainListCommand    `cmd:"" help:"List domains available to the selected team."`
	Status  domainStatusCommand  `cmd:"" help:"Show DNS setup for one team domain by name or ID."`
	Release domainReleaseCommand `cmd:"" help:"Release a custom domain."`
}

type domainClaimCommand struct {
	scopedTeamFlags `embed:""`
	Domain          string `arg:"" name:"domain" required:"" help:"Canonical domain name to claim."`
	Default         bool   `name:"default" help:"Make the domain the team default after it becomes ready."`
}

type domainDefaultCommand struct {
	scopedTeamFlags `embed:""`
	Domain          string `arg:"" name:"domain" required:"" help:"Domain ID or domain name."`
}

type domainListCommand struct {
	scopedTeamFlags `embed:""`
}

type domainStatusCommand struct {
	scopedTeamFlags `embed:""`
	Domain          string `arg:"" name:"domain" required:"" help:"Domain ID or domain name."`
}

type domainReleaseCommand struct {
	scopedTeamFlags `embed:""`
	Domain          string `arg:"" name:"domain" required:"" help:"Domain ID or domain name."`
}

func runDomainClaim(ctx context.Context, command domainClaimCommand, output, diagnostics io.Writer) error {
	domain, err := naming.CanonicalizeHostname(command.Domain)
	if err != nil || domain != command.Domain {
		return failure.Wrap("validate custom domain", failure.InvalidDomainName, errors.Join(err, errors.New("domain must use lowercase ASCII DNS labels without a trailing dot")))
	}
	session, err := openTeamSession(ctx, command.selection(), "tnl domain claim", diagnostics)
	if err != nil {
		return err
	}
	defer session.Close()
	current, err := session.CurrentWithDomains(ctx)
	if err != nil {
		return err
	}
	key, err := randomIdempotencyKey()
	if err != nil {
		return err
	}
	claimed, timedOut, err := clientteam.ClaimAndWaitForDomainRecords(ctx, session.Authenticated().Authority, current.Team().Id, domain, key, command.Default, defaultDomainClaimWait())
	if err != nil {
		return err
	}
	return writeDomainClaimWithContext(output, claimed, command.Default, timedOut, session.Authenticated().ServerEndpoint, current.Team().Id)
}

func defaultDomainClaimWait() clientteam.DomainClaimWait {
	return clientteam.DomainClaimWait{Timeout: 3 * time.Minute, Poll: func(ctx context.Context) error {
		timer := time.NewTimer(2 * time.Second)
		defer timer.Stop()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
			return nil
		}
	}}
}

func writeDomainClaim(output io.Writer, claimed authorityv1.Domain, makeDefault, timedOut bool) error {
	return writeDomainClaimWithContext(output, claimed, makeDefault, timedOut, "", "")
}

func writeDomainClaimWithContext(output io.Writer, claimed authorityv1.Domain, makeDefault, timedOut bool, server, team string) error {
	blocks := []clioutput.Block{clioutput.Fields(
		clioutput.Field{Label: "domain", Value: claimed.CanonicalDomain},
		clioutput.Field{Label: "state", Value: string(claimed.State)},
		clioutput.Field{Label: "id", Value: claimed.Id},
	)}
	blocks = append(blocks, domainDNSRecordBlocks(claimed.RequiredRecords)...)
	state, footer := domainClaimPresentation(claimed, makeDefault)
	if timedOut {
		next := "tnl domain status " + claimed.CanonicalDomain
		if server != "" {
			next += " --server=" + server
		}
		if team != "" {
			next += " --team=" + team
		}
		state, footer = "saved", "claim saved; check with tnl domain status"
		blocks = append(blocks, clioutput.Text("DNS records not yet available"), clioutput.Fields(
			clioutput.Field{Label: "next", Value: next},
		))
		if makeDefault {
			blocks = append(blocks, clioutput.Fields(clioutput.Field{Label: "default", Value: "when ready"}))
		}
	}
	return writeHumanFrame(output, "tnl domain claim", state, footer, blocks...)
}

func runDomainList(ctx context.Context, command domainListCommand, output, diagnostics io.Writer) error {
	session, err := openTeamSession(ctx, command.selection(), "tnl domain list", diagnostics)
	if err != nil {
		return err
	}
	defer session.Close()
	current, err := session.CurrentWithDomains(ctx)
	if err != nil {
		return err
	}
	blocks := []clioutput.Block{clioutput.Fields(
		clioutput.Field{Label: "server", Value: session.Authenticated().ServerEndpoint},
		clioutput.Field{Label: "team", Value: current.Team().DisplayName},
	)}
	for _, domain := range current.Domains() {
		title := domain.CanonicalDomain
		if domain.Id == current.Team().DefaultDomainId {
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
	return writeHumanFrame(output, "tnl domain list", countState(len(current.Domains()), "domain", "domains"), "* default", blocks...)
}

func runDomainStatus(ctx context.Context, command domainStatusCommand, output, diagnostics io.Writer) error {
	session, err := openTeamSession(ctx, command.selection(), "tnl domain status", diagnostics)
	if err != nil {
		return err
	}
	defer session.Close()
	current, err := session.CurrentWithDomains(ctx)
	if err != nil {
		return err
	}
	domain, err := current.Domain(command.Domain)
	if err != nil {
		return err
	}
	return writeDomainStatus(output, domain, domain.Id == current.Team().DefaultDomainId)
}

func writeDomainStatus(output io.Writer, domain authorityv1.Domain, isDefault bool) error {
	marker := "no"
	if isDefault {
		marker = "yes"
	}
	blocks := []clioutput.Block{clioutput.Fields(
		clioutput.Field{Label: "domain", Value: domain.CanonicalDomain},
		clioutput.Field{Label: "kind", Value: string(domain.Kind)},
		clioutput.Field{Label: "state", Value: string(domain.State)},
		clioutput.Field{Label: "id", Value: domain.Id},
		clioutput.Field{Label: "default", Value: marker},
	)}
	blocks = append(blocks, domainDNSRecordBlocks(domain.RequiredRecords)...)
	state, footer := domainStatusPresentation(domain)
	return writeHumanFrame(output, "tnl domain status", state, footer, blocks...)
}

func domainStatusPresentation(domain authorityv1.Domain) (string, string) {
	if domain.State == authorityv1.DomainStatePending && len(domain.RequiredRecords) == 0 {
		return "provisioning", "DNS records not yet available; check again later"
	}
	if domain.State == authorityv1.DomainStatePending {
		return "verification required", "add the DNS records to continue"
	}
	if domain.State == authorityv1.DomainStateFailed {
		return "failed", "ask your team admin to check DNS setup"
	}
	return string(domain.State), "ready for public URLs"
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
			state, footer = "provisioning", "run tnl domain status to check DNS setup"
			if makeDefault {
				footer = "will become default; run tnl domain status"
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
	if domain.State == authorityv1.DomainStateFailed {
		footer = "ask your team admin to check DNS setup"
	}
	return state, footer
}

func runDomainDefault(ctx context.Context, command domainDefaultCommand, output, diagnostics io.Writer) error {
	return mutateDomain(ctx, command.selection(), "tnl domain default", command.Domain, output, diagnostics, func(session *clientteam.Session, current clientteam.Context, domain authorityv1.Domain) error {
		team, err := session.Authenticated().Authority.SetTeamDefaultDomain(ctx, current.Team().Id, domain.Id)
		if err != nil {
			return err
		}
		return writeHumanTransition(output, "tnl domain default", "updated", domain.CanonicalDomain, "", "default domain", "",
			clioutput.Field{Label: "id", Value: team.DefaultDomainId})
	})
}

func runDomainRelease(ctx context.Context, command domainReleaseCommand, output, diagnostics io.Writer) error {
	return mutateDomain(ctx, command.selection(), "tnl domain release", command.Domain, output, diagnostics, func(session *clientteam.Session, current clientteam.Context, domain authorityv1.Domain) error {
		if err := session.Authenticated().Authority.ReleaseTeamDomain(ctx, current.Team().Id, domain.Id); err != nil {
			return err
		}
		return writeHumanTransition(output, "tnl domain release", "released", domain.CanonicalDomain, "", "domain released", "",
			clioutput.Field{Label: "id", Value: domain.Id})
	})
}

func mutateDomain(ctx context.Context, flags remoteFlags, command, value string, output, diagnostics io.Writer, mutate func(*clientteam.Session, clientteam.Context, authorityv1.Domain) error) error {
	session, err := openTeamSession(ctx, flags, command, diagnostics)
	if err != nil {
		return err
	}
	defer session.Close()
	current, err := session.CurrentWithDomains(ctx)
	if err != nil {
		return err
	}
	domain, err := current.Domain(value)
	if err != nil {
		return err
	}
	return mutate(session, current, domain)
}

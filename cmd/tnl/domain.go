package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/tnldotdev/tnl/internal/clioutput"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/pkg/api/authorityv1"
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
	current, err := session.currentWithDomains(ctx)
	if err != nil {
		return err
	}
	key, err := randomIdempotencyKey()
	if err != nil {
		return err
	}
	claimed, timedOut, err := claimAndWaitForDomainRecords(ctx, session.api, current.team.Id, domain, key, command.Default, defaultDomainClaimWait())
	if err != nil {
		return err
	}
	return writeDomainClaimWithContext(output, claimed, command.Default, timedOut, session.authenticated.ServerEndpoint, current.team.Id)
}

type domainClaimAPI interface {
	ClaimTeamDomain(context.Context, string, string, string, bool) (authorityv1.Domain, error)
	ListTeamDomains(context.Context, string) (authorityv1.DomainPage, error)
}

type domainClaimWait struct {
	timeout time.Duration
	poll    func(context.Context) error
}

func defaultDomainClaimWait() domainClaimWait {
	return domainClaimWait{timeout: 3 * time.Minute, poll: func(ctx context.Context) error {
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

func claimAndWaitForDomainRecords(ctx context.Context, api domainClaimAPI, teamID, name, key string, makeDefault bool, wait domainClaimWait) (authorityv1.Domain, bool, error) {
	claimed, err := api.ClaimTeamDomain(ctx, teamID, name, key, makeDefault)
	if err != nil || claimed.State != authorityv1.DomainStatePending || len(claimed.RequiredRecords) != 0 {
		return claimed, false, err
	}
	waitCtx, cancel := context.WithTimeout(ctx, wait.timeout)
	defer cancel()
	for {
		if err := wait.poll(waitCtx); err != nil {
			if ctx.Err() != nil {
				return claimed, false, ctx.Err()
			}
			if errors.Is(waitCtx.Err(), context.DeadlineExceeded) {
				return claimed, true, nil
			}
			return claimed, false, err
		}
		if err := waitCtx.Err(); err != nil {
			if ctx.Err() != nil {
				return claimed, false, ctx.Err()
			}
			return claimed, true, nil
		}
		page, err := api.ListTeamDomains(waitCtx, teamID)
		if err != nil {
			if ctx.Err() != nil {
				return claimed, false, ctx.Err()
			}
			if errors.Is(waitCtx.Err(), context.DeadlineExceeded) {
				return claimed, true, nil
			}
			return claimed, false, err
		}
		if err := ctx.Err(); err != nil {
			return claimed, false, err
		}
		if domain, ok := teamDomain(page.Domains, claimed.Id); ok {
			claimed = domain
			if len(domain.RequiredRecords) != 0 || domain.State != authorityv1.DomainStatePending {
				return domain, false, nil
			}
		}
	}
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
	current, err := session.currentWithDomains(ctx)
	if err != nil {
		return err
	}
	blocks := []clioutput.Block{clioutput.Fields(
		clioutput.Field{Label: "server", Value: session.authenticated.ServerEndpoint},
		clioutput.Field{Label: "team", Value: current.team.DisplayName},
	)}
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
	return writeHumanFrame(output, "tnl domain list", countState(len(current.domains), "domain", "domains"), "* default", blocks...)
}

func runDomainStatus(ctx context.Context, command domainStatusCommand, output, diagnostics io.Writer) error {
	session, err := openTeamSession(ctx, command.selection(), "tnl domain status", diagnostics)
	if err != nil {
		return err
	}
	defer session.Close()
	current, err := session.currentWithDomains(ctx)
	if err != nil {
		return err
	}
	domain, ok := teamDomain(current.domains, command.Domain)
	if !ok {
		return failure.Wrap("select team domain", failure.DomainNotAvailable,
			fmt.Errorf("domain %q is not available to the selected team", command.Domain))
	}
	return writeDomainStatus(output, domain, domain.Id == current.team.DefaultDomainId)
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
	return mutateDomain(ctx, command.selection(), "tnl domain default", command.Domain, output, diagnostics, func(session *teamSession, current teamContext, domain authorityv1.Domain) error {
		team, err := session.api.SetTeamDefaultDomain(ctx, current.team.Id, domain.Id)
		if err != nil {
			return err
		}
		return writeHumanTransition(output, "tnl domain default", "updated", domain.CanonicalDomain, "", "default domain", "",
			clioutput.Field{Label: "id", Value: team.DefaultDomainId})
	})
}

func runDomainRelease(ctx context.Context, command domainReleaseCommand, output, diagnostics io.Writer) error {
	return mutateDomain(ctx, command.selection(), "tnl domain release", command.Domain, output, diagnostics, func(session *teamSession, current teamContext, domain authorityv1.Domain) error {
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
	current, err := session.currentWithDomains(ctx)
	if err != nil {
		return err
	}
	domain, ok := teamDomain(current.domains, value)
	if ok {
		return mutate(session, current, domain)
	}
	return failure.Wrap("select team domain", failure.DomainNotAvailable,
		fmt.Errorf("domain %q is not available to the selected team", value))
}

func teamDomain(domains []authorityv1.Domain, value string) (authorityv1.Domain, bool) {
	for _, domain := range domains {
		if domain.Id == value || domain.CanonicalDomain == value {
			return domain, true
		}
	}
	return authorityv1.Domain{}, false
}

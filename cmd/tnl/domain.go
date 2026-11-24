package main

import (
	"context"
	"errors"
	"io"
	"strings"
	"time"

	"github.com/spf13/cobra"

	clientteam "github.com/tnldotdev/tnl/internal/client/team"
	"github.com/tnldotdev/tnl/internal/clioutput"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	authorityv1 "github.com/tnldotdev/tnl/pkg/api/control/authority/v1"
)

type domainCommand struct {
	Claim    domainClaimCommand
	Default  domainDefaultCommand
	List     domainListCommand
	Status   domainStatusCommand
	Release  domainReleaseCommand
	Transfer domainTransferCommand
}

type domainClaimCommand struct {
	scopedTeamFlags `embed:""`
	Domain          string `arg:"" name:"domain" required:"" help:"Canonical domain name to claim."`
	Default         bool   `name:"default" help:"Make the domain the team default after it becomes ready."`
	Personal        bool   `name:"personal" help:"Claim the domain for your personal team."`
}

type domainTransferCommand struct {
	remoteFlags `embed:""`
	Domain      string `arg:"" name:"domain" required:"" help:"Custom domain to transfer."`
	ToTeam      string `name:"to-team" help:"Destination team name or ID."`
	ToPersonal  bool   `name:"to-personal" help:"Transfer to your personal team."`
	Accept      bool   `name:"accept" help:"Accept a pending transfer as the destination owner."`
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
	if command.Personal && command.Team != "" {
		return failure.Wrap("select domain owner", failure.InvalidTunnelFlags, errors.New("choose either --personal or --team"))
	}
	session, err := openTeamSession(ctx, command.selection(), "tnl domain claim", diagnostics)
	if err != nil {
		return err
	}
	defer session.Close()
	teamID := session.Identity().PersonalTeamId
	if !command.Personal {
		membership, err := session.CurrentMembership(ctx)
		if err != nil {
			return err
		}
		teamID = membership.TeamId
	}
	key, err := randomIdempotencyKey()
	if err != nil {
		return err
	}
	claimed, timedOut, err := clientteam.ClaimAndWaitForDomainRecords(ctx, session.Authenticated().Authority, teamID, domain, key, command.Default, defaultDomainClaimWait())
	if err != nil {
		return err
	}
	return writeDomainClaimWithContext(output, claimed, command.Default, timedOut, session.Authenticated().ServerEndpoint, teamID)
}

func runDomainTransfer(ctx context.Context, command domainTransferCommand, output, diagnostics io.Writer) error {
	if (command.ToTeam != "") == command.ToPersonal {
		return failure.Wrap("select destination", failure.InvalidTunnelFlags, errors.New("choose one of --to-personal or --to-team"))
	}
	if domain, err := naming.CanonicalizeHostname(command.Domain); err != nil || domain != command.Domain {
		return failure.Wrap("validate custom domain", failure.InvalidDomainName, errors.New("domain must use lowercase ASCII DNS labels without a trailing dot"))
	}
	session, err := openTeamSession(ctx, command.remoteFlags, "tnl domain transfer", diagnostics)
	if err != nil {
		return err
	}
	defer session.Close()
	destination := command.ToTeam
	if command.ToPersonal {
		destination = session.Identity().PersonalTeamId
	} else if !opaqueid.Valid(destination, opaqueid.TeamPrefix) {
		membership, err := session.ResolveMembership(ctx, destination)
		if err != nil {
			return err
		}
		destination = membership.TeamId
	}
	result, err := session.Authenticated().Authority.TransferDomain(ctx, command.Domain, destination, command.Accept)
	if err != nil {
		return err
	}
	blocks := []clioutput.Block{clioutput.Fields(clioutput.Field{Label: "domain", Value: result.Domain},
		clioutput.Field{Label: "from team", Value: result.SourceTeamId}, clioutput.Field{Label: "to team", Value: result.DestinationTeamId})}
	hint := "existing DNS delegation kept"
	switch result.State {
	case authorityv1.Blocked:
		if result.Blockers == nil || len(*result.Blockers) == 0 {
			return failure.Wrap("transfer domain", failure.ServerResponseInvalid, errors.New("missing transfer blockers"))
		}
		return failure.Wrap("transfer domain", failure.ServerConflict, errors.New(strings.Join(*result.Blockers, "\n")))
	case authorityv1.Offered:
		if result.ExpiresAt == nil {
			return failure.Wrap("transfer domain", failure.ServerResponseInvalid, errors.New("missing transfer offer expiry"))
		}
		blocks = append(blocks, clioutput.Fields(clioutput.Field{Label: "expires", Value: result.ExpiresAt.Format(time.RFC3339)},
			clioutput.Field{Label: "accept", Value: "tnl domain transfer " + result.Domain + " --to-team " + destination + " --accept"}))
		hint = "send the accept command to the destination owner"
	case authorityv1.Transferred:
	default:
		return failure.Wrap("transfer domain", failure.ServerResponseInvalid, errors.New("unknown transfer outcome"))
	}
	return writeHumanFrame(output, "tnl domain transfer", string(result.State), hint, blocks...)
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
	if team != "" {
		blocks = append(blocks, clioutput.Fields(clioutput.Field{Label: "team", Value: team}))
	}
	blocks = append(blocks, domainClaimDNSBlocks(claimed)...)
	if makeDefault && claimed.ClaimStage != nil {
		blocks = append(blocks, clioutput.Fields(clioutput.Field{Label: "default", Value: "when ready"}))
	}
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
		if makeDefault && claimed.ClaimStage == nil {
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
	domainID := command.Domain
	if !opaqueid.Valid(domainID, opaqueid.DomainPrefix) {
		domain, err := current.Domain(command.Domain)
		if err != nil {
			return err
		}
		domainID = domain.Id
	}
	domain, err := session.Authenticated().Authority.GetTeamDomain(ctx, current.Team().Id, domainID)
	if err != nil {
		return err
	}
	return writeDomainObservation(output, "tnl domain status", domain, domain.Id == current.Team().DefaultDomainId, session.Authenticated().ServerEndpoint, current.Team().Id)
}

func writeDomainStatus(output io.Writer, domain authorityv1.Domain, isDefault bool) error {
	return writeDomainObservation(output, "tnl domain status", domain, isDefault, "", "")
}

func writeDomainObservation(output io.Writer, command string, domain authorityv1.Domain, isDefault bool, server, team string) error {
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
	if domain.State == authorityv1.DomainStateReleasing || domain.State == authorityv1.DomainStateReleased {
		blocks = append(blocks, domainReleaseBlocks(domain, server, team)...)
	} else {
		blocks = append(blocks, domainClaimDNSBlocks(domain)...)
	}
	state, footer := domainStatusPresentation(domain)
	return writeHumanFrame(output, command, state, footer, blocks...)
}

func domainStatusPresentation(domain authorityv1.Domain) (string, string) {
	if domain.State == authorityv1.DomainStatePending && domain.ClaimStage != nil {
		switch *domain.ClaimStage {
		case authorityv1.CheckingNameservers:
			return "checking nameservers", "check domain status again"
		case authorityv1.WaitingForOwnership:
			return "waiting for ownership proof", "add the TXT record before changing any nameservers"
		case authorityv1.PreparingZone:
			return "preparing dns zone", "check status before adding nameservers"
		case authorityv1.WaitingForDelegation:
			return "waiting for delegation", "add the nameservers shown above"
		}
	}
	if domain.State == authorityv1.DomainStatePending && len(domain.RequiredRecords) == 0 {
		return "provisioning", "DNS records not yet available; check again later"
	}
	if domain.State == authorityv1.DomainStatePending {
		return "verification required", "add the DNS records to continue"
	}
	if domain.State == authorityv1.DomainStateFailed {
		return "failed", "ask your team admin to check DNS setup"
	}
	if domainReleaseConfirmed(domain) {
		return "released", "DNS authority release confirmed"
	}
	if domain.State == authorityv1.DomainStateReleasing || domain.State == authorityv1.DomainStateReleased {
		return "releasing", "release is not complete; check status again"
	}
	if domain.State == authorityv1.DomainStateReady {
		return "ready", "ready for public URLs"
	}
	return string(domain.State), "check domain status before use"
}

func domainClaimDNSBlocks(domain authorityv1.Domain) []clioutput.Block {
	var blocks []clioutput.Block
	if domain.ClaimStage != nil {
		blocks = append(blocks, clioutput.Text("tnl will manage this domain and all names beneath it"))
		if *domain.ClaimStage == authorityv1.WaitingForOwnership || *domain.ClaimStage == authorityv1.WaitingForDelegation {
			if domain.DelegationTarget != nil && *domain.DelegationTarget != "registrar" {
				blocks = append(blocks, clioutput.Fields(clioutput.Field{Label: "add records under", Value: *domain.DelegationTarget}),
					clioutput.Text("leave the parent domain's nameservers unchanged"))
			} else if *domain.ClaimStage == authorityv1.WaitingForDelegation {
				blocks = append(blocks, clioutput.Text("change the domain's nameservers at its registrar; existing DNS records are not copied"))
			}
		}
		if domain.ClaimExpiresAt != nil {
			blocks = append(blocks, clioutput.Fields(clioutput.Field{Label: "claim expires", Value: domain.ClaimExpiresAt.UTC().Format(time.RFC3339)}))
		}
	}
	return append(blocks, domainDNSRecordBlocks(domain.RequiredRecords)...)
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
		if domain.ClaimStage != nil {
			return domainStatusPresentation(domain)
		}
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
		observed, readErr := session.Authenticated().Authority.GetTeamDomain(ctx, current.Team().Id, domain.Id)
		if readErr != nil {
			// the mutation was acknowledged, but missing status is not completion.
			domain.State, domain.Release = authorityv1.DomainStateReleasing, nil
			return errors.Join(readErr, writeDomainObservation(output, "tnl domain release", domain, false, session.Authenticated().ServerEndpoint, current.Team().Id))
		}
		if observed.State != authorityv1.DomainStateReleasing && observed.State != authorityv1.DomainStateReleased {
			return failure.Wrap("read domain release", failure.ServerResponseInvalid, errors.New("domain release acknowledgement was not followed by release state"))
		}
		return writeDomainObservation(output, "tnl domain release", observed, false, session.Authenticated().ServerEndpoint, current.Team().Id)
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

func (a *commandApp) newDomainCommand() *cobra.Command {
	f := a.flags
	cDomain := &cobra.Command{Use: "domain", Short: "Set up a custom domain for your team's services.", GroupID: "access"}
	cDomainClaim := &cobra.Command{Use: "claim", Short: "Claim a domain and show the required DNS setup."}
	a.leaf(cDomainClaim, &f.Domain.Claim, func(call commandCall) error {
		return runDomainClaim(call.ctx, f.Domain.Claim, a.out, a.errOut)
	})
	cDomain.AddCommand(cDomainClaim)
	cDomainDefault := &cobra.Command{Use: "default", Short: "Set the selected team's default domain."}
	a.leaf(cDomainDefault, &f.Domain.Default, func(call commandCall) error {
		return runDomainDefault(call.ctx, f.Domain.Default, a.out, a.errOut)
	})
	cDomain.AddCommand(cDomainDefault)
	cDomainList := &cobra.Command{Use: "list", Short: "List domains available to the selected team."}
	a.leaf(cDomainList, &f.Domain.List, func(call commandCall) error {
		return runDomainList(call.ctx, f.Domain.List, a.out, a.errOut)
	})
	cDomain.AddCommand(cDomainList)
	cDomainStatus := &cobra.Command{Use: "status", Short: "Show DNS setup for one team domain by name or ID."}
	a.leaf(cDomainStatus, &f.Domain.Status, func(call commandCall) error {
		return runDomainStatus(call.ctx, f.Domain.Status, a.out, a.errOut)
	})
	cDomain.AddCommand(cDomainStatus)
	cDomainRelease := &cobra.Command{Use: "release", Short: "Release a custom domain."}
	a.leaf(cDomainRelease, &f.Domain.Release, func(call commandCall) error {
		return runDomainRelease(call.ctx, f.Domain.Release, a.out, a.errOut)
	})
	cDomain.AddCommand(cDomainRelease)
	cDomainTransfer := &cobra.Command{Use: "transfer", Short: "Transfer a custom domain without changing its DNS delegation."}
	a.leaf(cDomainTransfer, &f.Domain.Transfer, func(call commandCall) error {
		return runDomainTransfer(call.ctx, f.Domain.Transfer, a.out, a.errOut)
	})
	cDomain.AddCommand(cDomainTransfer)
	return cDomain
}

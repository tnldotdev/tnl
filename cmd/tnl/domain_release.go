package main

import (
	"time"

	"github.com/tnldotdev/tnl/internal/clioutput"
	authorityv1 "github.com/tnldotdev/tnl/pkg/api/control/authority/v1"
)

func domainReleaseConfirmed(domain authorityv1.Domain) bool {
	return domain.State == authorityv1.DomainStateReleased && domain.Release != nil &&
		!domain.Release.CompletionUnknown && domain.Release.ReleasedAt != nil
}

func domainReleaseBlocks(domain authorityv1.Domain, server, team string) []clioutput.Block {
	blocks := []clioutput.Block{}
	if domain.Release != nil {
		blocks = append(blocks, clioutput.Fields(clioutput.Field{Label: "observed", Value: domain.Release.ObservedAt.UTC().Format(time.RFC3339)}))
		for _, blocker := range domain.Release.Blockers {
			blocks = append(blocks, clioutput.Fields(clioutput.Field{Label: "blocked", Value: domainReleaseBlockerText(blocker)}))
		}
		if expiry := domain.Release.CertificateExpiresAt; expiry != nil {
			blocks = append(blocks, clioutput.Fields(clioutput.Field{Label: "certificate expires", Value: expiry.UTC().Format(time.RFC3339)}),
				clioutput.Text("Certificate expiry is not a release completion date."))
		}
	}
	if domainReleaseConfirmed(domain) {
		return append(blocks, clioutput.Fields(clioutput.Field{Label: "released", Value: domain.Release.ReleasedAt.UTC().Format(time.RFC3339)}))
	}
	if domain.DelegationTarget != nil {
		if *domain.DelegationTarget == "registrar" {
			blocks = append(blocks, clioutput.Text("move the domain off the tnl nameservers at its registrar"))
		} else {
			blocks = append(blocks, clioutput.Text("remove the tnl nameservers for this domain from its parent DNS"))
		}
	}
	next := "tnl domain status " + domain.Id
	if server != "" {
		next += " --server=" + server
	}
	if team != "" {
		next += " --team=" + team
	}
	return append(blocks,
		clioutput.Fields(clioutput.Field{Label: "completion", Value: "unknown"},
			clioutput.Field{Label: "next", Value: next}),
		clioutput.Text("Wait for cleanup and final DNS authority release; ask your team admin if it stays blocked."))
}

func domainReleaseBlockerText(blocker authorityv1.DomainReleaseBlocker) string {
	switch blocker {
	case authorityv1.Deployments:
		return "saved deployments remain; remove them through their project configuration"
	case authorityv1.Services:
		return "saved services remain; remove them through their owner"
	case authorityv1.EndpointDns:
		return "endpoint DNS removal is not confirmed"
	case authorityv1.ChallengeCleanup:
		return "certificate challenge cleanup is not confirmed"
	case authorityv1.Issuance:
		return "certificate issuance is not settled"
	case authorityv1.UncertainIssuance:
		return "certificate issuance outcome is unknown"
	case authorityv1.Certificate:
		return "an issued certificate has not expired"
	case authorityv1.DnsAuthority:
		return "final DNS authority release is not confirmed"
	default:
		return "release work is not settled"
	}
}

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"slices"

	"github.com/tnldotdev/tnl/internal/clioutput"
	"github.com/tnldotdev/tnl/internal/controlclient"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/localproxy"
	"github.com/tnldotdev/tnl/internal/opaqueid"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

type publicURLCredentialCommand struct {
	Create publicURLCredentialCreateCommand `cmd:"" help:"Create a credential for an existing or new saved public URL."`
	List   publicURLCredentialListCommand   `cmd:"" help:"List credentials without showing their secrets."`
	Revoke publicURLCredentialRevokeCommand `cmd:"" help:"Revoke a credential; its active run stops on heartbeat."`
}

type publicURLCredentialCreateCommand struct {
	scopedTeamFlags `embed:""`
	PublicURLID     string   `arg:"" name:"public-url-id" optional:"" help:"Saved public URL ID. Omit to create a URL with --public-url and --target."`
	PublicURL       string   `name:"public-url" help:"Exact public URL to save before issuing the credential."`
	Target          string   `name:"target" help:"HTTP or HTTPS target origin to save; it need not be reachable from this machine."`
	AllowIP         []string `name:"allow-ip" help:"Visitor IP address or prefix; repeat for more visitors."`
	AllowAllIPs     bool     `name:"allow-all-ips" help:"Allow visitors from every IP."`
}

type publicURLCredentialListCommand struct {
	scopedTeamFlags `embed:""`
	PublicURLID     string `arg:"" name:"public-url-id" required:""`
}

type publicURLCredentialRevokeCommand struct {
	scopedTeamFlags `embed:""`
	PublicURLID     string `arg:"" name:"public-url-id" required:""`
	CredentialID    string `arg:"" name:"credential-id" required:""`
}

func runURLCredentialCreate(ctx context.Context, flags publicURLCredentialCreateCommand, output, diagnostics io.Writer) error {
	if flags.PublicURLID != "" && (flags.PublicURL != "" || flags.Target != "" || flags.AllowIP != nil || flags.AllowAllIPs) {
		return failure.Wrap("select public URL", failure.InvalidTunnelFlags, errors.New("choose an existing public URL ID or supply --public-url and --target"))
	}
	if flags.PublicURLID == "" && (flags.PublicURL == "" || flags.Target == "") {
		return failure.Wrap("select public URL", failure.InvalidTunnelFlags, errors.New("pass a public URL ID or set both --public-url and --target"))
	}
	session, err := openTeamSession(ctx, flags.selection(), "tnl url credential create", diagnostics)
	if err != nil {
		return err
	}
	defer session.Close()
	urlID := flags.PublicURLID
	if urlID == "" {
		urlID, err = reservePublishCredentialURL(ctx, session, flags)
		if err != nil {
			return err
		}
	} else {
		current, err := session.current(ctx)
		if err != nil {
			return err
		}
		selected, err := session.authenticated.Control.GetPublicURL(ctx, urlID)
		if err != nil {
			return err
		}
		if selected.TeamId != current.team.Id {
			return controlclient.ErrNotFound
		}
	}
	issued, err := session.authenticated.Control.CreatePublicURLPublishCredential(ctx, urlID)
	if err != nil {
		return err
	}
	// one-time credentials remain exact raw values on stdout.
	_, err = fmt.Fprintln(output, issued.Credential)
	return err
}

func reservePublishCredentialURL(ctx context.Context, session *teamSession, flags publicURLCredentialCreateCommand) (string, error) {
	target, err := localproxy.NormalizeTarget(flags.Target)
	if err != nil {
		return "", err
	}
	team := flags.Team
	if team == "" {
		team = flags.ProjectTeam
	}
	services, err := preparePublisherServices(ctx, session.database, session.authenticated.ServerEndpoint, flags.PublicURL, "", "", team, false, session.authenticated)
	if err != nil {
		return "", err
	}
	policy, err := resolveIPPolicy(ctx, session.authenticated.Control, flags.AllowIP, flags.AllowAllIPs)
	if err != nil {
		return "", err
	}
	route, err := session.authenticated.Control.GetPublicURLByHostname(ctx, services.teamID, services.hostname)
	if errors.Is(err, controlclient.ErrNotFound) {
		key, keyErr := opaqueid.New(opaqueid.IdempotencyPrefix)
		if keyErr != nil {
			return "", keyErr
		}
		request := controlv1.CreatePublicURLRequest{
			TeamId: services.teamID, DomainId: services.domainID, CanonicalHostname: services.hostname,
			Target: target, PublicUrlScope: services.publicURLScope, Purpose: controlv1.App,
		}
		if services.publicURLScope == controlv1.Member {
			request.MembershipId = &services.membershipID
		}
		if policy.prefixes != nil {
			copy := slices.Clone(policy.prefixes)
			request.AllowedIpPrefixes = &copy
		}
		route, err = session.authenticated.Control.CreatePublicURL(ctx, request, key)
	}
	if err != nil {
		return "", err
	}
	currentPolicy := []string{}
	if route.AllowedIpPrefixes != nil {
		currentPolicy = *route.AllowedIpPrefixes
	}
	if route.Target != target || route.CanonicalHostname != services.hostname || route.Purpose != controlv1.App ||
		route.Ephemeral || !slices.Equal(currentPolicy, policy.prefixes) {
		return "", failure.Wrap("reserve public URL for credential", failure.PublishCredentialMismatch,
			fmt.Errorf("public URL %s already exists with a different target or visitor policy", route.Id))
	}
	return route.Id, nil
}

func runURLCredentialList(ctx context.Context, flags publicURLCredentialListCommand, output, diagnostics io.Writer) error {
	session, err := openTeamSession(ctx, flags.selection(), "tnl url credential list", diagnostics)
	if err != nil {
		return err
	}
	defer session.Close()
	if err := checkSelectedCredentialURL(ctx, session, flags.PublicURLID); err != nil {
		return err
	}
	items, err := session.authenticated.Control.ListPublicURLPublishCredentials(ctx, flags.PublicURLID)
	if err != nil {
		return err
	}
	blocks := make([]clioutput.Block, 0, len(items))
	for _, item := range items {
		state := "active"
		if item.RevokedAt != nil {
			state = "revoked"
		}
		blocks = append(blocks, clioutput.Section(item.Id, clioutput.Fields(
			clioutput.Field{Label: "state", Value: state},
			clioutput.Field{Label: "expires", Value: item.ExpiresAt.UTC().Format("2006-01-02T15:04:05Z")},
		)))
	}
	return writeHumanFrame(output, "tnl url credential list", countState(len(items), "credential", "credentials"), "", blocks...)
}

func runURLCredentialRevoke(ctx context.Context, flags publicURLCredentialRevokeCommand, output, diagnostics io.Writer) error {
	session, err := openTeamSession(ctx, flags.selection(), "tnl url credential revoke", diagnostics)
	if err != nil {
		return err
	}
	defer session.Close()
	if err := checkSelectedCredentialURL(ctx, session, flags.PublicURLID); err != nil {
		return err
	}
	if err := session.authenticated.Control.RevokePublicURLPublishCredential(ctx, flags.PublicURLID, flags.CredentialID); err != nil {
		return err
	}
	return writeHumanFrame(output, "tnl url credential revoke", "revoked", "active run stops on its next heartbeat",
		clioutput.Fields(clioutput.Field{Label: "credential", Value: flags.CredentialID}))
}

func checkSelectedCredentialURL(ctx context.Context, session *teamSession, publicURLID string) error {
	current, err := session.current(ctx)
	if err != nil {
		return err
	}
	selected, err := session.authenticated.Control.GetPublicURL(ctx, publicURLID)
	if err != nil {
		return err
	}
	if selected.TeamId != current.team.Id {
		return controlclient.ErrNotFound
	}
	return nil
}

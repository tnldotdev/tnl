package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"time"

	"github.com/tnldotdev/tnl/internal/clioutput"
	"github.com/tnldotdev/tnl/internal/controlclient"
	"github.com/tnldotdev/tnl/internal/credentials"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/localproxy"
	"github.com/tnldotdev/tnl/internal/opaqueid"
	"github.com/tnldotdev/tnl/internal/projectconfig"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

type credentialOutputMode string

const (
	credentialOutputHuman credentialOutputMode = "human"
	credentialOutputJSON  credentialOutputMode = "json"
)

type publicURLCredentialCommand struct {
	Create publicURLCredentialCreateCommand `cmd:"" help:"Create a credential for an existing or new saved public URL."`
	List   publicURLCredentialListCommand   `cmd:"" help:"List credentials without showing their secrets."`
	Revoke publicURLCredentialRevokeCommand `cmd:"" help:"Revoke a credential; its active run stops on heartbeat."`
}

type publicURLCredentialCreateCommand struct {
	scopedTeamFlags `embed:""`
	Selector        string               `arg:"" name:"service-or-public-url-id" optional:"" help:"Configured service or saved public URL ID. Omit to use a single service or create a new saved URL."`
	PublicURL       string               `name:"public-url" help:"Exact public URL to save before issuing the credential."`
	Name            string               `name:"name" help:"One label under the selected domain or namespace."`
	Domain          string               `name:"domain" help:"Team domain for this public URL."`
	Target          string               `name:"target" help:"HTTP or HTTPS target origin to save with the public URL."`
	AllowIP         []string             `name:"allow-ip" help:"Visitor IP address or prefix; repeat for more visitors."`
	AllowAllIPs     bool                 `name:"allow-all-ips" help:"Allow visitors from every IP."`
	Output          credentialOutputMode `name:"output" enum:"human,json" default:"human" help:"Output format: ${enum}."`
}

type publicURLCredentialListCommand struct {
	scopedTeamFlags `embed:""`
	PublicURLID     string               `arg:"" name:"public-url-id" optional:"" help:"Filter the selected team to one saved public URL."`
	Output          credentialOutputMode `name:"output" enum:"human,json" default:"human" help:"Output format: ${enum}."`
}

type publicURLCredentialRevokeCommand struct {
	scopedTeamFlags `embed:""`
	CredentialID    string               `arg:"" name:"credential-id" required:""`
	Output          credentialOutputMode `name:"output" enum:"human,json" default:"human" help:"Output format: ${enum}."`
}

type publicURLCredentialListEntry struct {
	CredentialID string     `json:"credential_id"`
	PublicURLID  string     `json:"public_url_id"`
	PublicURL    string     `json:"public_url"`
	CreatedAt    time.Time  `json:"created_at"`
	ExpiresAt    time.Time  `json:"expires_at"`
	RevokedAt    *time.Time `json:"revoked_at,omitempty"`
}

type publicURLCredentialListResult struct {
	SchemaVersion int                            `json:"schema_version"`
	Credentials   []publicURLCredentialListEntry `json:"credentials"`
}

func credentialListEntry(item controlv1.PublicURLPublishCredential) publicURLCredentialListEntry {
	return publicURLCredentialListEntry{
		CredentialID: item.Id, PublicURLID: item.PublicUrlId, PublicURL: item.PublicUrl,
		CreatedAt: item.CreatedAt, ExpiresAt: item.ExpiresAt, RevokedAt: item.RevokedAt,
	}
}

type publicURLCredentialCreateResult struct {
	SchemaVersion int       `json:"schema_version"`
	PublicURL     string    `json:"public_url"`
	PublicURLID   string    `json:"public_url_id"`
	Target        string    `json:"target"`
	CredentialID  string    `json:"credential_id"`
	Credential    string    `json:"credential"`
	ExpiresAt     time.Time `json:"expires_at"`
}

func runURLCredentialCreate(ctx context.Context, flags publicURLCredentialCreateCommand, project projectConfiguration, output, diagnostics io.Writer) error {
	isURLID := opaqueid.Valid(flags.Selector, opaqueid.PublicURLPrefix)
	if isURLID && (flags.PublicURL != "" || flags.Name != "" || flags.Domain != "" || flags.Target != "" || flags.AllowIP != nil || flags.AllowAllIPs) {
		return failure.Wrap("select public URL", failure.InvalidTunnelFlags, errors.New("an existing public URL ID does not take hostname, target, or visitor policy options"))
	}
	if !isURLID {
		var err error
		flags, err = resolveCredentialCreateConfig(flags, project)
		if err != nil {
			return err
		}
	}
	session, err := openTeamSession(ctx, flags.selection(), "tnl url credential create", diagnostics)
	if err != nil {
		return err
	}
	defer session.Close()
	var route controlv1.PublicURL
	if !isURLID {
		route, err = reservePublishCredentialURL(ctx, session, flags)
		if err != nil {
			return err
		}
	} else {
		current, err := session.current(ctx)
		if err != nil {
			return err
		}
		route, err = session.authenticated.Control.GetPublicURL(ctx, flags.Selector)
		if err != nil {
			return err
		}
		if route.TeamId != current.team.Id {
			return controlclient.ErrNotFound
		}
	}
	issued, err := session.authenticated.Control.CreatePublicURLPublishCredential(ctx, route.Id)
	if err != nil {
		return err
	}
	if issued.PublicUrlId != route.Id || issued.Id == "" || !issued.ExpiresAt.After(time.Now()) {
		return failure.Wrap("validate issued credential", failure.ServerResponseInvalid, errors.New("control returned an invalid public URL publish credential"))
	}
	if _, _, _, err := credentials.ParsePublicURLPublishCredential(credentials.PublicURLPublishCredential(issued.Credential)); err != nil {
		return failure.Wrap("validate issued credential", failure.ServerResponseInvalid, err)
	}
	result := publicURLCredentialCreateResult{
		SchemaVersion: 1, PublicURL: "https://" + route.CanonicalHostname, PublicURLID: route.Id,
		Target: route.Target, CredentialID: issued.Id, Credential: issued.Credential, ExpiresAt: issued.ExpiresAt,
	}
	return writeCredentialCreateResult(flags.Output, result, output, diagnostics)
}

func writeCredentialCreateResult(mode credentialOutputMode, result publicURLCredentialCreateResult, output, diagnostics io.Writer) error {
	if mode == credentialOutputJSON {
		return json.NewEncoder(output).Encode(result)
	}
	fields := []clioutput.Field{{Label: "public URL", Value: result.PublicURL}}
	if result.Target != "" {
		fields = append(fields, clioutput.Field{Label: "target", Value: result.Target})
	}
	fields = append(fields,
		clioutput.Field{Label: "URL ID", Value: result.PublicURLID},
		clioutput.Field{Label: "credential", Value: result.CredentialID},
		clioutput.Field{Label: "expires", Value: result.ExpiresAt.UTC().Format(time.RFC3339)})
	if err := writeHumanFrame(diagnostics, "tnl url credential create", "created", "save the credential; it will not be shown again",
		clioutput.Fields(fields...)); err != nil {
		return err
	}
	// one-time credentials remain exact raw values on stdout.
	_, err := fmt.Fprintln(output, result.Credential)
	return err
}

func resolveCredentialCreateConfig(flags publicURLCredentialCreateCommand, project projectConfiguration) (publicURLCredentialCreateCommand, error) {
	service := flags.Selector
	if service == "" && flags.Target == "" && flags.PublicURL == "" && flags.Name == "" && project.Found() && len(project.Config.Services) != 0 {
		selected, err := project.defaultService()
		if err != nil {
			return flags, err
		}
		service = selected
	}
	if service != "" {
		if !project.Found() {
			return flags, failure.Wrap("select project service", failure.ServiceNotConfigured, errors.New("a configured project service is required"))
		}
		effective, err := project.EffectiveService(service)
		if err != nil {
			return flags, failure.Wrap("select project service", failure.ServiceNotConfigured, err)
		}
		if effective.Tunnel != nil {
			if flags.PublicURL == "" && flags.Name == "" {
				if effective.Tunnel.PublicURL != nil {
					flags.PublicURL = *effective.Tunnel.PublicURL
				} else if effective.Tunnel.Name != nil {
					flags.Name = *effective.Tunnel.Name
				}
			}
			if flags.Domain == "" && effective.Tunnel.Domain != nil {
				flags.Domain = *effective.Tunnel.Domain
			}
			if flags.AllowIP == nil && !flags.AllowAllIPs {
				flags.AllowIP = slices.Clone(effective.Tunnel.AllowIP)
				if flags.AllowIP == nil && effective.Tunnel.AllowAllIPs != nil {
					flags.AllowAllIPs = *effective.Tunnel.AllowAllIPs
				}
			}
		}
		if flags.PublicURL == "" && flags.Name == "" {
			flags.Name = projectconfig.ServiceWorktreeLabel(service, project.Worktree)
		}
	}
	if flags.Name != "" && flags.PublicURL != "" {
		return flags, failure.Wrap("validate public URL options", failure.InvalidTunnelFlags, errors.New("--name and --public-url are mutually exclusive"))
	}
	return flags, nil
}

func reservePublishCredentialURL(ctx context.Context, session *teamSession, flags publicURLCredentialCreateCommand) (controlv1.PublicURL, error) {
	target := ""
	if flags.Target != "" {
		var err error
		target, err = localproxy.NormalizeTarget(flags.Target)
		if err != nil {
			return controlv1.PublicURL{}, err
		}
	}
	team := flags.Team
	if team == "" {
		team = flags.ProjectTeam
	}
	services, err := preparePublisherServices(ctx, session.database, session.authenticated.ServerEndpoint, flags.PublicURL, flags.Name, flags.Domain, team, false, session.authenticated)
	if err != nil {
		return controlv1.PublicURL{}, err
	}
	policy, err := resolveIPPolicy(ctx, session.authenticated.Control, flags.AllowIP, flags.AllowAllIPs)
	if err != nil {
		return controlv1.PublicURL{}, err
	}
	route, err := session.authenticated.Control.GetPublicURLByHostname(ctx, services.teamID, services.hostname)
	if errors.Is(err, controlclient.ErrNotFound) {
		key, keyErr := opaqueid.New(opaqueid.IdempotencyPrefix)
		if keyErr != nil {
			return controlv1.PublicURL{}, keyErr
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
		return controlv1.PublicURL{}, err
	}
	currentPolicy := []string{}
	if route.AllowedIpPrefixes != nil {
		currentPolicy = *route.AllowedIpPrefixes
	}
	if target != "" && route.Target != target || route.CanonicalHostname != services.hostname || route.Purpose != controlv1.App ||
		route.Ephemeral || !slices.Equal(currentPolicy, policy.prefixes) {
		return controlv1.PublicURL{}, failure.Wrap("reserve public URL for credential", failure.PublishCredentialMismatch,
			fmt.Errorf("public URL %s already exists with a different target or visitor policy", route.Id))
	}
	return route, nil
}

func runURLCredentialList(ctx context.Context, flags publicURLCredentialListCommand, output, diagnostics io.Writer) error {
	session, err := openTeamSession(ctx, flags.selection(), "tnl url credential list", diagnostics)
	if err != nil {
		return err
	}
	defer session.Close()
	if flags.PublicURLID != "" {
		if err := checkSelectedCredentialURL(ctx, session, flags.PublicURLID); err != nil {
			return err
		}
	}
	current, err := session.current(ctx)
	if err != nil {
		return err
	}
	items, err := session.authenticated.Control.AllTeamPublicURLPublishCredentials(ctx, current.team.Id)
	if err != nil {
		return err
	}
	result := publicURLCredentialListResult{SchemaVersion: 1, Credentials: []publicURLCredentialListEntry{}}
	for _, item := range items {
		if flags.PublicURLID != "" && item.PublicUrlId != flags.PublicURLID {
			continue
		}
		result.Credentials = append(result.Credentials, credentialListEntry(item))
	}
	return writeCredentialListResult(flags.Output, result, time.Now(), output)
}

func writeCredentialListResult(mode credentialOutputMode, result publicURLCredentialListResult, now time.Time, output io.Writer) error {
	if mode == credentialOutputJSON {
		return json.NewEncoder(output).Encode(result)
	}
	blocks := make([]clioutput.Block, 0, len(result.Credentials))
	for _, item := range result.Credentials {
		state := "active"
		if item.RevokedAt != nil {
			state = "revoked"
		} else if !item.ExpiresAt.After(now) {
			state = "expired"
		}
		blocks = append(blocks, clioutput.Section(item.CredentialID, clioutput.Fields(
			clioutput.Field{Label: "public URL", Value: item.PublicURL},
			clioutput.Field{Label: "state", Value: state},
			clioutput.Field{Label: "expires", Value: item.ExpiresAt.UTC().Format("2006-01-02T15:04:05Z")},
		)))
	}
	return writeHumanFrame(output, "tnl url credential list", countState(len(result.Credentials), "credential", "credentials"), "", blocks...)
}

func runURLCredentialRevoke(ctx context.Context, flags publicURLCredentialRevokeCommand, output, diagnostics io.Writer) error {
	session, err := openTeamSession(ctx, flags.selection(), "tnl url credential revoke", diagnostics)
	if err != nil {
		return err
	}
	defer session.Close()
	current, err := session.current(ctx)
	if err != nil {
		return err
	}
	revoked, err := session.authenticated.Control.RevokePublishCredentialByID(ctx, current.team.Id, flags.CredentialID)
	if err != nil {
		return err
	}
	if revoked.RevokedAt == nil || revoked.Id != flags.CredentialID || revoked.PublicUrl == "" {
		return failure.Wrap("validate revoked credential", failure.ServerResponseInvalid, errors.New("control returned incomplete revoked credential metadata"))
	}
	return writeCredentialRevokeResult(flags.Output, revoked, output)
}

func writeCredentialRevokeResult(mode credentialOutputMode, revoked controlv1.PublicURLPublishCredential, output io.Writer) error {
	if mode == credentialOutputJSON {
		return json.NewEncoder(output).Encode(struct {
			SchemaVersion int       `json:"schema_version"`
			CredentialID  string    `json:"credential_id"`
			PublicURLID   string    `json:"public_url_id"`
			PublicURL     string    `json:"public_url"`
			RevokedAt     time.Time `json:"revoked_at"`
		}{SchemaVersion: 1, CredentialID: revoked.Id, PublicURLID: revoked.PublicUrlId,
			PublicURL: revoked.PublicUrl, RevokedAt: *revoked.RevokedAt})
	}
	return writeHumanFrame(output, "tnl url credential revoke", "revoked", "active run stops on its next heartbeat",
		clioutput.Fields(clioutput.Field{Label: "credential", Value: revoked.Id}, clioutput.Field{Label: "public URL", Value: revoked.PublicUrl}))
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

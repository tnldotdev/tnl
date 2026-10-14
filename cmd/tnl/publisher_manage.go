package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/tnldotdev/tnl/internal/clioutput"
	"github.com/tnldotdev/tnl/internal/controlclient"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/opaqueid"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

type publisherCommand struct {
	Enroll publisherEnrollCommand `cmd:"" help:"Issue a one-use enrollment key for a saved URL or namespace."`
	List   publisherListCommand   `cmd:"" help:"List publisher identities and grants."`
	Revoke publisherRevokeCommand `cmd:"" help:"Revoke a publisher identity."`
	Grant  struct {
		Add    publisherGrantAddCommand    `cmd:"" help:"Add a saved URL or namespace grant."`
		Revoke publisherGrantRevokeCommand `cmd:"" help:"Revoke one grant."`
	} `cmd:"" help:"Manage publisher grants."`
}

type publisherEnrollCommand struct {
	scopedTeamFlags `embed:""`
	PublicURLID     string `arg:"" name:"public-url-id" optional:"" help:"Saved public URL ID."`
	Name            string `name:"name" default:"publisher" help:"Publisher identity name."`
	Namespace       bool   `name:"namespace" help:"Grant temporary public URLs in the authorized namespace."`
	Domain          string `name:"domain" help:"Ready team domain for a namespace grant."`
	Automation      bool   `name:"automation" help:"Expire the initial grant after one hour."`
}

type publisherListCommand struct {
	scopedTeamFlags `embed:""`
	After           string `name:"after" help:"Publisher ID after which to read the next page."`
}

type publisherRevokeCommand struct {
	scopedTeamFlags `embed:""`
	ID              string `arg:"" name:"publisher-id" required:""`
}

type publisherGrantAddCommand struct {
	scopedTeamFlags `embed:""`
	PublisherID     string `arg:"" name:"publisher-id" required:""`
	PublicURLID     string `name:"public-url-id" help:"Saved public URL to grant."`
	Namespace       bool   `name:"namespace" help:"Grant temporary public URLs in a namespace."`
	Domain          string `name:"domain" help:"Ready team domain for the namespace."`
}

type publisherGrantRevokeCommand struct {
	scopedTeamFlags `embed:""`
	PublisherID     string `arg:"" name:"publisher-id" required:""`
	GrantID         string `arg:"" name:"grant-id" required:""`
}

func publisherScopeRequest(ctx context.Context, session *teamSession, current teamContext, urlID string, namespace bool, domainName string) (controlv1.TeamID, *controlv1.PublicURLID, *controlv1.DomainID, *controlv1.PublicURLScope, error) {
	if namespace == (urlID != "") || !namespace && domainName != "" {
		return "", nil, nil, nil, failure.Wrap("select publisher grant", failure.InvalidTunnelFlags, errors.New("select a saved public URL ID or --namespace"))
	}
	if !namespace {
		if !opaqueid.Valid(urlID, opaqueid.PublicURLPrefix) {
			return "", nil, nil, nil, failure.Wrap("select public URL", failure.InvalidTunnelFlags, errors.New("pass a saved public URL ID"))
		}
		route, err := session.authenticated.Control.GetPublicURL(ctx, urlID)
		if err != nil {
			return "", nil, nil, nil, err
		}
		if route.TeamId != current.team.Id || route.Ephemeral || route.Purpose != controlv1.App || route.LifecycleState != controlv1.Enabled {
			return "", nil, nil, nil, controlclient.ErrNotFound
		}
		id := controlv1.PublicURLID(urlID)
		return controlv1.TeamID(current.team.Id), &id, nil, nil, nil
	}
	domain, err := readyDomain(current, domainName)
	if err != nil {
		return "", nil, nil, nil, err
	}
	_, direct := current.namespace(domain)
	scope := controlv1.Member
	if direct {
		scope = controlv1.Shared
	}
	return controlv1.TeamID(current.team.Id), nil, &domain.Id, &scope, nil
}

func runPublisherEnroll(ctx context.Context, flags publisherEnrollCommand, output, diagnostics io.Writer) error {
	if !naming.ValidServiceName(flags.Name) {
		return failure.Wrap("name publisher", failure.InvalidTunnelFlags, errors.New("pass a lowercase service name"))
	}
	session, err := openTeamSession(ctx, flags.selection(), "tnl publisher enroll", diagnostics)
	if err != nil {
		return err
	}
	defer session.Close()
	current, err := session.currentWithDomains(ctx)
	if err != nil {
		return err
	}
	team, urlID, domain, scope, err := publisherScopeRequest(ctx, session, current, flags.PublicURLID, flags.Namespace, flags.Domain)
	if err != nil {
		return err
	}
	kind := controlv1.CreatePublisherEnrollmentRequestKindInstalled
	if flags.Automation {
		kind = controlv1.CreatePublisherEnrollmentRequestKindAutomation
	}
	issued, err := session.authenticated.Control.CreatePublisherEnrollment(ctx, controlv1.CreatePublisherEnrollmentRequest{
		TeamId: team, PublicUrlId: urlID, DomainId: domain, PublicUrlScope: scope, Name: flags.Name, Kind: kind,
	})
	if err != nil {
		return err
	}
	if issued.EnrollmentKey == "" || issued.Id == "" || !issued.ExpiresAt.After(time.Now()) ||
		(urlID != nil && (issued.PublicUrlId == nil || *issued.PublicUrlId != *urlID)) {
		return failure.Wrap("validate publisher enrollment", failure.ServerResponseInvalid, errors.New("control returned a different enrollment"))
	}
	// one-time credentials are exact raw values on stdout.
	_, err = fmt.Fprintln(output, issued.EnrollmentKey)
	return err
}

func runPublisherList(ctx context.Context, flags publisherListCommand, output, diagnostics io.Writer) error {
	if flags.After != "" && !opaqueid.Valid(flags.After, opaqueid.PublisherIdentityPrefix) {
		return failure.Wrap("select publisher page", failure.InvalidTunnelFlags, errors.New("--after needs a publisher identity ID"))
	}
	session, err := openTeamSession(ctx, flags.selection(), "tnl publisher list", diagnostics)
	if err != nil {
		return err
	}
	defer session.Close()
	current, err := session.current(ctx)
	if err != nil {
		return err
	}
	page, err := session.authenticated.Control.ListPublisherIdentities(ctx, current.team.Id, flags.After)
	if err != nil {
		return err
	}
	blocks := make([]clioutput.Block, 0, len(page.Identities))
	now := time.Now().UTC()
	for _, identity := range page.Identities {
		state := "active"
		if identity.RevokedAt != nil {
			state = "revoked"
		}
		fields := []clioutput.Field{{Label: "publisher", Value: identity.Id}, {Label: "kind", Value: string(identity.Kind)}, {Label: "state", Value: state}}
		for _, grant := range identity.Grants {
			scope := grant.Id
			grantState := "active"
			if grant.RevokedAt != nil {
				grantState = "revoked"
			} else if grant.ExpiresAt != nil && !grant.ExpiresAt.After(now) {
				grantState = "expired"
			}
			if grant.PublicUrlId != nil {
				scope += " " + string(*grant.PublicUrlId)
			} else if grant.Namespace != nil {
				scope += " " + *grant.Namespace
			}
			fields = append(fields, clioutput.Field{Label: "grant", Value: scope + " (" + grantState + ")"})
		}
		blocks = append(blocks, clioutput.Section(identity.Name, clioutput.Fields(fields...)))
	}
	footer := ""
	if page.NextCursor != nil {
		footer = "next: tnl publisher list --after " + *page.NextCursor
	}
	return writeHumanFrame(output, "tnl publisher list", countState(len(page.Identities), "publisher", "publishers"), footer, blocks...)
}

func runPublisherRevoke(ctx context.Context, flags publisherRevokeCommand, output, diagnostics io.Writer) error {
	if !opaqueid.Valid(flags.ID, opaqueid.PublisherIdentityPrefix) {
		return failure.Wrap("select publisher", failure.InvalidTunnelFlags, errors.New("pass a publisher identity ID"))
	}
	session, err := openTeamSession(ctx, flags.selection(), "tnl publisher revoke", diagnostics)
	if err != nil {
		return err
	}
	defer session.Close()
	current, err := session.current(ctx)
	if err != nil {
		return err
	}
	if err := session.authenticated.Control.RevokePublisherIdentity(ctx, current.team.Id, flags.ID); err != nil {
		return err
	}
	return writeHumanFrame(output, "tnl publisher revoke", "revoked", "active runs stop on heartbeat", clioutput.Fields(clioutput.Field{Label: "publisher", Value: flags.ID}))
}

func runPublisherGrantAdd(ctx context.Context, flags publisherGrantAddCommand, output, diagnostics io.Writer) error {
	if !opaqueid.Valid(flags.PublisherID, opaqueid.PublisherIdentityPrefix) {
		return failure.Wrap("select publisher", failure.InvalidTunnelFlags, errors.New("pass a publisher identity ID"))
	}
	session, err := openTeamSession(ctx, flags.selection(), "tnl publisher grant add", diagnostics)
	if err != nil {
		return err
	}
	defer session.Close()
	current, err := session.currentWithDomains(ctx)
	if err != nil {
		return err
	}
	team, urlID, domain, scope, err := publisherScopeRequest(ctx, session, current, flags.PublicURLID, flags.Namespace, flags.Domain)
	if err != nil {
		return err
	}
	grant, err := session.authenticated.Control.CreatePublisherGrant(ctx, flags.PublisherID, controlv1.CreatePublisherGrantRequest{
		TeamId: team, PublicUrlId: urlID, DomainId: domain, PublicUrlScope: scope,
	})
	if err != nil {
		return err
	}
	return writeHumanFrame(output, "tnl publisher grant add", "created", "", clioutput.Fields(
		clioutput.Field{Label: "publisher", Value: flags.PublisherID}, clioutput.Field{Label: "grant", Value: grant.Id}))
}

func runPublisherGrantRevoke(ctx context.Context, flags publisherGrantRevokeCommand, output, diagnostics io.Writer) error {
	if !opaqueid.Valid(flags.PublisherID, opaqueid.PublisherIdentityPrefix) || !opaqueid.Valid(flags.GrantID, opaqueid.PublisherGrantPrefix) {
		return failure.Wrap("select grant", failure.InvalidTunnelFlags, errors.New("pass publisher and grant IDs"))
	}
	session, err := openTeamSession(ctx, flags.selection(), "tnl publisher grant revoke", diagnostics)
	if err != nil {
		return err
	}
	defer session.Close()
	current, err := session.current(ctx)
	if err != nil {
		return err
	}
	if err := session.authenticated.Control.RevokePublisherGrant(ctx, current.team.Id, flags.PublisherID, flags.GrantID); err != nil {
		return err
	}
	return writeHumanFrame(output, "tnl publisher grant revoke", "revoked", "active runs stop on heartbeat", clioutput.Fields(
		clioutput.Field{Label: "publisher", Value: flags.PublisherID}, clioutput.Field{Label: "grant", Value: flags.GrantID}))
}

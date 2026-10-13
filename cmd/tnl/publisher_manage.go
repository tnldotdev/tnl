package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"time"

	"github.com/tnldotdev/tnl/internal/clioutput"
	"github.com/tnldotdev/tnl/internal/controlclient"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/opaqueid"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

type publisherOutputMode string

const (
	publisherOutputHuman publisherOutputMode = "human"
	publisherOutputJSON  publisherOutputMode = "json"
)

type publisherListCommand struct {
	scopedTeamFlags `embed:""`
	After           string              `name:"after" help:"Publisher identity ID after which to read the next page."`
	Output          publisherOutputMode `name:"output" enum:"human,json" default:"human" help:"Output format: ${enum}."`
}

type publisherRevokeCommand struct {
	scopedTeamFlags `embed:""`
	ID              string              `arg:"" name:"publisher-id" required:""`
	Output          publisherOutputMode `name:"output" enum:"human,json" default:"human" help:"Output format: ${enum}."`
}

type publisherGrantCommand struct {
	Add    publisherGrantAddCommand    `cmd:"" help:"Grant an existing saved URL or an authorized namespace."`
	Revoke publisherGrantRevokeCommand `cmd:"" help:"Revoke one grant without revoking sibling grants."`
}

type publisherGrantAddCommand struct {
	scopedTeamFlags `embed:""`
	PublisherID     string              `arg:"" name:"publisher-id" required:""`
	PublicURLID     string              `arg:"" name:"public-url-id" optional:""`
	Namespace       bool                `name:"namespace" help:"Grant temporary URLs within the authorized namespace."`
	Domain          string              `name:"domain" help:"Ready team domain for the namespace."`
	Output          publisherOutputMode `name:"output" enum:"human,json" default:"human" help:"Output format: ${enum}."`
}

type publisherGrantRevokeCommand struct {
	scopedTeamFlags `embed:""`
	PublisherID     string              `arg:"" name:"publisher-id" required:""`
	GrantID         string              `arg:"" name:"grant-id" required:""`
	Output          publisherOutputMode `name:"output" enum:"human,json" default:"human" help:"Output format: ${enum}."`
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
	if flags.Output == publisherOutputJSON {
		return json.NewEncoder(output).Encode(struct {
			SchemaVersion int    `json:"schema_version"`
			TeamID        string `json:"team_id"`
			controlv1.PublisherIdentityPage
		}{1, current.team.Id, page})
	}
	blocks := make([]clioutput.Block, 0, len(page.Identities))
	now := time.Now().UTC()
	for _, identity := range page.Identities {
		state := "active"
		if identity.RevokedAt != nil {
			state = "revoked"
		}
		fields := []clioutput.Field{{Label: "publisher", Value: identity.Id},
			{Label: "kind", Value: string(identity.Kind)}, {Label: "state", Value: state}}
		for _, grant := range identity.Grants {
			label := "namespace"
			address := ""
			if grant.PublicUrlId != nil {
				if grant.PublicUrl == nil {
					return failure.Wrap("read publisher grant", failure.ServerResponseInvalid,
						errors.New("control omitted the saved public URL address"))
				}
				label, address = "public URL", *grant.PublicUrl
			} else if grant.Namespace != nil {
				address = *grant.Namespace
			}
			grantState := "active"
			if grant.RevokedAt != nil {
				grantState = "revoked"
			} else if grant.ExpiresAt != nil && !grant.ExpiresAt.After(now) {
				grantState = "expired"
			}
			fields = append(fields, clioutput.Field{Label: label, Value: address},
				clioutput.Field{Label: "grant", Value: grant.Id + " (" + grantState + ")"})
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
	if flags.Output == publisherOutputJSON {
		return json.NewEncoder(output).Encode(struct {
			SchemaVersion int    `json:"schema_version"`
			PublisherID   string `json:"publisher_identity_id"`
			State         string `json:"state"`
		}{1, flags.ID, "revoked"})
	}
	return writeHumanFrame(output, "tnl publisher revoke", "revoked", "active runs stop on heartbeat",
		clioutput.Fields(clioutput.Field{Label: "publisher", Value: flags.ID}))
}

func runPublisherGrantAdd(ctx context.Context, flags publisherGrantAddCommand, output, diagnostics io.Writer) error {
	if !opaqueid.Valid(flags.PublisherID, opaqueid.PublisherIdentityPrefix) ||
		flags.Namespace == (flags.PublicURLID != "") ||
		flags.PublicURLID != "" && (!opaqueid.Valid(flags.PublicURLID, opaqueid.PublicURLPrefix) || flags.Domain != "") {
		return failure.Wrap("select publisher grant", failure.InvalidTunnelFlags,
			errors.New("pass a publisher ID with one public URL ID or --namespace and an optional domain"))
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
	request := controlv1.CreatePublisherGrantRequest{TeamId: controlv1.TeamID(current.team.Id)}
	if flags.Namespace {
		domain, err := readyDomain(current, flags.Domain)
		if err != nil {
			return err
		}
		_, direct := current.namespace(domain)
		scope := controlv1.Member
		if direct {
			scope = controlv1.Shared
		}
		request.DomainId, request.PublicUrlScope = &domain.Id, &scope
	} else {
		route, err := session.authenticated.Control.GetPublicURL(ctx, flags.PublicURLID)
		if err != nil {
			return err
		}
		if route.TeamId != current.team.Id {
			return controlclient.ErrNotFound
		}
		request.PublicUrlId = &route.Id
	}
	grant, err := session.authenticated.Control.CreatePublisherGrant(ctx, flags.PublisherID, request)
	if err != nil {
		return err
	}
	if grant.Id == "" || grant.TeamId != current.team.Id ||
		flags.Namespace && grant.Namespace == nil || !flags.Namespace && (grant.PublicUrlId == nil || *grant.PublicUrlId != flags.PublicURLID) {
		return failure.Wrap("validate publisher grant", failure.ServerResponseInvalid, errors.New("control returned a different publisher grant"))
	}
	if flags.Output == publisherOutputJSON {
		return json.NewEncoder(output).Encode(struct {
			SchemaVersion int `json:"schema_version"`
			controlv1.PublisherGrant
		}{1, grant})
	}
	selected := flags.PublicURLID
	if grant.Namespace != nil {
		selected = *grant.Namespace
	}
	return writeHumanFrame(output, "tnl publisher grant add", "created", "",
		clioutput.Fields(clioutput.Field{Label: "publisher", Value: flags.PublisherID},
			clioutput.Field{Label: "grant", Value: grant.Id}, clioutput.Field{Label: "scope", Value: selected}))
}

func runPublisherGrantRevoke(ctx context.Context, flags publisherGrantRevokeCommand, output, diagnostics io.Writer) error {
	if !opaqueid.Valid(flags.PublisherID, opaqueid.PublisherIdentityPrefix) || !opaqueid.Valid(flags.GrantID, opaqueid.PublisherGrantPrefix) {
		return failure.Wrap("select publisher grant", failure.InvalidTunnelFlags, errors.New("pass publisher and grant IDs"))
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
	if flags.Output == publisherOutputJSON {
		return json.NewEncoder(output).Encode(struct {
			SchemaVersion int    `json:"schema_version"`
			PublisherID   string `json:"publisher_identity_id"`
			GrantID       string `json:"publisher_grant_id"`
			State         string `json:"state"`
		}{1, flags.PublisherID, flags.GrantID, "revoked"})
	}
	return writeHumanFrame(output, "tnl publisher grant revoke", "revoked", "active runs using this grant stop on heartbeat",
		clioutput.Fields(clioutput.Field{Label: "publisher", Value: flags.PublisherID}, clioutput.Field{Label: "grant", Value: flags.GrantID}))
}

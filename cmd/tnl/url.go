package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"strconv"

	"github.com/tnldotdev/tnl/internal/clioutput"
	"github.com/tnldotdev/tnl/internal/controlclient"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/localproxy"
	"github.com/tnldotdev/tnl/internal/opaqueid"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

type publicURLCommand struct {
	List      publicURLListCommand      `cmd:"" help:"List public URLs you may visit; --team filters the results."`
	Available urlAvailableCommand       `cmd:"" help:"List public URLs you may visit."`
	Inventory publicURLInventoryCommand `cmd:"" help:"List saved public URLs owned by the selected team."`
	Access    urlAccessCommand          `cmd:"" help:"Show or replace one public URL's complete visitor access policy."`
	Update    publicURLUpdateCommand    `cmd:"" help:"Change a saved public URL target."`
	Delete    publicURLDeleteCommand    `cmd:"" help:"Delete a public URL by ID; use tnl url list to find it."`
}

type publicURLUpdateCommand struct {
	scopedTeamFlags `embed:""`
	PublicURLID     string `arg:"" name:"public-url-id" required:""`
	Target          string `name:"target" help:"New HTTP or HTTPS target origin; no connection is made from this command."`
}

type publicURLListCommand struct {
	scopedTeamFlags `embed:""`
	Output          statusOutputMode `name:"output" enum:"human,json" default:"human" help:"Output format: ${enum}."`
}

type publicURLInventoryCommand struct {
	scopedTeamFlags `embed:""`
}

type publicURLDeleteCommand struct {
	scopedTeamFlags `embed:""`
	PublicURLID     string `arg:"" name:"public-url-id" required:"" help:"Public URL ID to delete."`
}

func runURLList(ctx context.Context, command publicURLListCommand, output, diagnostics io.Writer) error {
	session, err := openTeamSession(ctx, command.selection(), "tnl url list", diagnostics)
	if err != nil {
		return err
	}
	defer session.Close()
	items, err := visitorURLList(ctx, session.authenticated.Control, command.Team)
	if err != nil {
		return err
	}
	if command.Output == statusOutputJSON {
		return json.NewEncoder(output).Encode(items)
	}
	blocks := make([]clioutput.Block, 0, len(items))
	for _, item := range items {
		address, err := availablePublicAddress(item)
		if err != nil {
			return err
		}
		blocks = append(blocks, clioutput.Section(item.CanonicalHostname, clioutput.Fields(
			clioutput.Field{Label: "public URL", Value: address},
			clioutput.Field{Label: "public URL ID", Value: item.Id},
			clioutput.Field{Label: "team", Value: item.TeamName},
			clioutput.Field{Label: "protocol", Value: string(item.ServiceProtocol)},
			clioutput.Field{Label: "access", Value: string(item.VisitorAccess)},
		)))
	}
	return writeHumanFrame(output, "tnl url list", countState(len(items), "public URL", "public URLs"), "", blocks...)
}

type visitorURLListClient interface {
	ListAvailablePublicURLs(context.Context, string, string) (controlv1.AvailablePublicURLPage, error)
}

func visitorURLList(ctx context.Context, control visitorURLListClient, team string) ([]controlv1.AvailablePublicURL, error) {
	teamID := ""
	if opaqueid.Valid(team, opaqueid.TeamPrefix) {
		teamID = team
	}
	items := []controlv1.AvailablePublicURL{}
	seen := map[string]bool{}
	cursor := ""
	for {
		page, err := control.ListAvailablePublicURLs(ctx, teamID, cursor)
		if err != nil {
			return nil, err
		}
		for _, item := range page.PublicUrls {
			if team == "" || item.TeamId == team || item.TeamName == team {
				items = append(items, item)
			}
		}
		if page.NextCursor == nil {
			break
		}
		if *page.NextCursor == "" || *page.NextCursor == cursor || seen[*page.NextCursor] {
			return nil, failure.Wrap("read visitor inventory", failure.ServerResponseInvalid, errors.New("invalid visitor inventory cursor"))
		}
		cursor = *page.NextCursor
		seen[cursor] = true
	}
	return items, nil
}

func availablePublicAddress(item controlv1.AvailablePublicURL) (string, error) {
	return savedPublicAddress(controlv1.PublicURL{CanonicalHostname: item.CanonicalHostname, ServiceProtocol: controlv1.PublicURLServiceProtocol(item.ServiceProtocol)})
}

func runURLInventory(ctx context.Context, command publicURLInventoryCommand, output, diagnostics io.Writer) error {
	session, err := openTeamSession(ctx, command.selection(), "tnl url inventory", diagnostics)
	if err != nil {
		return err
	}
	defer session.Close()
	current, err := session.current(ctx)
	if err != nil {
		return err
	}
	routes, err := session.authenticated.Control.ListPublicURLs(ctx, current.team.Id)
	if err != nil {
		return err
	}
	blocks := []clioutput.Block{clioutput.Fields(
		clioutput.Field{Label: "server", Value: session.authenticated.ServerEndpoint},
		clioutput.Field{Label: "team", Value: current.team.DisplayName},
	)}
	for _, route := range routes {
		fields := []clioutput.Field{
			clioutput.Field{Label: "scope", Value: string(route.PublicUrlScope)},
			clioutput.Field{Label: "state", Value: string(route.LifecycleState)},
			clioutput.Field{Label: "next publish run number", Value: strconv.FormatInt(route.NextPublishRunNumber, 10)},
			clioutput.Field{Label: "public URL ID", Value: route.Id},
		}
		if route.ServiceProtocol != controlv1.Http {
			address, err := savedPublicAddress(route)
			if err != nil {
				return err
			}
			fields = append(fields, clioutput.Field{Label: "protocol", Value: string(route.ServiceProtocol)},
				clioutput.Field{Label: "public URL", Value: address})
		}
		blocks = append(blocks, clioutput.Section(route.CanonicalHostname, clioutput.Fields(fields...)))
	}
	return writeHumanFrame(output, "tnl url inventory", countState(len(routes), "public URL", "public URLs"), "", blocks...)
}

func runURLDelete(ctx context.Context, command publicURLDeleteCommand, output, diagnostics io.Writer) error {
	session, err := openTeamSession(ctx, command.selection(), "tnl url delete", diagnostics)
	if err != nil {
		return err
	}
	defer session.Close()
	current, err := session.current(ctx)
	if err != nil {
		return err
	}
	selected, err := session.authenticated.Control.GetPublicURL(ctx, command.PublicURLID)
	if err != nil {
		return err
	}
	if selected.TeamId != current.team.Id {
		return controlclient.ErrNotFound
	}
	if err := session.authenticated.Control.DeletePublicURL(ctx, selected.Id); err != nil {
		return err
	}
	return writeHumanTransition(output, "tnl url delete", "deleted", selected.CanonicalHostname, "", "public URL deleted", "",
		clioutput.Field{Label: "id", Value: selected.Id})
}

func runURLUpdate(ctx context.Context, flags publicURLUpdateCommand, output, diagnostics io.Writer) error {
	if flags.Target == "" {
		return failure.Wrap("validate URL update", failure.InvalidTunnelFlags, errors.New("set --target to update this public URL"))
	}
	session, err := openTeamSession(ctx, flags.selection(), "tnl url update", diagnostics)
	if err != nil {
		return err
	}
	defer session.Close()
	current, err := session.current(ctx)
	if err != nil {
		return err
	}
	route, err := session.authenticated.Control.GetPublicURL(ctx, flags.PublicURLID)
	if err != nil {
		return err
	}
	if route.TeamId != current.team.Id {
		return controlclient.ErrNotFound
	}
	if flags.Target != "" && route.ServiceProtocol != controlv1.Http {
		return failure.Wrap("validate TCP URL update", failure.InvalidTunnelFlags,
			errors.New("TCP targets are configured on the publisher, not the saved public URL"))
	}
	target := route.Target
	if flags.Target != "" {
		target, err = localproxy.NormalizeTarget(flags.Target)
		if err != nil {
			return err
		}
	}
	allowed := []string{}
	if route.AllowedIpPrefixes != nil {
		allowed = *route.AllowedIpPrefixes
	}
	updated, err := session.authenticated.Control.UpdatePublicURL(ctx, flags.PublicURLID, controlv1.UpdatePublicURLRequest{
		Target: target, AllowedIpPrefixes: allowed,
	})
	if err != nil {
		return err
	}
	address, err := savedPublicAddress(updated)
	if err != nil {
		return err
	}
	fields := []clioutput.Field{{Label: "public URL", Value: address}}
	if updated.Target != "" {
		fields = append(fields, clioutput.Field{Label: "target", Value: updated.Target})
	}
	return writeHumanFrame(output, "tnl url update", "updated", "restart the publisher to use the new target",
		clioutput.Fields(fields...))
}

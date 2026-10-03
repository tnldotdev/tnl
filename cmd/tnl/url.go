package main

import (
	"context"
	"io"
	"strconv"

	"github.com/tnldotdev/tnl/internal/clioutput"
	"github.com/tnldotdev/tnl/internal/controlclient"
)

type publicURLCommand struct {
	List   publicURLListCommand   `cmd:"" help:"List public URLs for the selected team."`
	Delete publicURLDeleteCommand `cmd:"" help:"Delete a public URL by ID; use tnl url list to find it."`
}

type publicURLListCommand struct {
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
		blocks = append(blocks, clioutput.Section(route.CanonicalHostname, clioutput.Fields(
			clioutput.Field{Label: "scope", Value: string(route.PublicUrlScope)},
			clioutput.Field{Label: "state", Value: string(route.LifecycleState)},
			clioutput.Field{Label: "next publish run number", Value: strconv.FormatInt(route.NextPublishRunNumber, 10)},
			clioutput.Field{Label: "public URL ID", Value: route.Id},
		)))
	}
	return writeHumanFrame(output, "tnl url list", countState(len(routes), "public URL", "public URLs"), "", blocks...)
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

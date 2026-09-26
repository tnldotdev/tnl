package main

import (
	"context"
	"io"
	"strconv"

	"github.com/tnldotdev/tnl/internal/clioutput"
	"github.com/tnldotdev/tnl/internal/controlclient"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

type publicURLCommand struct {
	List   publicURLListCommand   `cmd:"" help:"List public URLs for the selected team."`
	Delete publicURLDeleteCommand `cmd:"" help:"Delete a public URL."`
}

type publicURLListCommand struct {
	remoteFlags `embed:""`
}

type publicURLDeleteCommand struct {
	remoteFlags `embed:""`
	PublicURLID string `arg:"" name:"public-url-id" required:"" help:"Public URL ID to delete."`
}

func runURLList(ctx context.Context, command publicURLListCommand, output, diagnostics io.Writer) error {
	session, err := openTeamSession(ctx, command.remoteFlags, "tnl url list", diagnostics)
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
	blocks := make([]clioutput.Block, 0, len(routes))
	for _, route := range routes {
		blocks = append(blocks, clioutput.Section(route.CanonicalHostname, clioutput.Fields(
			clioutput.Field{Label: "scope", Value: string(route.PublicUrlScope)},
			clioutput.Field{Label: "state", Value: string(route.LifecycleState)},
			clioutput.Field{Label: "next publish run number", Value: strconv.FormatInt(route.NextPublishRunNumber, 10)},
			clioutput.Field{Label: "public URL ID", Value: route.Id},
		)))
	}
	return writeHumanFrame(output, "tnl url list", countState(len(blocks), "public URL", "public URLs"), "", blocks...)
}

func runURLDelete(ctx context.Context, command publicURLDeleteCommand, output, diagnostics io.Writer) error {
	session, err := openTeamSession(ctx, command.remoteFlags, "tnl url delete", diagnostics)
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
	var selected *controlv1.PublicURL
	for index := range routes {
		if routes[index].Id == command.PublicURLID {
			selected = &routes[index]
			break
		}
	}
	if selected == nil {
		return controlclient.ErrNotFound
	}
	if err := session.authenticated.Control.DeletePublicURL(ctx, selected.Id); err != nil {
		return err
	}
	return writeHumanTransition(output, "tnl url delete", "deleted", selected.CanonicalHostname, "", "public URL deleted", "",
		clioutput.Field{Label: "id", Value: selected.Id})
}

package main

import (
	"context"
	"io"
	"strconv"

	"github.com/tnldotdev/tnl/internal/clientauth"
	"github.com/tnldotdev/tnl/internal/clioutput"
	"github.com/tnldotdev/tnl/internal/controlclient"
	"github.com/tnldotdev/tnl/internal/routeclient"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

type routeCommand struct {
	List   routeListCommand   `cmd:"" help:"List durable routes for the selected team."`
	Delete routeDeleteCommand `cmd:"" help:"Delete a durable route."`
}

type routeListCommand struct {
	remoteFlags `embed:""`
}

type routeDeleteCommand struct {
	remoteFlags `embed:""`
	RouteID     string `arg:"" name:"route-id" required:""`
}

func runRouteList(ctx context.Context, command routeListCommand, output, diagnostics io.Writer) error {
	session, err := openTeamSession(ctx, command.remoteFlags, "tnl route list", diagnostics)
	if err != nil {
		return err
	}
	defer session.Close()
	current, err := session.current(ctx)
	if err != nil {
		return err
	}
	routes, err := session.authenticated.Control.ListRoutes(ctx, current.team.Id)
	if err != nil {
		return err
	}
	blocks := make([]clioutput.Block, 0, len(routes))
	for _, route := range routes {
		blocks = append(blocks, clioutput.Section(route.CanonicalHostname, clioutput.Fields(
			clioutput.Field{Label: "scope", Value: string(route.RouteScope)},
			clioutput.Field{Label: "state", Value: string(route.LifecycleState)},
			clioutput.Field{Label: "route version", Value: strconv.FormatInt(route.NextRouteVersion, 10)},
			clioutput.Field{Label: "id", Value: route.Id},
		)))
	}
	return writeHumanFrame(output, "tnl route list", countState(len(blocks), "route", "routes"), "", blocks...)
}

func runRouteDelete(ctx context.Context, command routeDeleteCommand, output, diagnostics io.Writer) error {
	session, err := openTeamSession(ctx, command.remoteFlags, "tnl route delete", diagnostics)
	if err != nil {
		return err
	}
	defer session.Close()
	current, err := session.current(ctx)
	if err != nil {
		return err
	}
	routes, err := session.authenticated.Control.ListRoutes(ctx, current.team.Id)
	if err != nil {
		return err
	}
	var selected *controlv1.Route
	for index := range routes {
		if routes[index].Id == command.RouteID {
			selected = &routes[index]
			break
		}
	}
	if selected == nil {
		return controlclient.ErrNotFound
	}
	client, err := routeAPI(session.authenticated)
	if err != nil {
		return err
	}
	if err := client.DeleteRoute(ctx, *selected); err != nil {
		return err
	}
	return writeHumanTransition(output, "tnl route delete", "deleted", selected.CanonicalHostname, "", "route deleted", "",
		clioutput.Field{Label: "id", Value: selected.Id})
}

func routeAPI(authenticated *clientauth.Client) (*routeclient.Client, error) {
	return routeclient.New(authenticated.Control)
}

package main

import (
	"context"
	"errors"
	"io"
	"os"

	"github.com/tnldotdev/tnl/internal/clientauth"
	"github.com/tnldotdev/tnl/internal/clientstate"
	"github.com/tnldotdev/tnl/internal/clioutput"
	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/localpublisher"
	"github.com/tnldotdev/tnl/internal/publisher"
)

func prepareAliasServices(ctx context.Context, state *clientstate.Database, project projectConfiguration, name string, alias config.Alias, server, team string, auth *clientauth.Client) (publisherServices, error) {
	services, err := localpublisher.PrepareAlias(ctx, state, project.Project, name, alias, server, team, auth)
	return services, err
}
func checkAliasHostnamePolicy(services publisherServices) error {
	return localpublisher.CheckAliasPolicy(services)
}
func aliasScope(project projectConfiguration, name string, services publisherServices) clientstate.AliasScope {
	return localpublisher.AliasScope(project.Project, name, services)
}
func registerProjectAlias(ctx context.Context, state *clientstate.Database, project projectConfiguration, name string, definition config.Alias, services publisherServices, tunnelID, group string) (clientstate.AliasSelection, error) {
	return localpublisher.RegisterAlias(ctx, state, project.Project, name, definition, services, tunnelID, group)
}
func aliasChoiceError(err error) error { return localpublisher.AliasChoiceError(err) }
func startProjectAliases(ctx context.Context, state *clientstate.Database, project projectConfiguration, service, team string, parent publisherServices, base publisher.Config, group string, tunnel *clientstate.Tunnel, output *publishOutput) func() {
	return localpublisher.StartAliases(ctx, state, project.Project, service, team, parent, base, group, tunnel, output.integrationURLMessage)
}

func runAliasChoice(ctx context.Context, flags aliasChoiceCommand, project projectConfiguration, use, force bool, stdout, stderr io.Writer) error {
	if !project.Found() {
		return failure.Wrap("select alias", failure.ProjectConfigMissing, errors.New("project configuration with an alias is required"))
	}
	definition, found := project.Config.Aliases[flags.Name]
	if !found {
		return failure.Wrap("select alias", failure.ProjectConfigInvalid, errors.New("select an alias declared in this project's configuration"))
	}
	server, state, err := resolveServer(ctx, flags.StateDir, flags.ServerURL)
	if err != nil {
		return err
	}
	defer state.Close()
	authenticated, err := authenticatePublisher(ctx, state, server, flags.AccessToken, "tnl alias", os.Stdin, stderr)
	if err != nil {
		return err
	}
	team := flags.Team
	if team == "" {
		team = flags.ProjectTeam
	}
	services, err := prepareAliasServices(ctx, state, project, flags.Name, definition, server, team, authenticated)
	if err != nil {
		return err
	}
	// validate the chosen server/domain before any local declaration or selection
	// write. a rejected nested name must not disturb the current owner.
	if use {
		if err := checkAliasHostnamePolicy(services); err != nil {
			return err
		}
	}
	scope := aliasScope(project, flags.Name, services)
	if use {
		snapshot, err := state.SnapshotProject(ctx, project.Root)
		if err != nil {
			return err
		}
		var receiver *clientstate.TunnelInfo
		for i := range snapshot.Tunnels {
			tunnel := &snapshot.Tunnels[i]
			if tunnel.Server == server && tunnel.Service == definition.Service && tunnel.State == clientstate.TunnelStateReady && tunnel.IntegrationGroup != "" {
				if receiver != nil {
					return failure.Wrap("select alias service", failure.InvalidTunnelFlags, errors.New("more than one entry-service tunnel is running in this worktree"))
				}
				receiver = tunnel
			}
		}
		if receiver == nil {
			return failure.Wrap("select alias service", failure.AliasReceiverUnready, clientstate.ErrAliasReceiverUnavailable)
		}
		if _, err := registerProjectAlias(ctx, state, project, flags.Name, definition, services, receiver.ID, receiver.IntegrationGroup); err != nil {
			return aliasChoiceError(err)
		}
	}
	var selected clientstate.AliasSelection
	command, status := "tnl alias use", "selected"
	if use {
		selected, err = state.SelectAlias(ctx, scope, project.Root, force)
	} else {
		command, status = "tnl alias release", "default restored"
		selected, err = state.ReleaseAlias(ctx, scope, project.Root)
	}
	if err != nil {
		return aliasChoiceError(err)
	}
	return writeHumanFrame(stdout, command, status, "tnl status shows alias readiness", clioutput.Fields(
		clioutput.Field{Label: "alias", Value: flags.Name}, clioutput.Field{Label: "public URL", Value: "https://" + selected.Hostname},
		clioutput.Field{Label: "selected worktree", Value: selected.Project},
	))
}

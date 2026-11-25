package main

import (
	"context"
	"errors"
	"io"
	"os"

	"github.com/tnldotdev/tnl/internal/clioutput"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/publisher/invocation"
)

func runAliasChoice(ctx context.Context, flags aliasChoiceCommand, project projectConfiguration, use, force bool, stdout, stderr io.Writer) error {
	if !project.Found() {
		return failure.Wrap("select alias", failure.ProjectConfigMissing, errors.New("project configuration with an alias is required"))
	}
	if _, found := project.Config.Aliases[flags.Name]; !found {
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
	selected, err := invocation.ChooseAlias(ctx, state, invocation.AliasChoice{Project: project.Project, Name: flags.Name, Server: server, Team: team, Use: use, Force: force, Authenticated: authenticated})
	if err != nil {
		return err
	}
	status := "selected"
	if !use {
		status = "default restored"
	}
	return writeResult(stdout, clioutput.Line("https://"+selected.Hostname), clioutput.Line(status+": "+selected.Project))
}

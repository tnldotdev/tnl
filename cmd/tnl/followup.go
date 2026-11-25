package main

import (
	"context"
	"os"

	clientteam "github.com/tnldotdev/tnl/internal/client/team"
	"github.com/tnldotdev/tnl/internal/clioutput"
)

type commandScope struct{ configArgs, server, team, stateDir string }

func (flags scopedTeamFlags) followupScope(ctx context.Context, session *clientteam.Session, team string) commandScope {
	if flags.Team != "" {
		team = flags.Team
	}
	pin := suggestedServer(ctx, session.Authenticated().ServerEndpoint, flags.projectServer, os.Getenv("TNL_ACCESS_TOKEN"), flags.StateDir, session.Database())
	return commandScope{flags.configArgs, pin, team, flags.StateDir}
}

func (f commandScope) command(path string, args ...string) string {
	cmd := "tnl " + f.configArgs + path
	for _, arg := range args {
		cmd += " " + shellWord(arg)
	}
	if f.server != "" {
		cmd += " --server=" + shellWord(f.server)
	}
	if f.team != "" {
		cmd += " --team=" + shellWord(f.team)
	}
	if f.stateDir != "" {
		cmd += " --state-dir=" + shellWord(f.stateDir)
	}
	return cmd
}

func (f commandScope) nextPage(path, cursor string, filters ...string) clioutput.Block {
	command := f.command(path, append(filters, "--after="+cursor)...)
	return clioutput.Section("Next page", clioutput.Literal(command))
}

package main

import (
	"context"
	"os"
	"strconv"

	clientteam "github.com/tnldotdev/tnl/internal/client/team"
	"github.com/tnldotdev/tnl/internal/clioutput"
	"github.com/tnldotdev/tnl/internal/failure"
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

func observationFollowup(err error, flags cli) error {
	reason, _ := failure.ReasonOf(err)
	if reason != failure.AppReadinessTimeout && reason != failure.AppCursorExpired {
		return err
	}
	args := []string{"tnl"}
	if flags.NoConfig {
		args = append(args, "--no-config")
	} else if path := flags.ConfigPath; path != "" {
		args = append(args, "--config", path)
	} else if path := os.Getenv("TNL_CONFIG"); path != "" {
		args = append(args, "--config", path)
	}
	var stateDir, output string
	if reason == failure.AppCursorExpired {
		args = append(args, "watch")
		if flags.Watch.Service != "" {
			args = append(args, "--service", flags.Watch.Service)
		}
		if flags.Watch.Count > 0 {
			args = append(args, "--count", strconv.Itoa(flags.Watch.Count))
		}
		if flags.Watch.Timeout > 0 {
			args = append(args, "--timeout", flags.Watch.Timeout.String())
		}
		stateDir, output = flags.Watch.StateDir, flags.Watch.Output
	} else {
		stateDir, output = flags.Wait.StateDir, flags.Wait.Output
		if len(flags.Wait.Service) <= 1 {
			args = append(args, "status", "--last-known")
		} else {
			// status accepts one service. retry an exact multi-service wait.
			args = append(args, "wait")
			if flags.Wait.Timeout > 0 {
				args = append(args, "--timeout", flags.Wait.Timeout.String())
			}
		}
		for _, service := range flags.Wait.Service {
			args = append(args, "--service", service)
		}
	}
	if stateDir != "" {
		args = append(args, "--state-dir", stateDir)
	}
	if output != "" {
		args = append(args, "--output", output)
	}
	return &commandGuidance{error: err, help: args}
}

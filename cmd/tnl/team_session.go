package main

import (
	"context"
	"io"
	"os"

	"github.com/tnldotdev/tnl/internal/client/team"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
)

func openTeamSession(ctx context.Context, flags remoteFlags, command string, diagnostics io.Writer) (*team.Session, error) {
	return team.Open(ctx, team.Options{
		ServerURL: flags.ServerURL, StateDir: flags.StateDir, AccessToken: flags.AccessToken,
		ProjectTeam: flags.ProjectTeam, SelectedTeam: flags.SelectedTeam,
		Diagnostics: diagnostics, AuthenticationPrompt: authenticationPrompt(diagnostics, command),
		OpenURL: interactiveBrowserOpener(os.Stdin),
	})
}

func randomIdempotencyKey() (string, error) { return opaqueid.New(opaqueid.IdempotencyPrefix) }

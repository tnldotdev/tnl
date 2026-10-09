package main

import (
	"context"
	"io"
	"strconv"

	"github.com/tnldotdev/tnl/internal/clioutput"
)

type teamFeedbackCommand struct {
	Show teamFeedbackShowCommand `cmd:"" help:"Show the team's feedback sign-in policy."`
	Set  teamFeedbackSetCommand  `cmd:"" help:"Set the team's live feedback sign-in policy (owner or admin)."`
}

type teamFeedbackShowCommand struct {
	scopedTeamFlags `embed:""`
}

type teamFeedbackSetCommand struct {
	scopedTeamFlags `embed:""`
	RequireSignIn   bool `name:"require-sign-in" required:"" help:"Require browser sign-in for reports, replies, resolve, and reopen; use =true or =false."`
}

func runTeamFeedbackShow(ctx context.Context, command teamFeedbackShowCommand, output, diagnostics io.Writer) error {
	session, err := openTeamSession(ctx, command.selection(), "tnl team feedback show", diagnostics)
	if err != nil {
		return err
	}
	defer session.Close()
	membership, err := session.currentMembership(ctx)
	if err != nil {
		return err
	}
	policy, err := session.api.GetTeamFeedbackPolicy(ctx, membership.TeamId)
	if err != nil {
		return err
	}
	return writeTeamFeedbackPolicy(output, "tnl team feedback show", "current", membership.TeamDisplayName, policy.RequireSignIn)
}

func runTeamFeedbackSet(ctx context.Context, command teamFeedbackSetCommand, output, diagnostics io.Writer) error {
	session, err := openTeamSession(ctx, command.selection(), "tnl team feedback set", diagnostics)
	if err != nil {
		return err
	}
	defer session.Close()
	membership, err := session.currentMembership(ctx)
	if err != nil {
		return err
	}
	policy, err := session.api.SetTeamFeedbackPolicy(ctx, membership.TeamId, command.RequireSignIn)
	if err != nil {
		return err
	}
	return writeTeamFeedbackPolicy(output, "tnl team feedback set", "updated", membership.TeamDisplayName, policy.RequireSignIn)
}

func writeTeamFeedbackPolicy(output io.Writer, command, state, team string, required bool) error {
	return writeHumanFrame(output, command, state, "", clioutput.Fields(
		clioutput.Field{Label: "team", Value: team},
		clioutput.Field{Label: "require sign-in", Value: strconv.FormatBool(required)},
	))
}

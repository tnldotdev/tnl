package main

import (
	"context"
	"encoding/json"
	"io"

	"github.com/tnldotdev/tnl/internal/clioutput"
	authorityv1 "github.com/tnldotdev/tnl/pkg/api/control/authority/v1"
)

type teamFeedbackCommand struct {
	Get teamFeedbackGetCommand `cmd:"" help:"Read the feedback author policy."`
	Set teamFeedbackSetCommand `cmd:"" help:"Change who may write feedback."`
}
type teamFeedbackGetCommand struct {
	scopedTeamFlags `embed:""`
	Output          statusOutputMode `name:"output" enum:"human,json" default:"human"`
}
type teamFeedbackSetCommand struct {
	scopedTeamFlags `embed:""`
	Authors         string           `arg:"" name:"authors" enum:"anyone,signed_in,team_members" required:""`
	Output          statusOutputMode `name:"output" enum:"human,json" default:"human"`
}

func runTeamFeedbackGet(ctx context.Context, f teamFeedbackGetCommand, output, diagnostics io.Writer) error {
	return runTeamFeedbackPolicy(ctx, f.selection(), "", f.Output, output, diagnostics)
}
func runTeamFeedbackSet(ctx context.Context, f teamFeedbackSetCommand, output, diagnostics io.Writer) error {
	return runTeamFeedbackPolicy(ctx, f.selection(), f.Authors, f.Output, output, diagnostics)
}
func runTeamFeedbackPolicy(ctx context.Context, f remoteFlags, authors string, mode statusOutputMode, output, diagnostics io.Writer) error {
	s, err := openTeamSession(ctx, f, "tnl team feedback", diagnostics)
	if err != nil {
		return err
	}
	defer s.Close()
	current, err := s.Current(ctx)
	if err != nil {
		return err
	}
	policy := authorityv1.TeamFeedbackPolicy{}
	if authors == "" {
		policy, err = s.Authenticated().Authority.GetTeamFeedbackPolicy(ctx, current.Team().Id)
	} else {
		policy, err = s.Authenticated().Authority.SetTeamFeedbackPolicy(ctx, current.Team().Id, authorityv1.TeamFeedbackPolicy{Authors: authorityv1.TeamFeedbackPolicyAuthors(authors)})
	}
	if err != nil {
		return err
	}
	if mode == statusOutputJSON {
		return json.NewEncoder(output).Encode(policy)
	}
	return writeHumanFrame(output, "tnl team feedback", "current", "", clioutput.Fields(clioutput.Field{Label: "team", Value: current.Team().DisplayName}, clioutput.Field{Label: "authors", Value: string(policy.Authors)}))
}

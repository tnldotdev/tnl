package main

import (
	"context"
	"encoding/json"
	"io"
	"time"

	"github.com/tnldotdev/tnl/internal/client/project/workloadsetup"
	"github.com/tnldotdev/tnl/internal/clioutput"
)

type authApproveCommand struct {
	scopedTeamFlags `embed:""`
	Environment     string           `name:"environment" required:"" help:"Declared remote environment to approve."`
	Workload        string           `name:"workload" required:"" help:"Workload declared in the selected environment."`
	Intent          string           `name:"intent" required:"" help:"Nonsecret operation key; reuse it to recover the same IDs, use a new key for a new grant."`
	ExpiresAt       time.Time        `name:"expires-at" required:"" help:"Absolute RFC3339 permission expiry, at most 366 days away; reuse it on retry."`
	Output          statusOutputMode `name:"output" enum:"human,json" default:"human"`
}

func authApproveCommandContext(project projectConfiguration, flags *authApproveCommand) error {
	selection := applyCommand{scopedTeamFlags: flags.scopedTeamFlags, Environment: flags.Environment}
	if err := applyEnvironmentCommandContext(project, &selection); err != nil {
		return err
	}
	flags.scopedTeamFlags = selection.scopedTeamFlags
	return nil
}

func runAuthApprove(ctx context.Context, flags authApproveCommand, project projectConfiguration, output, diagnostics io.Writer) error {
	if err := authApproveCommandContext(project, &flags); err != nil {
		return err
	}
	session, err := openTeamSession(ctx, flags.selection(), "tnl auth approve", diagnostics)
	if err != nil {
		return err
	}
	defer session.Close()
	current, err := session.Current(ctx)
	if err != nil {
		return err
	}
	result, err := workloadsetup.Approve(ctx, session.Authenticated().Authority, session.Authenticated().Control, workloadsetup.ApprovalOptions{Project: project.Project, Server: flags.ServerURL, TeamID: current.Team().Id, Environment: flags.Environment, Workload: flags.Workload, Intent: flags.Intent, ExpiresAt: flags.ExpiresAt})
	if err != nil {
		return err
	}
	if flags.Output == statusOutputJSON {
		return json.NewEncoder(output).Encode(result)
	}
	state, hint := "approved", "this receipt is not a credential"
	if result.MachineRevokedAt != nil || result.PermissionRevokedAt != nil {
		state, hint = "revoked", "no access restored; a new permission needs a new --intent"
	} else if !result.Request.ExpiresAt.After(time.Now()) {
		state, hint = "expired", "no access restored; a new permission needs a new --intent"
	}
	return writeHumanFrame(output, "tnl auth approve", state, hint, clioutput.Fields(
		clioutput.Field{Label: "intent", Value: result.IntentKey},
		clioutput.Field{Label: "environment ID", Value: result.Request.EnvironmentId},
		clioutput.Field{Label: "machine ID", Value: result.Machine.Id},
		clioutput.Field{Label: "permission ID", Value: result.Selection.PermissionId},
		clioutput.Field{Label: "expires at", Value: result.Request.ExpiresAt.Format(time.RFC3339)},
	))
}

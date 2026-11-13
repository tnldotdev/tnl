package main

import (
	"context"
	"io"

	"github.com/tnldotdev/tnl/internal/clioutput"
	"github.com/tnldotdev/tnl/internal/naming"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type deploymentRenameCommand struct {
	scopedTeamFlags `embed:""`
	ProjectKey      string `name:"project-key" help:"Applied project key; defaults to this Git configuration source."`
	Deployment      string `arg:"" name:"deployment" help:"Current configured deployment."`
	Name            string `arg:"" name:"name" help:"New configuration key; existing hostnames and ports are retained."`
}

func runDeploymentRename(ctx context.Context, flags deploymentRenameCommand, project projectConfiguration, output, diagnostics io.Writer) error {
	if !validDeploymentSelector(flags.Deployment) || !naming.ValidServiceName(flags.Name) || flags.Name == "local" {
		return publisherCLIError("select a saved deployment name or ID and a new canonical service label other than local")
	}
	key, err := deploymentProjectKey(ctx, project, flags.ProjectKey)
	if err != nil {
		return err
	}
	session, err := openTeamSession(ctx, flags.selection(), "tnl deployment rename", diagnostics)
	if err != nil {
		return err
	}
	defer session.Close()
	current, err := session.CurrentWithDomains(ctx)
	if err != nil {
		return err
	}
	applied, err := session.Authenticated().Control.GetProjectConfiguration(ctx, current.Team().Id, key, flags.Deployment)
	if err != nil {
		return err
	}
	_, err = session.Authenticated().Control.RenameDeployment(ctx, key, flags.Deployment, controlv1.RenameDeploymentRequest{TeamId: current.Team().Id, Name: flags.Name, ExpectedRevision: applied.Revision})
	if err != nil {
		return err
	}
	return writeHumanFrame(output, "tnl deployment rename", "renamed", "update the deployment selector in Git before tnl apply", clioutput.Fields(clioutput.Field{Label: "deployment", Value: flags.Name}, clioutput.Field{Label: "endpoints", Value: "preserved"}))
}

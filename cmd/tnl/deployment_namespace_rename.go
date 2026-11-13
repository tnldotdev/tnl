package main

import (
	"context"
	"io"
	"strconv"

	"github.com/tnldotdev/tnl/internal/clioutput"
	"github.com/tnldotdev/tnl/internal/naming"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type deploymentNamespaceRenameCommand struct {
	scopedTeamFlags  `embed:""`
	ProjectKey       string `name:"project-key" help:"Applied project key; defaults to this Git configuration source."`
	Deployment       string `arg:"" name:"deployment" help:"Current or historical deployment selector."`
	Label            string `arg:"" name:"label" help:"New DNS namespace label beneath this project's existing domain."`
	ExpectedRevision int64  `required:"" help:"Applied revision from tnl status --scope=server; reuse on retry."`
	RequestID        string `name:"request-id" required:"" help:"Unique operation key; reuse with the same arguments after a lost reply."`
}

func runDeploymentNamespaceRename(ctx context.Context, flags deploymentNamespaceRenameCommand, project projectConfiguration, output, diagnostics io.Writer) error {
	if !validDeploymentSelector(flags.Deployment) || !naming.ValidServiceName(flags.Label) || flags.ExpectedRevision < 1 || flags.RequestID == "" {
		return publisherCLIError("select a deployment, DNS label, --expected-revision and --request-id; reuse the same arguments when retrying")
	}
	key, err := deploymentProjectKey(ctx, project, flags.ProjectKey)
	if err != nil {
		return err
	}
	session, err := openTeamSession(ctx, flags.selection(), "tnl deployment namespace rename", diagnostics)
	if err != nil {
		return err
	}
	defer session.Close()
	current, err := session.Current(ctx)
	if err != nil {
		return err
	}
	result, err := session.Authenticated().Control.RenameDeploymentNamespace(ctx, key, flags.Deployment, controlv1.RenameDeploymentNamespaceRequest{TeamId: current.Team().Id, NamespaceLabel: flags.Label, ExpectedRevision: flags.ExpectedRevision, IdempotencyKey: flags.RequestID})
	if err != nil {
		return err
	}
	blocks := []clioutput.Block{clioutput.Fields(clioutput.Field{Label: "revision", Value: strconv.FormatInt(result.Revision, 10)}, clioutput.Field{Label: "request ID", Value: flags.RequestID})}
	for _, service := range result.Services {
		if service.Hostname != nil {
			blocks = append(blocks, clioutput.Fields(clioutput.Field{Label: service.Service, Value: *service.Hostname}))
		}
	}
	return writeHumanFrame(output, "tnl deployment namespace rename", "renamed", "refresh client profiles; wait for publishers to become ready", blocks...)
}

package main

import (
	"context"
	"io"

	"github.com/tnldotdev/tnl/internal/clioutput"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

type publisherGroupRenameCommand struct {
	scopedTeamFlags `embed:""`
	Group           string `arg:"" name:"group" help:"Current configured publisher group."`
	Name            string `arg:"" name:"name" help:"New configuration key; existing hostnames and ports are retained."`
}

func runPublisherGroupRename(ctx context.Context, flags publisherGroupRenameCommand, project projectConfiguration, output, diagnostics io.Writer) error {
	if !naming.ValidServiceName(flags.Group) || !naming.ValidServiceName(flags.Name) || flags.Group == "local" || flags.Name == "local" {
		return publisherCLIError("group names must be canonical service labels other than local")
	}
	source, err := project.SourceIdentity(ctx)
	if err != nil {
		return err
	}
	session, err := openTeamSession(ctx, flags.selection(), "tnl publisher rename", diagnostics)
	if err != nil {
		return err
	}
	defer session.Close()
	current, err := session.CurrentWithDomains(ctx)
	if err != nil {
		return err
	}
	applied, err := session.Authenticated().Control.GetProjectConfiguration(ctx, current.Team().Id, source.Key)
	if err != nil {
		return err
	}
	if applied.SourceFingerprint != source.Fingerprint {
		return publisherCLIError("applied project belongs to another configuration source")
	}
	_, err = session.Authenticated().Control.RenamePublisherGroup(ctx, source.Key, flags.Group, controlv1.RenamePublisherGroupRequest{TeamId: current.Team().Id, Name: flags.Name, ExpectedRevision: applied.Revision})
	if err != nil {
		return err
	}
	return writeHumanFrame(output, "tnl publisher rename", "renamed", "update publisher keys and references in Git before tnl apply", clioutput.Fields(clioutput.Field{Label: "group", Value: flags.Name}, clioutput.Field{Label: "endpoints", Value: "preserved"}))
}

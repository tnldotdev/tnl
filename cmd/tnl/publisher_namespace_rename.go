package main

import (
	"context"
	"io"
	"strconv"

	"github.com/tnldotdev/tnl/internal/clioutput"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

type publisherNamespaceRenameCommand struct {
	scopedTeamFlags  `embed:""`
	Group            string `arg:"" name:"group" help:"Current or historical publisher group selector."`
	Label            string `arg:"" name:"label" help:"New DNS namespace label beneath this project's existing domain."`
	ExpectedRevision int64  `required:"" help:"Applied revision from tnl status --scope=server; reuse on retry."`
	RequestID        string `name:"request-id" required:"" help:"Unique operation key; reuse with the same arguments after a lost reply."`
}

func runPublisherNamespaceRename(ctx context.Context, flags publisherNamespaceRenameCommand, project projectConfiguration, output, diagnostics io.Writer) error {
	if !naming.ValidServiceName(flags.Group) || flags.Group == "local" || !naming.ValidServiceName(flags.Label) || flags.ExpectedRevision < 1 || flags.RequestID == "" {
		return publisherCLIError("select a group, DNS label, --expected-revision and --request-id; reuse the same arguments when retrying")
	}
	source, err := project.SourceIdentity(ctx)
	if err != nil {
		return err
	}
	session, err := openTeamSession(ctx, flags.selection(), "tnl publisher namespace rename", diagnostics)
	if err != nil {
		return err
	}
	defer session.Close()
	current, err := session.current(ctx)
	if err != nil {
		return err
	}
	applied, err := session.authenticated.Control.GetProjectConfiguration(ctx, current.team.Id, source.Key)
	if err != nil {
		return err
	}
	if applied.SourceFingerprint != source.Fingerprint {
		return publisherCLIError("applied project belongs to another configuration source")
	}
	result, err := session.authenticated.Control.RenamePublisherNamespace(ctx, source.Key, flags.Group, controlv1.RenamePublisherNamespaceRequest{TeamId: current.team.Id, NamespaceLabel: flags.Label, ExpectedRevision: flags.ExpectedRevision, IdempotencyKey: flags.RequestID})
	if err != nil {
		return err
	}
	blocks := []clioutput.Block{clioutput.Fields(clioutput.Field{Label: "revision", Value: strconv.FormatInt(result.Revision, 10)}, clioutput.Field{Label: "request ID", Value: flags.RequestID})}
	for _, service := range result.Services {
		if service.Hostname != nil {
			blocks = append(blocks, clioutput.Fields(clioutput.Field{Label: service.Service, Value: *service.Hostname}))
		}
	}
	return writeHumanFrame(output, "tnl publisher namespace rename", "renamed", "refresh client profiles; wait for publishers to become ready", blocks...)
}

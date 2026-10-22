package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"strconv"

	clientcontrol "github.com/tnldotdev/tnl/internal/client/control"
	"github.com/tnldotdev/tnl/internal/client/project/resolve"
	"github.com/tnldotdev/tnl/internal/clioutput"
	connectorruntime "github.com/tnldotdev/tnl/internal/connector/runtime"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/publisher/target"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type applyCommand struct {
	scopedTeamFlags `embed:""`
	Output          statusOutputMode `name:"output" enum:"human,json" default:"human"`
}

func runApply(ctx context.Context, flags applyCommand, project projectConfiguration, output, diagnostics io.Writer) error {
	source, err := project.SourceIdentity(ctx)
	if err != nil {
		return failure.Wrap("identify applied project", failure.ProjectConfigInvalid, err)
	}
	session, err := openTeamSession(ctx, flags.selection(), "tnl apply", diagnostics)
	if err != nil {
		return err
	}
	defer session.Close()
	current, err := session.CurrentWithDomains(ctx)
	if err != nil {
		return err
	}
	declaration, err := resolve.Declaration(ctx, project.Project, current, func(ctx context.Context, name string) (string, error) {
		resolved, err := target.ResolveTarget(ctx, project.Project, name, runtimeTargetResolver)
		if err != nil {
			return "", err
		}
		return string(*resolved.Target), nil
	})
	if err != nil {
		return err
	}
	revision := int64(0)
	existing, err := session.Authenticated().Control.GetProjectConfiguration(ctx, current.Team().Id, source.Key)
	if err == nil {
		if existing.SourceFingerprint != source.Fingerprint {
			return publisherCLIError("project key belongs to another configuration source")
		}
		revision = existing.Revision
	} else if !errors.Is(err, clientcontrol.ErrNotFound) {
		return err
	}
	if err = bindProjectWorkloads(ctx, project, &declaration, existing.Configuration); err != nil {
		return err
	}
	applied, err := session.Authenticated().Control.ApplyProjectConfiguration(ctx, source.Key, controlv1.ApplyProjectConfigurationRequest{
		TeamId: current.Team().Id, SourceFingerprint: source.Fingerprint, ExpectedRevision: revision, Configuration: declaration,
		ProjectLabel: &source.Label,
	})
	if err != nil {
		return err
	}
	if applied.ProjectKey != source.Key || applied.TeamId != current.Team().Id || applied.SourceFingerprint != source.Fingerprint || applied.Revision < 1 {
		return failure.Wrap("read applied project", failure.ServerResponseInvalid, errors.New("control returned another project configuration"))
	}
	if len(project.Config.Workloads) != 0 {
		team := ""
		if project.Config.Team != nil {
			team = *project.Config.Team
		}
		if err := connectorruntime.WriteBinding(project.Root, connectorruntime.Binding{Schema: 1, Server: session.Authenticated().ServerEndpoint, Team: team, TeamID: current.Team().Id, ProjectKey: source.Key, SourceID: source.Fingerprint}); err != nil {
			return failure.Wrap("write applied connection scope", failure.ProjectConfigInvalid, err)
		}
	}
	if flags.Output == statusOutputJSON {
		return json.NewEncoder(output).Encode(applied)
	}
	return writeHumanFrame(output, "tnl apply", "applied", "start remote publishers with tnl publisher serve --group NAME", appliedProjectBlocks(applied)...)
}

func appliedProjectBlocks(applied controlv1.AppliedProjectConfiguration) []clioutput.Block {
	blocks := []clioutput.Block{clioutput.Fields(clioutput.Field{Label: "project key", Value: applied.ProjectKey}, clioutput.Field{Label: "desired revision", Value: strconv.FormatInt(applied.Revision, 10)})}
	for _, service := range applied.Services {
		id := ""
		if service.ServiceId != nil {
			id = *service.ServiceId
		}
		blocks = append(blocks, clioutput.Section(service.Service, clioutput.Fields(clioutput.Field{Label: "publisher", Value: service.PublisherGroup}, clioutput.Field{Label: "service ID", Value: id}, clioutput.Field{Label: "assignment", Value: string(service.ServiceKind)}, clioutput.Field{Label: "desired revision", Value: strconv.FormatInt(service.DesiredRevision, 10)})))
	}
	for _, member := range applied.Members {
		fields := []clioutput.Field{{Label: "publisher ID", Value: member.PublisherIdentityId}, {Label: "observed revision", Value: strconv.FormatInt(member.ObservedRevision, 10)}, {Label: "healthy", Value: strconv.FormatBool(member.Healthy)}}
		fields = append(fields, publisherRuntimeFields(member.Runtime)...)
		blocks = append(blocks, clioutput.Section(member.GroupName, clioutput.Fields(fields...)))
	}
	return blocks
}

package main

import (
	"context"
	"errors"
	"os"

	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/publisher/invocation"
	"github.com/tnldotdev/tnl/internal/publisher/local"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type resolvedNamedInvocation struct {
	telemetryDisabled bool
	project           projectConfiguration
	service           string
}

func namedInvocation(flags publishCommand) (resolvedNamedInvocation, error) {
	if flags.namedOverrides {
		return resolvedNamedInvocation{}, failure.Wrap("select named publication", failure.NamedPublishOverrides, errors.New("policy overrides supplied"))
	}
	if flags.AccessToken != "" || os.Getenv("TNL_ACCESS_TOKEN") != "" {
		return resolvedNamedInvocation{}, failure.Wrap("select named publication", failure.NamedPublishSession, errors.New("access token supplied"))
	}
	project := flags.project
	binding, found := project.Config.Services[flags.Service]
	if !found || !controlv1.ServiceProtocol(config.Protocol(binding)).Valid() || flags.Protocol != "" && flags.Protocol != config.Protocol(binding) {
		return resolvedNamedInvocation{}, failure.Wrap("select named service", failure.PublisherGrantMismatch, errors.New("select a configured service with its declared protocol"))
	}
	if project.Config.Team != nil && flags.selectedTeam == "" {
		return resolvedNamedInvocation{}, failure.Wrap("select named team", failure.NamedPublishTeam, errors.New("explicit team required"))
	}
	if flags.ServerURL != "" {
		server, err := clientstate.CanonicalServer(flags.ServerURL)
		if err != nil {
			return resolvedNamedInvocation{}, err
		}
		project.Config.Server = &server
	}
	project.Config.Team = nil
	if flags.selectedTeam != "" {
		team := flags.selectedTeam
		project.Config.Team = &team
	}
	return resolvedNamedInvocation{project: project, service: flags.Service, telemetryDisabled: flags.TelemetryDisabled}, nil
}

func runNamedPublish(ctx context.Context, selected resolvedNamedInvocation, stateDir string, output *publishOutput) error {
	return invocation.PublishNamed(ctx, selected.project.Project, selected.service, stateDir, selected.telemetryDisabled, local.EnsureOwner, &invocation.Presentation{Starting: output.starting, Provisioning: output.provisioning, Ready: output.ready, Stopped: output.stopped})
}

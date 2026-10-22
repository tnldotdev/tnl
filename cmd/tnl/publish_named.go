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
	project projectConfiguration
	service string
}
type resolvedPublicInvocation struct{ resolvedNamedInvocation }
type resolvedPrivateInvocation struct {
	resolvedNamedInvocation
	protocol controlv1.ServiceProtocol
}

func namedInvocation(flags publishCommand) (resolvedNamedInvocation, error) {
	if flags.namedOverrides {
		return resolvedNamedInvocation{}, failure.Wrap("select named publication", failure.NamedPublishOverrides, errors.New("policy overrides supplied"))
	}
	if flags.AccessToken != "" || os.Getenv("TNL_ACCESS_TOKEN") != "" {
		return resolvedNamedInvocation{}, failure.Wrap("select named publication", failure.NamedPublishSession, errors.New("access token supplied"))
	}
	project := flags.project
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
	return resolvedNamedInvocation{project: project, service: flags.Service}, nil
}

func resolveNamedPublic(flags publishCommand) (resolvedPublicInvocation, error) {
	selected, err := namedInvocation(flags)
	if err == nil && !config.IsPublicService(selected.project.Config.Services[selected.service]) {
		err = failure.Wrap("select public service", failure.PublisherGrantMismatch, errors.New("configured service is private"))
	}
	return resolvedPublicInvocation{selected}, err
}

func resolveNamedPrivate(flags publishCommand) (resolvedPrivateInvocation, error) {
	selected, err := namedInvocation(flags)
	protocol := controlv1.ServiceProtocol(flags.Protocol)
	if err == nil && (!protocol.Valid() || config.IsPublicService(selected.project.Config.Services[selected.service])) {
		err = failure.Wrap("select service", failure.PublisherGrantMismatch, errors.New("configured service is not private"))
	}
	return resolvedPrivateInvocation{selected, protocol}, err
}

func runNamedPublish(ctx context.Context, selected resolvedNamedInvocation, stateDir string, output *publishOutput) error {
	return invocation.PublishNamed(ctx, selected.project.Project, selected.service, stateDir, local.EnsureOwner, &invocation.Presentation{Starting: output.starting, Provisioning: output.provisioning, Ready: output.ready, Stopped: output.stopped})
}

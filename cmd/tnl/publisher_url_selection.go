package main

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"github.com/tnldotdev/tnl/internal/controlclient"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/localproxy"
	"github.com/tnldotdev/tnl/internal/opaqueid"
	"github.com/tnldotdev/tnl/internal/projectconfig"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

func resolveEnrollmentConfig(flags publisherEnrollCommand, project projectConfiguration) (publisherEnrollCommand, error) {
	service := flags.Selector
	if service == "" && flags.Target == "" && flags.PublicURL == "" && flags.Name == "" && project.Found() && len(project.Config.Services) != 0 {
		selected, err := project.defaultService()
		if err != nil {
			return flags, err
		}
		service = selected
	}
	if service != "" {
		if !project.Found() {
			return flags, failure.Wrap("select project service", failure.ServiceNotConfigured, errors.New("a configured project service is required"))
		}
		effective, err := project.EffectiveService(service)
		if err != nil {
			return flags, failure.Wrap("select project service", failure.ServiceNotConfigured, err)
		}
		if effective.Tunnel != nil {
			if flags.PublicURL == "" && flags.Name == "" {
				if effective.Tunnel.PublicURL != nil {
					flags.PublicURL = *effective.Tunnel.PublicURL
				} else if effective.Tunnel.Name != nil {
					flags.Name = *effective.Tunnel.Name
				}
			}
			if flags.Domain == "" && effective.Tunnel.Domain != nil {
				flags.Domain = *effective.Tunnel.Domain
			}
			if flags.AllowIP == nil && !flags.AllowAllIPs {
				flags.AllowIP = slices.Clone(effective.Tunnel.AllowIP)
				if flags.AllowIP == nil && effective.Tunnel.AllowAllIPs != nil {
					flags.AllowAllIPs = *effective.Tunnel.AllowAllIPs
				}
			}
		}
		if flags.PublicURL == "" && flags.Name == "" {
			flags.Name = projectconfig.ServiceWorktreeLabel(service, project.Worktree)
		}
	}
	if flags.Name != "" && flags.PublicURL != "" {
		return flags, failure.Wrap("validate public URL options", failure.InvalidTunnelFlags, errors.New("--name and --public-url are mutually exclusive"))
	}
	return flags, nil
}

// selectEnrollmentURL creates or reuses one saved URL in the editor's team.
func selectEnrollmentURL(ctx context.Context, session *teamSession, flags publisherEnrollCommand, protocol controlv1.PublicURLServiceProtocol) (controlv1.PublicURL, error) {
	target := ""
	if flags.Target != "" {
		var err error
		target, err = localproxy.NormalizeTarget(flags.Target)
		if err != nil {
			return controlv1.PublicURL{}, err
		}
	}
	team := flags.Team
	if team == "" {
		team = flags.ProjectTeam
	}
	services, err := preparePublisherServices(ctx, session.database, session.authenticated.ServerEndpoint, flags.PublicURL, flags.Name, flags.Domain, team, false, session.authenticated)
	if err != nil {
		return controlv1.PublicURL{}, err
	}
	policy, err := resolveIPPolicy(ctx, session.authenticated.Control, flags.AllowIP, flags.AllowAllIPs)
	if err != nil {
		return controlv1.PublicURL{}, err
	}
	route, err := session.authenticated.Control.GetPublicURLByHostname(ctx, services.TeamID, services.Hostname)
	if errors.Is(err, controlclient.ErrNotFound) {
		key, keyErr := opaqueid.New(opaqueid.IdempotencyPrefix)
		if keyErr != nil {
			return controlv1.PublicURL{}, keyErr
		}
		request := controlv1.CreatePublicURLRequest{
			TeamId: services.TeamID, DomainId: services.DomainID, CanonicalHostname: services.Hostname,
			Target: target, PublicUrlScope: services.PublicURLScope, Purpose: controlv1.App,
		}
		if protocol != controlv1.Http {
			request.ServiceProtocol = &protocol
		}
		if services.PublicURLScope == controlv1.Member {
			request.MembershipId = &services.MembershipID
		}
		if policy.prefixes != nil {
			copy := slices.Clone(policy.prefixes)
			request.AllowedIpPrefixes = &copy
		}
		route, err = session.authenticated.Control.CreatePublicURL(ctx, request, key)
	}
	if err != nil {
		return controlv1.PublicURL{}, err
	}
	currentPolicy := []string{}
	if route.AllowedIpPrefixes != nil {
		currentPolicy = *route.AllowedIpPrefixes
	}
	if target != "" && route.Target != target || route.ServiceProtocol != protocol ||
		protocol != controlv1.Http && (route.Target != "" || route.PublicPort == nil) ||
		route.CanonicalHostname != services.Hostname || route.Purpose != controlv1.App ||
		route.Ephemeral || !slices.Equal(currentPolicy, policy.prefixes) {
		return controlv1.PublicURL{}, failure.Wrap("select public URL for publisher enrollment", failure.ServerConflict,
			fmt.Errorf("public URL %s already exists with a different target or visitor policy", route.Id))
	}
	return route, nil
}

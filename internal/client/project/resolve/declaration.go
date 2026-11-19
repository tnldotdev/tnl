package resolve

import (
	"context"
	"encoding/json"
	"errors"
	"maps"
	"slices"

	clientcontrol "github.com/tnldotdev/tnl/internal/client/control"
	clientproject "github.com/tnldotdev/tnl/internal/client/project"
	"github.com/tnldotdev/tnl/internal/client/team"
	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/failure"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

// Declaration sends shared service policy and required target trust. local target
// selection, readiness, mounts, and integration handlers stay with the publisher.
// saved remote deployments retain the configuration their publishers need.
func Declaration(ctx context.Context, project clientproject.Project, current team.Context, discover func(context.Context, string) (string, error), selected ...string) (controlv1.ProjectConfiguration, error) {
	declaration := controlv1.ProjectConfiguration{Webhooks: map[string]controlv1.ProjectWebhook{}, Services: map[string]controlv1.ProjectServiceConfiguration{}}
	if err := config.ValidateTNL(project.Config); err != nil {
		return declaration, err
	}
	deployment := config.SelectedDeployment(project.Config)
	if deployment != "local" {
		settings := project.Config.DeploymentSettings
		entry := controlv1.DeploymentSettings{Description: settings.Description}
		if settings.Domain != nil {
			domain, err := current.ReadyDomain(*settings.Domain)
			if err != nil {
				return declaration, err
			}
			entry.DomainId = &domain.Id
		}
		declaration.Settings = &entry
	}
	names := slices.Sorted(maps.Keys(project.Config.Services))
	if len(selected) != 0 {
		names = selected
	}
	for _, name := range names {
		service := project.Config.Services[name]
		savedName, protocol := config.ServiceName(name, service), controlv1.ServiceProtocol(config.Protocol(service))
		entry := controlv1.ProjectServiceConfiguration{Name: &savedName, Protocol: &protocol, Public: service.Public,
			Hostname: service.Hostname, PublisherAliasParent: service.RunAliasParent, CertificateScope: service.CertificateScope, Ephemeral: service.Ephemeral, RequirePostQuantum: service.RequirePostQuantum}
		if service.Domain != nil {
			domain, err := current.ReadyDomain(*service.Domain)
			if err != nil {
				return declaration, err
			}
			entry.DomainId = &domain.Id
		} else if service.Hostname != nil {
			domain, err := team.ReadyDomainForHostname(current.Domains(), *service.Hostname)
			if err != nil {
				return declaration, err
			}
			entry.DomainId = &domain.Id
		}
		traffic, err := config.ResolveTrafficSelection(service.Traffic)
		if err != nil {
			return declaration, err
		}
		entry.Traffic, err = clientcontrol.TrafficSelection(traffic)
		if err != nil {
			return declaration, err
		}
		httpPolicy := service.HTTP
		if deployment == "local" {
			httpPolicy = config.HTTPRequestPolicy(httpPolicy)
		}
		if httpPolicy != nil {
			httpSettings := *httpPolicy
			if httpSettings.Access != nil {
				access := *httpSettings.Access
				if err := access.Validate(); err != nil {
					return declaration, err
				}
				httpSettings.Access = &access
			}
			encoded, err := json.Marshal(httpSettings)
			if err != nil {
				return declaration, err
			}
			entry.Http = &controlv1.ProjectServiceHTTP{}
			if err := json.Unmarshal(encoded, entry.Http); err != nil {
				return declaration, err
			}
		}
		cloud := config.TargetType(service) == "eks" || config.TargetType(service) == "rds"
		if deployment == "local" {
			// the application owns the listener for every local protocol.
			entry.Target = "app"
		} else if cloud {
			t := service.Target
			entry.TargetDiscovery = &controlv1.ProjectTargetDiscovery{Type: controlv1.ProjectTargetDiscoveryType(t.Type), Region: *t.Region, Cluster: t.Cluster, Instance: t.Instance}
			if t.Endpoint != nil {
				endpoint := controlv1.ProjectTargetDiscoveryEndpoint(*t.Endpoint)
				entry.TargetDiscovery.Endpoint = &endpoint
			}
		} else if config.TargetType(service) == "app" {
			entry.Target = "app"
		} else {
			resolved, err := project.ResolvePublish(name, "")
			if err != nil {
				return declaration, err
			}
			entry.Target = string(*resolved.Target)
		}
		if service.Access != nil {
			entry.Access = &controlv1.ProjectServiceAccess{Team: controlv1.ProjectServiceAccessTeam(service.Access.Team)}
		}
		if !cloud && service.Target != nil && service.Target.TLS != nil {
			discovered := ""
			if config.TargetType(service) != "address" && config.TargetType(service) != "app" {
				if discover == nil {
					return declaration, errors.New("target discovery is required to capture configured trust")
				}
				resolved, err := discover(ctx, name)
				if err != nil {
					return declaration, err
				}
				discovered = resolved
			}
			{
				trust, err := project.CaptureTargetTrust(ctx, name, discovered)
				if err != nil {
					return declaration, err
				}
				entry.TargetTls = &controlv1.ProjectTargetTLS{Hostname: trust.Hostname, Digest: trust.Digest, HostnameFromTarget: trust.HostnameFromTarget}
				if len(trust.CAPEM) != 0 {
					pem := string(trust.CAPEM)
					entry.TargetTls.CaPem = &pem
				}
			}
		}
		declaration.Services[name] = entry
	}
	encoded, err := json.Marshal(declaration)
	if err != nil {
		return declaration, err
	}
	if len(encoded) > 512<<10 {
		return declaration, failure.Wrap("encode project configuration", failure.ProjectConfigInvalid, errors.New("normalized configuration and trust snapshots exceed 512 KiB"))
	}
	return declaration, nil
}

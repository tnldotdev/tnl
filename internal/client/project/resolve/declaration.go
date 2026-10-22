package resolve

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"slices"

	clientproject "github.com/tnldotdev/tnl/internal/client/project"
	"github.com/tnldotdev/tnl/internal/client/team"
	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/security/targettrust"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

// Declaration sends evaluated declarations, never executable TypeScript or local
// paths that a remote publisher would need to reopen. discover is needed only
// when capturing target trust for a local Docker or Compose target.
func Declaration(ctx context.Context, project clientproject.Project, current team.Context, discover func(context.Context, string) (string, error), selected ...string) (controlv1.ProjectConfiguration, error) {
	declaration := controlv1.ProjectConfiguration{Oauth: project.Config.OAuth, Webhooks: map[string]controlv1.ProjectWebhook{}, PublisherGroups: map[string]controlv1.ProjectPublisherGroup{}, Services: map[string]controlv1.ProjectServiceConfiguration{}}
	if err := config.ValidateTNL(project.Config); err != nil {
		return declaration, err
	}
	for name, group := range project.Config.PublisherGroups {
		entry := controlv1.ProjectPublisherGroup{Description: group.Description, Public: &group.Public}
		if group.Domain != nil {
			domain, err := current.ReadyDomain(*group.Domain)
			if err != nil {
				return declaration, err
			}
			entry.DomainId = &domain.Id
		}
		declaration.PublisherGroups[name] = entry
	}
	for name, webhook := range project.Config.Webhooks {
		delivery := webhook.DeliveryMode()
		methods := slices.Clone(webhook.Methods)
		if len(methods) == 0 {
			methods = []string{http.MethodPost}
		}
		slices.Sort(methods)
		entry := controlv1.ProjectWebhook{Service: webhook.Service, Path: webhook.Path, Provider: controlv1.WebhookProvider(webhook.Provider), Delivery: &delivery, Methods: &methods}
		if len(webhook.SourceIPs) != 0 {
			ips := slices.Clone(webhook.SourceIPs)
			slices.Sort(ips)
			entry.SourceIps = &ips
		}
		declaration.Webhooks[name] = entry
	}
	cache := targettrust.NewCache(nil)
	names := slices.Sorted(maps.Keys(project.Config.Services))
	if len(selected) != 0 {
		names = selected
	}
	for _, name := range names {
		service := project.Config.Services[name]
		publisher, savedName, protocol := config.PublisherGroupName(service), config.ServiceName(name, service), controlv1.ServiceProtocol(config.Protocol(service))
		entry := controlv1.ProjectServiceConfiguration{PublisherGroup: &publisher, Name: &savedName, Protocol: &protocol}
		httpSettings := service.HTTP
		if publisher != "local" {
			resolved, err := config.ResolveGroupHTTP(project.Config.Tunnel, service.HTTP)
			if err != nil {
				return declaration, err
			}
			httpSettings = resolved
		}
		if httpSettings != nil {
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
		if cloud {
			t := service.Target
			entry.TargetDiscovery = &controlv1.ProjectTargetDiscovery{Type: controlv1.ProjectTargetDiscoveryType(t.Type), Region: *t.Region, Cluster: t.Cluster, Instance: t.Instance}
			if t.Endpoint != nil {
				endpoint := controlv1.ProjectTargetDiscoveryEndpoint(*t.Endpoint)
				entry.TargetDiscovery.Endpoint = &endpoint
			}
		} else if publisher == "local" {
			// local discovery stays local. this declarative descriptor contains no
			// checkout path, discovered container address or running app listener.
			entry.Target = config.TargetType(service)
			if service.Target != nil {
				switch service.Target.Type {
				case "address":
					resolved, err := project.ResolvePublish(name, "")
					if err != nil {
						return declaration, err
					}
					entry.Target = string(*resolved.Target)
				case "compose":
					entry.Target = fmt.Sprintf("compose:%s:%d", *service.Target.Service, *service.Target.Port)
				case "docker":
					entry.Target = fmt.Sprintf("docker:%s:%d", *service.Target.Container, *service.Target.Port)
				}
			}
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
			if service.Target != nil && service.Target.TLS != nil {
				trust, err := project.CaptureTargetTrust(ctx, cache, name, discovered)
				if err != nil {
					return declaration, err
				}
				entry.TargetTls = &controlv1.ProjectTargetTLS{Hostname: trust.Hostname, Digest: trust.Digest}
				if len(trust.CAPEM) != 0 {
					pem := string(trust.CAPEM)
					entry.TargetTls.CaPem = &pem
				}
			}
		}
		if config.IsPublicService(service) {
			effective, err := project.EffectiveService(name)
			if err != nil {
				return declaration, err
			}
			entry.PublicUrl, err = projectPublicURL(effective.Tunnel)
			if err != nil {
				return declaration, err
			}
			if publisher == "local" {
				if effective.Tunnel.PublicURL != nil {
					hostname, _ := naming.ParseExactPublicURL(*effective.Tunnel.PublicURL)
					entry.PublicUrl.Hostname = &hostname
				}
				if effective.Tunnel.Domain != nil {
					domain, err := current.ReadyDomain(*effective.Tunnel.Domain)
					if err != nil {
						return declaration, err
					}
					entry.PublicUrl.DomainId = &domain.Id
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

func projectPublicURL(tunnel *config.Tunnel) (*controlv1.ProjectServicePublicURL, error) {
	value := &controlv1.ProjectServicePublicURL{Ephemeral: tunnel.Ephemeral}
	if tunnel.Access != nil {
		mode := controlv1.VisitorAccessMode(tunnel.Access.VisitorMode())
		value.Access = &controlv1.ProjectPublicAccess{Mode: &mode}
		if len(tunnel.Access.IP) != 0 {
			ip := slices.Clone(tunnel.Access.IP)
			slices.Sort(ip)
			value.Access.Ip = &ip
		}
	}
	if tunnel.Limits != nil && (tunnel.Limits.HTTP != nil || tunnel.Limits.Traffic != nil) {
		wire := &controlv1.ProjectPublicLimits{}
		if h := tunnel.Limits.HTTP; h != nil {
			wire.Http = &controlv1.ProjectHTTPApplicationLimits{Total: h.Total, Concurrency: h.Concurrency}
			if r := h.Rate; r != nil {
				wire.Http.Rate = &controlv1.ProjectApplicationRate{Count: *r.Count, Per: r.Per.Value().String(), Burst: r.Burst}
			}
		}
		traffic, err := config.ResolveTrafficSelection(tunnel.Limits)
		if err != nil {
			return nil, err
		}
		if traffic != nil {
			wire.Traffic = &controlv1.TrafficSelection{Connections: traffic.Connections, Rate: traffic.Rate, RatePer: traffic.RatePer, Burst: traffic.Burst, UploadBytes: traffic.UploadBytes, DownloadBytes: traffic.DownloadBytes, TotalConnections: traffic.TotalConnections, TotalUploadBytes: traffic.TotalUploadBytes, TotalDownloadBytes: traffic.TotalDownloadBytes}
		}
		value.Limits = wire
	}
	return value, nil
}

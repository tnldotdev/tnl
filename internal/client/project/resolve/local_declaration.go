package resolve

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"

	clientproject "github.com/tnldotdev/tnl/internal/client/project"
	"github.com/tnldotdev/tnl/internal/client/team"
	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/security/targettrust"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

// local service declaration realizes only this worktree's owned listener. it
// does not publish definitions, apply environments or establish workload grants.
func LocalServiceDeclaration(ctx context.Context, project clientproject.Project, current team.Context, name string, discover func(context.Context, string) (string, error)) (controlv1.LocalServiceDeclaration, error) {
	if err := config.ValidateTNL(project.Config); err != nil {
		return controlv1.LocalServiceDeclaration{}, err
	}
	service, found := project.Config.Services[name]
	if !found {
		return controlv1.LocalServiceDeclaration{}, errors.New("local service is not declared")
	}
	savedName, protocol := config.ServiceName(name, service), controlv1.ServiceProtocol(config.Protocol(service))
	entry := controlv1.LocalServiceDeclaration{Name: &savedName, Protocol: &protocol, Target: config.TargetType(service)}
	if service.HTTP != nil {
		encoded, err := json.Marshal(service.HTTP)
		if err != nil {
			return entry, err
		}
		entry.Http = &controlv1.ProjectServiceHTTP{}
		if err := json.Unmarshal(encoded, entry.Http); err != nil {
			return entry, err
		}
	}
	if t := service.Target; t != nil {
		switch t.Type {
		case "address":
			resolved, err := project.ResolvePublish(name, "")
			if err != nil {
				return entry, err
			}
			entry.Target = string(*resolved.Target)
		case "compose":
			entry.Target = fmt.Sprintf("compose:%s:%d", *t.Service, *t.Port)
		case "docker":
			entry.Target = fmt.Sprintf("docker:%s:%d", *t.Container, *t.Port)
		case "eks", "rds":
			entry.Target = ""
			entry.TargetDiscovery = &controlv1.ProjectTargetDiscovery{Type: controlv1.ProjectTargetDiscoveryType(t.Type), Region: *t.Region, Cluster: t.Cluster, Instance: t.Instance}
			if t.Endpoint != nil {
				entry.TargetDiscovery.Endpoint = new(controlv1.ProjectTargetDiscoveryEndpoint(*t.Endpoint))
			}
		}
	}
	if service.Access != nil {
		entry.Access = &controlv1.ProjectServiceAccess{Team: controlv1.ProjectServiceAccessTeam(service.Access.Team)}
	}
	if service.Target != nil && service.Target.TLS != nil {
		discovered := ""
		if config.TargetType(service) != "address" && config.TargetType(service) != "app" {
			if discover == nil {
				return entry, errors.New("target discovery is required to capture configured trust")
			}
			var err error
			discovered, err = discover(ctx, name)
			if err != nil {
				return entry, err
			}
		}
		trust, err := project.CaptureTargetTrust(ctx, targettrust.NewCache(nil), name, discovered)
		if err != nil {
			return entry, err
		}
		entry.TargetTls = &controlv1.ProjectTargetTLS{Hostname: trust.Hostname, Digest: trust.Digest}
		if len(trust.CAPEM) != 0 {
			entry.TargetTls.CaPem = new(string(trust.CAPEM))
		}
	}
	if config.IsPublicService(service) {
		effective, err := project.EffectiveService(name)
		if err != nil {
			return entry, err
		}
		entry.PublicUrl, err = localPublicURL(effective.Tunnel)
		if err != nil {
			return entry, err
		}
		if effective.Tunnel.PublicURL != nil {
			hostname, _ := naming.ParseExactPublicURL(*effective.Tunnel.PublicURL)
			entry.PublicUrl.Hostname = &hostname
		}
		if effective.Tunnel.Domain != nil {
			domain, err := current.ReadyDomain(*effective.Tunnel.Domain)
			if err != nil {
				return entry, err
			}
			entry.PublicUrl.DomainId = &domain.Id
		}
	}
	return entry, nil
}

func localPublicURL(tunnel *config.Tunnel) (*controlv1.ProjectServicePublicURL, error) {
	value := &controlv1.ProjectServicePublicURL{Ephemeral: tunnel.Ephemeral, RequirePostQuantum: tunnel.RequirePostQuantum}
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

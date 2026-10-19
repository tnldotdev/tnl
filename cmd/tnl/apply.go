package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/http"
	"slices"
	"strconv"

	"github.com/tnldotdev/tnl/internal/clioutput"
	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/controlclient"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/privatetrust"
	"github.com/tnldotdev/tnl/internal/projectconfig"
	"github.com/tnldotdev/tnl/internal/projectpublisher"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

type applyCommand struct {
	scopedTeamFlags `embed:""`
	Output          statusOutputMode `name:"output" enum:"human,json" default:"human"`
}

// apply sends evaluated declarations, never executable TypeScript or local paths
// that a remote publisher would need to reopen on this machine.
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
	current, err := session.currentWithDomains(ctx)
	if err != nil {
		return err
	}
	declaration, err := projectDeclaration(ctx, project, current, source)
	if err != nil {
		return err
	}
	revision := int64(0)
	existing, err := session.authenticated.Control.GetProjectConfiguration(ctx, current.team.Id, source.Key)
	if err == nil {
		if existing.SourceFingerprint != source.Fingerprint {
			return publisherCLIError("project key belongs to another configuration source")
		}
		revision = existing.Revision
	} else if !errors.Is(err, controlclient.ErrNotFound) {
		return err
	}
	applied, err := session.authenticated.Control.ApplyProjectConfiguration(ctx, source.Key, controlv1.ApplyProjectConfigurationRequest{
		TeamId: current.team.Id, SourceFingerprint: source.Fingerprint, ExpectedRevision: revision, Configuration: declaration,
		ProjectLabel: &source.Label,
	})
	if err != nil {
		return err
	}
	if applied.ProjectKey != source.Key || applied.TeamId != current.team.Id || applied.SourceFingerprint != source.Fingerprint || applied.Revision < 1 {
		return failure.Wrap("read applied project", failure.ServerResponseInvalid, errors.New("control returned another project configuration"))
	}
	if flags.Output == statusOutputJSON {
		return json.NewEncoder(output).Encode(applied)
	}
	return writeHumanFrame(output, "tnl apply", "applied", "start remote publishers with tnl publisher serve --group NAME", appliedProjectBlocks(applied)...)
}

func projectDeclaration(ctx context.Context, project projectConfiguration, current teamContext, source projectconfig.SourceIdentity, selected ...string) (controlv1.ProjectConfiguration, error) {
	declaration := controlv1.ProjectConfiguration{Oauth: project.Config.OAuth, Webhooks: map[string]controlv1.ProjectWebhook{}, Publishers: map[string]controlv1.ProjectPublisherGroup{}, Services: map[string]controlv1.ProjectServiceConfiguration{}}
	if err := config.ValidateTNL(project.Config); err != nil {
		return declaration, err
	}
	for name, group := range project.Config.Publishers {
		entry := controlv1.ProjectPublisherGroup{Description: group.Description, Public: &group.Public}
		if group.Domain != nil {
			domain, err := readyDomain(current, *group.Domain)
			if err != nil {
				return declaration, err
			}
			entry.DomainId = &domain.Id
		}
		declaration.Publishers[name] = entry
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
	cache := privatetrust.NewCache(nil)
	names := slices.Sorted(maps.Keys(project.Config.Services))
	if len(selected) != 0 {
		names = selected
	}
	for _, name := range names {
		service := project.Config.Services[name]
		publisher, savedName, protocol := config.PublisherName(service), config.ServiceName(name, service), controlv1.PrivateServiceProtocol(config.Protocol(service))
		entry := controlv1.ProjectServiceConfiguration{Publisher: &publisher, Name: &savedName, Protocol: &protocol}
		if service.HTTP != nil {
			encoded, err := json.Marshal(service.HTTP)
			if err != nil {
				return declaration, err
			}
			entry.Http = &controlv1.ProjectServiceHTTP{}
			if err := json.Unmarshal(encoded, entry.Http); err != nil {
				return declaration, err
			}
		}
		if publisher == "local" {
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
		if service.Target != nil && service.Target.TLS != nil {
			discovered := ""
			if config.TargetType(service) != "address" && config.TargetType(service) != "app" {
				resolved, err := projectpublisher.ResolveTarget(ctx, project.Project, name, runtimeTargetResolver)
				if err != nil {
					return declaration, err
				}
				discovered = string(*resolved.Target)
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
					domain, err := readyDomain(current, *effective.Tunnel.Domain)
					if err != nil {
						return declaration, err
					}
					entry.PublicUrl.DomainId = &domain.Id
				}
			} else {
				if effective.Tunnel.PublicURL != nil || effective.Tunnel.Domain != nil || effective.Tunnel.Ephemeral != nil && *effective.Tunnel.Ephemeral || entry.PublicUrl.Limits != nil && entry.PublicUrl.Limits.Traffic != nil || entry.PublicUrl.Access != nil && entry.PublicUrl.Access.Mode != nil && *entry.PublicUrl.Access.Mode != "restricted" {
					return declaration, publisherCLIError("named publisher HTTP uses the group's domain and public setting; select restricted access and remove endpoint, ephemeral, and traffic-limit overrides")
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

func appliedProjectBlocks(applied controlv1.AppliedProjectConfiguration) []clioutput.Block {
	blocks := []clioutput.Block{clioutput.Fields(clioutput.Field{Label: "project key", Value: applied.ProjectKey}, clioutput.Field{Label: "desired revision", Value: strconv.FormatInt(applied.Revision, 10)})}
	for _, service := range applied.Services {
		id := ""
		if service.ServiceId != nil {
			id = *service.ServiceId
		}
		blocks = append(blocks, clioutput.Section(service.Service, clioutput.Fields(clioutput.Field{Label: "publisher", Value: service.Publisher}, clioutput.Field{Label: "service ID", Value: id}, clioutput.Field{Label: "assignment", Value: string(service.ServiceKind)}, clioutput.Field{Label: "desired revision", Value: strconv.FormatInt(service.DesiredRevision, 10)})))
	}
	for _, member := range applied.Members {
		blocks = append(blocks, clioutput.Section(member.GroupName, clioutput.Fields(clioutput.Field{Label: "publisher ID", Value: member.PublisherIdentityId}, clioutput.Field{Label: "observed revision", Value: strconv.FormatInt(member.ObservedRevision, 10)}, clioutput.Field{Label: "healthy", Value: strconv.FormatBool(member.Healthy)})))
	}
	return blocks
}

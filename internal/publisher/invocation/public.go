package invocation

import (
	"context"
	"errors"
	"slices"

	"github.com/tnldotdev/tnl/internal/client/project/resolve"
	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/publisher"
	"github.com/tnldotdev/tnl/internal/publisher/app"
	integrationurls "github.com/tnldotdev/tnl/internal/publisher/integrations"
	localproxy "github.com/tnldotdev/tnl/internal/publisher/proxy"
	"github.com/tnldotdev/tnl/internal/publisher/target"
)

func (a *ProjectRuntime) PublicConfiguration(ctx context.Context, service app.Service) (app.Configuration, error) {
	project := a.project
	effective, err := project.EffectiveService(service.Name)
	if err != nil {
		return app.Configuration{}, err
	}
	resolver := resolve.NewMetadataResolver(a.state, project.Project, authenticateRuntime)
	authenticated, selectedTeam, err := resolver.Context(ctx, effective)
	if err != nil {
		return app.Configuration{}, err
	}
	current := FromTeamContext(selectedTeam)
	server := authenticated.ServerEndpoint
	selected, err := resolve.ConfiguredService(service.Name, project.Worktree, effective, selectedTeam)
	if err != nil {
		return app.Configuration{}, err
	}
	services, err := preparePublisherServices(ctx, a.state, server, "https://"+selected.Hostname, "", "", valueOrEmpty(effective.Team), false, authenticated)
	if err != nil {
		return app.Configuration{}, err
	}
	var access *config.Access
	if effective.Tunnel != nil {
		access = effective.Tunnel.Access
	}
	policy, err := resolveVisitorAccess(ctx, authenticated.Control, access, false, nil)
	if err != nil {
		return app.Configuration{}, err
	}
	limits, err := config.ResolveWorkLimits(effectiveTunnelLimits(effective), service.ServiceProtocol)
	if err != nil {
		return app.Configuration{}, err
	}
	inspectionPolicy, err := config.ResolveInspection(effective.Inspection, service.ServiceProtocol)
	if err != nil {
		return app.Configuration{}, err
	}
	cfg := services.config(service.Target, policy.prefixes, limits)
	if policy.explicit {
		cfg.AccessMode = policy.access
	}
	binding := target.RuntimeTargetBinding(project.Project, service.Name, service.Target, nil, a.TargetResolver)
	captured, err := binding.Capture(ctx)
	if err != nil {
		return app.Configuration{}, err
	}
	cfg.Target = captured.Address
	cfg.ResolveTarget = func(ctx context.Context) (string, string, error) {
		selected, err := binding.Capture(ctx)
		return selected.Address, selected.Identity, err
	}
	cfg.ControlURL, cfg.ProjectRoot, cfg.Service = server, project.Root, service.Name
	cfg.ServiceProtocol = protocolForService(project.Config.Services[service.Name])
	cfg.PreserveSavedURLTarget = true
	resolved := config.ServicePublish(project.Config.Services[service.Name])
	if resolved.TargetTLSName != nil {
		cfg.TargetTLSName = *resolved.TargetTLSName
	}
	if resolved.TargetCAFile != nil {
		cfg.TargetOptions, err = localproxy.TargetOptionsForCA(*resolved.TargetCAFile, project.Root)
		if err != nil {
			return app.Configuration{}, err
		}
	}
	native, err := selectNativeProjectPublisher(ctx, services, cfg)
	if err != nil {
		return app.Configuration{}, err
	}
	route, err := native.SavedURL(ctx)
	if err != nil {
		return app.Configuration{}, err
	}
	realized, err := RealizeLocalService(ctx, services.authenticated.Control, LocalService{Project: project.Project, Team: current, Name: service.Name, PublicURLID: route.Id, TargetResolver: a.TargetResolver})
	if err != nil {
		return app.Configuration{}, err
	}
	if realized.Hostname == nil || *realized.Hostname != cfg.Hostname {
		return app.Configuration{}, failure.Wrap("realize local public URL", failure.ServerResponseInvalid, errors.New("control returned another public hostname"))
	}
	traffic, err := config.ResolveTrafficSelection(effectiveTunnelLimits(effective))
	if err != nil {
		return app.Configuration{}, err
	}
	native, err = native.WithTraffic(traffic)
	if err != nil {
		return app.Configuration{}, err
	}
	cfg.Control, cfg.PublisherID = native, native.PublisherID()
	if a.AttachPublication != nil {
		if err := a.AttachPublication(ctx, service, &cfg); err != nil {
			return app.Configuration{}, err
		}
	}
	cfg.Mounts, err = ProjectMounts(project.Project, service.Name, func(name string) string {
		for _, candidate := range a.manager.Snapshot().Services {
			if candidate.Name == name && a.manager.Current(name, candidate.RegistrationID, candidate.Target, 0) {
				return candidate.Target
			}
		}
		return ""
	}, a.TargetResolver)
	if err != nil {
		return app.Configuration{}, err
	}
	previewID, err := ensurePreview(ctx, a.state, services.state, services.routes, server, services.teamID, project.Root)
	if err != nil {
		return app.Configuration{}, err
	}
	cfg.PreviewID, cfg.Feedback = previewID, project.Config.Feedback != nil && *project.Config.Feedback
	cfg.BrowserLoginAvailable = services.authenticated.Discovery.BrowserLoginAvailable != nil && *services.authenticated.Discovery.BrowserLoginAvailable
	cfg.Observe = func(event publisher.Event) error {
		if event.Type != publisher.EventPublicURLAssigned {
			return nil
		}
		preview, err := services.routes.AddPreviewPublicURL(ctx, previewID, event.PublicURLID)
		if err != nil {
			return err
		}
		if preview.Id != previewID || preview.TeamId != services.teamID || !slices.Contains(preview.PublicUrlIds, event.PublicURLID) {
			return failure.Wrap("associate preview", failure.ServerResponseInvalid, errors.New("preview omitted assigned public URL"))
		}
		return nil
	}
	group := projectIntegrationGroup(project.Project, services.namespace)
	configuration := app.Configuration{Publisher: cfg, TargetBinding: binding, Inspection: inspectionPolicy, PrimaryRoot: project.Worktree.PrimaryCheckoutRoot(), SharedRoot: project.Worktree.PrimaryCheckoutRoot(), IntegrationGroup: group}
	configuration.Attach = func(ctx context.Context, tunnel *clientstate.Tunnel, cfg *publisher.Config) (func(), error) {
		if project.Config.OAuth {
			origin, _, err := projectOAuthPublisher(ctx, a.state, project.Project, server, valueOrEmpty(project.Config.Team), services.authenticated)
			if err != nil {
				return nil, err
			}
			cfg.ObserveResponse = integrationurls.Observer(a.state, server, origin.Hostname, group, tunnel.ID())
		}
		return attachRuntimeIntegrations(ctx, a.state, project.Project, service, tunnel, cfg)
	}
	return configuration, nil
}

package invocation

import (
	"context"
	"slices"
	"strings"

	clientcontrol "github.com/tnldotdev/tnl/internal/client/control"
	"github.com/tnldotdev/tnl/internal/client/project/resolve"
	clientteam "github.com/tnldotdev/tnl/internal/client/team"
	"github.com/tnldotdev/tnl/internal/config"
	installedjobs "github.com/tnldotdev/tnl/internal/installed"
	"github.com/tnldotdev/tnl/internal/policy/trafficlimits"
	publisheridentity "github.com/tnldotdev/tnl/internal/publisher/identity"
	"github.com/tnldotdev/tnl/internal/publisher/setup"
	"github.com/tnldotdev/tnl/internal/publisher/target"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type InstallationOptions struct {
	PublicOptions
	Installation   installedjobs.ServiceOptions
	ServiceName    string
	ReadinessPath  string
	ServerCAFile   string
	StreamCapacity int32
	Traffic        *trafficlimits.Selection
}

func InstallHTTP(ctx context.Context, flags InstallationOptions, presentation setup.Presentation) error {
	if flags.Ephemeral || flags.Demo || flags.StreamCapacity < 0 || flags.StreamCapacity > 4096 {
		return installedjobs.ErrScope
	}
	if flags.Service != "" {
		definition, found := flags.Project.Config.Services[flags.Service]
		if !found || config.Protocol(definition) != "http" || config.TargetType(definition) == "app" {
			return installedjobs.ErrScope
		}
		resolved, err := target.ResolveTarget(ctx, flags.Project, flags.Service, flags.Resolver)
		if err != nil {
			return err
		}
		if resolved.Target == nil {
			return installedjobs.ErrScope
		}
		flags.Target = string(*resolved.Target)
		effective, err := flags.Project.EffectiveService(flags.Service)
		if err != nil {
			return err
		}
		if flags.Traffic == nil {
			flags.Traffic, err = config.ResolveTrafficSelection(effective.Traffic)
			if err != nil {
				return err
			}
		}
		if flags.ReadinessPath == "" && effective.HTTP != nil && effective.HTTP.Readiness != nil {
			flags.ReadinessPath = effective.HTTP.Readiness.Path
		}
	}
	if flags.Traffic != nil {
		if err := flags.Traffic.Validate(); err != nil {
			return err
		}
	}
	address, err := target.NormalizePrivateAddress(flags.Target, controlv1.ServiceProtocolHTTP)
	if err != nil {
		return err
	}
	selected := ServiceOptions{PublicOptions: flags.PublicOptions}
	if strings.HasPrefix(address, "https://") {
		selected.TargetTLS = new(true)
	}
	trust, err := CaptureServiceTargetTrust(ctx, selected, controlv1.ServiceProtocolHTTP, address)
	if err != nil {
		return err
	}
	plan := target.TargetPlan{Protocol: config.ProtocolHTTP, Target: address, Trust: trust}
	if trust != nil && !strings.Contains(flags.Target, "://") {
		plan.Target = "https://" + strings.TrimPrefix(address, "http://")
	}
	if err := plan.Normalize(); err != nil {
		return err
	}
	if err := target.PreflightPrivate(ctx, plan); err != nil {
		return err
	}
	server, database, err := resolveServer(ctx, flags.StateDir, flags.ServerURL)
	if err != nil {
		return err
	}
	defer database.Close()
	authenticated, err := flags.Authenticate(ctx, database, server, flags.AccessToken)
	if err != nil {
		return err
	}
	profile, err := database.Server(ctx, server)
	if err != nil {
		return err
	}
	identity, err := authenticated.Authority.IdentityContext(ctx)
	if err != nil {
		return err
	}
	team := flags.SelectedTeam
	if flags.Team != "" {
		team = flags.Team
	}
	session := clientteam.NewSession(nil, profile, authenticated, identity, clientteam.Options{SelectedTeam: team})
	current, err := session.CurrentWithDomains(ctx)
	if err != nil {
		return err
	}
	control := session.Authenticated().Control
	var service controlv1.Service
	if flags.Service != "" {
		realized, err := RealizeLocalService(ctx, control, LocalService{Project: flags.Project, Team: FromTeamContext(current), Name: flags.Service, Domain: flags.Domain, TargetResolver: flags.Resolver})
		if err != nil {
			return err
		}
		service, err = control.GetService(ctx, realized.ServiceId)
		if err != nil {
			return err
		}
		source := flags.Project.LocalPublicationIdentity()
		if service.Source == nil || service.Source.ProjectKey != source.Key || service.Source.SourceFingerprint != source.Fingerprint ||
			service.Source.WorktreeKey != flags.Project.LocalWorktreeKey() || service.Source.Service != flags.Service {
			return installedjobs.ErrScope
		}
	} else {
		hostname, domain, err := resolve.PublishHostname(flags.PublicURL, flags.Name, flags.Domain, current)
		if err != nil {
			return err
		}
		policy, err := resolveVisitorAccess(ctx, control, flags.Access, flags.Anonymous, flags.IP)
		if err != nil {
			return err
		}
		service, err = prepareInstalledHTTPService(ctx, publisherServices{
			authenticated: session.Authenticated(), state: profile, routes: control,
			hostname: hostname, teamID: current.Team().Id, domainID: domain.Id,
		}, flags, plan, policy)
		if err != nil {
			return err
		}
	}
	if err := validateProfileService(service); err != nil {
		return err
	}
	if service.TeamId != current.Team().Id || service.Ephemeral {
		return installedjobs.ErrScope
	}
	if flags.RequirePostQuantum != nil && *flags.RequirePostQuantum != service.RequirePostQuantum {
		return installedjobs.ErrScope
	}
	if err := publisheridentity.MatchServiceDeclaration(service, "http", trust); err != nil {
		return err
	}
	name := flags.ServiceName
	if name == "" {
		name = service.Name
	}
	job := installedjobs.Job{TelemetryDisabled: flags.TelemetryDisabled, Name: name, Target: plan.Target, Protocol: config.ProtocolHTTP, Trust: trust,
		ReadinessPath: flags.ReadinessPath, PreferredRegions: slices.Clone(flags.PreferredRegions), StreamCapacity: flags.StreamCapacity, Traffic: flags.Traffic}
	if flags.Service != "" {
		project := flags.Project
		job.Project, job.ProjectService = &project, flags.Service
	}
	return setup.InstallPublication(ctx, setup.Publication{Database: database, Server: server, Service: service, Control: control, Options: flags.Installation, Job: job, ServerCAFile: flags.ServerCAFile}, presentation)
}

// installation saves its target and readiness settings on the same service that
// foreground publication selects. omitted policy stays unchanged under the
// shared declaration compare-and-swap; installation credentials remain separate.
func prepareInstalledHTTPService(ctx context.Context, services publisherServices, flags InstallationOptions, plan target.TargetPlan, policy resolvedVisitorAccess) (controlv1.Service, error) {
	declaration := func(current *controlv1.ProjectServiceConfiguration) (controlv1.ProjectServiceConfiguration, error) {
		desired, err := foregroundServiceDeclaration(flags.PublicOptions, policy, plan, current)
		if err != nil {
			return desired, err
		}
		desired.Target = plan.Target
		desired.TargetTls, err = foregroundTargetTLS(plan.Trust)
		if err != nil {
			return desired, err
		}
		if flags.ReadinessPath != "" {
			if desired.Http == nil {
				desired.Http = &controlv1.ProjectServiceHTTP{}
			}
			desired.Http.Readiness = &struct {
				Path string `json:"path"`
			}{Path: flags.ReadinessPath}
		}
		if flags.Traffic != nil {
			desired.Traffic, err = clientcontrol.TrafficSelection(flags.Traffic)
		}
		return desired, err
	}
	initial, err := declaration(nil)
	if err != nil {
		return controlv1.Service{}, err
	}
	return reserveConfiguredService(ctx, services, initial, func(saved controlv1.Service, current *controlv1.ProjectServiceConfiguration) (*controlv1.ProjectServiceConfiguration, error) {
		if current == nil {
			current = &controlv1.ProjectServiceConfiguration{RequirePostQuantum: new(saved.RequirePostQuantum),
				Http: &controlv1.ProjectServiceHTTP{Limits: saved.HttpLimits}}
		}
		desired, err := declaration(current)
		return &desired, err
	})
}

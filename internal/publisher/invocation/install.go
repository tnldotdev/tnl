package invocation

import (
	"context"
	"crypto/sha256"
	"encoding/base32"
	"encoding/hex"
	"slices"
	"strings"

	clientcontrol "github.com/tnldotdev/tnl/internal/client/control"
	"github.com/tnldotdev/tnl/internal/client/project/resolve"
	clientteam "github.com/tnldotdev/tnl/internal/client/team"
	"github.com/tnldotdev/tnl/internal/config"
	installedjobs "github.com/tnldotdev/tnl/internal/installed"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
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
		name := flags.Name
		if name == "" {
			name, _, _ = strings.Cut(hostname, ".")
			if !naming.ValidServiceName(name) {
				digest := sha256.Sum256([]byte(hostname))
				name = "http-" + hex.EncodeToString(digest[:8])
			}
		}
		policy, err := resolveVisitorAccess(ctx, control, flags.Access, flags.Anonymous, flags.IP)
		if err != nil {
			return err
		}
		declaration, err := installedHTTPDeclaration(flags, name, domain.Id, hostname, plan, policy)
		if err != nil {
			return err
		}
		placement := &controlv1.ServicePlacement{DomainId: &domain.Id, Hostname: &hostname}
		worktree := ""
		if flags.Project.Root != "" {
			worktree = flags.Project.LocalWorktreeKey()
			placement.WorktreeKey = &worktree
			if label := flags.Project.Worktree.Label.FullLabel; label != "" {
				placement.WorktreeLabel = &label
			}
		}
		// the control API compares retained normalized intent on every retry.
		// the key identifies this service selection, not a replacement policy.
		key := installedHTTPCreateKey(server, current.Team().Id, domain.Id, hostname, name, worktree)
		service, err = control.CreateServiceAt(ctx, current.Team().Id, name, key, placement,
			controlv1.ServiceMetadata{Protocol: controlv1.ServiceProtocolHTTP, TargetTls: publisheridentity.ServiceTargetTLS(trust), TrustRevision: 1}, &declaration)
		if err != nil {
			return err
		}
		if service.Name != name || service.Source != nil || service.Endpoint == nil || service.Endpoint.Hostname != hostname || service.DomainId == nil || *service.DomainId != domain.Id || !service.Endpoint.Public {
			return installedjobs.ErrScope
		}
		if worktree != "" && (service.Placement == nil || service.Placement.WorktreeKey == nil || *service.Placement.WorktreeKey != worktree) {
			return installedjobs.ErrScope
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

func installedHTTPCreateKey(server, team, domain, hostname, name, worktree string) string {
	digest := sha256.Sum256([]byte(strings.Join([]string{"tnl-installed-service/v1", server, team, domain, hostname, name, worktree}, "\x00")))
	return opaqueid.IdempotencyPrefix + base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(digest[:])[:22]
}

func installedHTTPDeclaration(flags InstallationOptions, name, domain, hostname string, plan target.TargetPlan, policy resolvedVisitorAccess) (controlv1.ProjectServiceConfiguration, error) {
	protocol := controlv1.ServiceProtocolHTTP
	declaration := controlv1.ProjectServiceConfiguration{Name: &name, DomainId: &domain, Hostname: &hostname, Protocol: &protocol, Public: new(true), Ephemeral: new(false),
		Target: plan.Target, RequirePostQuantum: flags.RequirePostQuantum, Http: &controlv1.ProjectServiceHTTP{}}
	if err := flags.Limits.Validate(); err != nil {
		return declaration, err
	}
	if plan.Trust != nil {
		captured, err := plan.Trust.Declaration()
		if err != nil {
			return declaration, err
		}
		declaration.TargetTls = &controlv1.ProjectTargetTLS{Hostname: captured.Hostname, Digest: captured.Digest}
		if len(captured.CAPEM) != 0 {
			declaration.TargetTls.CaPem = new(string(captured.CAPEM))
		}
	}
	if policy.explicit {
		prefixes := slices.Clone(policy.prefixes)
		slices.Sort(prefixes)
		declaration.Http.Access = &controlv1.ProjectHTTPAccess{Mode: &policy.access, Ip: &prefixes}
	}
	limits := flags.Limits
	if limits.Requests > 0 || limits.Concurrency > 0 || limits.RateRequests > 0 {
		declaration.Http.Limits = &controlv1.ProjectHTTPApplicationLimits{}
		if limits.Requests > 0 {
			declaration.Http.Limits.Total = &limits.Requests
		}
		if limits.Concurrency > 0 {
			declaration.Http.Limits.Concurrency = &limits.Concurrency
		}
		if limits.RateRequests > 0 {
			declaration.Http.Limits.Rate = &controlv1.ProjectApplicationRate{Count: limits.RateRequests, Per: limits.RatePer.String()}
			if limits.RateBurst > 0 {
				declaration.Http.Limits.Rate.Burst = &limits.RateBurst
			}
		}
	}
	if flags.ReadinessPath != "" {
		declaration.Http.Readiness = &struct {
			Path string `json:"path"`
		}{Path: flags.ReadinessPath}
	}
	var err error
	declaration.Traffic, err = clientcontrol.TrafficSelection(flags.Traffic)
	return declaration, err
}

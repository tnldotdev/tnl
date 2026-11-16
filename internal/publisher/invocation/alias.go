package invocation

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/tnldotdev/tnl/internal/client/auth"
	clientproject "github.com/tnldotdev/tnl/internal/client/project"
	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	"github.com/tnldotdev/tnl/internal/clioutput"
	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/failure/diagnostic"
	"github.com/tnldotdev/tnl/internal/naming"
	publisheridentity "github.com/tnldotdev/tnl/internal/publisher/identity"
	"github.com/tnldotdev/tnl/internal/publisher/integrations"
	publisherservice "github.com/tnldotdev/tnl/internal/publisher/service"
	authorityv1 "github.com/tnldotdev/tnl/pkg/api/control/authority/v1"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func prepareAliasServices(ctx context.Context, state *clientstate.Database, project projectConfiguration, name string, alias config.Alias, server, team string, authenticated *auth.Client) (publisherServices, error) {
	effective, err := project.EffectiveService(alias.Service)
	if err != nil {
		return publisherServices{}, err
	}
	domain := aliasDomainName(alias, effective)
	if domain == "" {
		domain = valueOrEmpty(project.Config.DeploymentSettings.Domain)
	}
	publicURL, relative := "", name
	if alias.Hostname != nil {
		publicURL, relative = "https://"+*alias.Hostname, ""
	}
	services, err := preparePublisherServices(ctx, state, server, publicURL, relative, domain, team, false, authenticated)
	if err != nil {
		return publisherServices{}, err
	}
	if alias.Hostname == nil {
		services.hostname = alias.RelativeName(name) + "." + services.namespace
		canonical, err := naming.CanonicalizeHostname(services.hostname)
		if err != nil || canonical != services.hostname {
			return publisherServices{}, failure.Wrap("resolve alias hostname", failure.ProjectConfigInvalid, errors.New("alias hostname exceeds DNS bounds"))
		}
	}
	return services, nil
}

func aliasDomainName(alias config.Alias, effective clientproject.ResolvedService) string {
	if alias.Domain != nil {
		return *alias.Domain
	}
	if effective.Domain != nil {
		return *effective.Domain
	}
	return ""
}

func checkAliasHostnamePolicy(services publisherServices) error {
	return CheckAliasHostnamePolicy(AliasHostnamePolicy{Hostname: services.hostname, Namespace: services.namespace, DomainKind: services.domainKind, MemberNamespace: services.memberNamespace, MaxMemberChildLabels: services.authenticated.Discovery.ManagedDomainMaxMemberChildLabels, CustomDomainAvailable: services.customDomainAvailable})
}

type AliasHostnamePolicy struct {
	Hostname              string
	Namespace             string
	DomainKind            authorityv1.DomainKind
	MemberNamespace       bool
	MaxMemberChildLabels  int
	CustomDomainAvailable bool
}

func CheckAliasHostnamePolicy(policy AliasHostnamePolicy) error {
	limit := policy.MaxMemberChildLabels
	if limit < 0 {
		return failure.Wrap("read alias hostname policy", failure.ServerResponseInvalid, errors.New("negative member hostname depth limit"))
	}
	depth, member := naming.ChildDepth(policy.Hostname, policy.Namespace)
	if !member || !policy.MemberNamespace || policy.DomainKind != authorityv1.Managed || limit == 0 || depth <= limit {
		return nil
	}
	name := strings.TrimSuffix(policy.Hostname, "."+policy.Namespace)
	message := fmt.Sprintf("%s needs %d labels beneath your namespace, but this server allows %d on its managed domain. use a one-label alias name", name, depth, limit)
	if policy.CustomDomainAvailable {
		message += ", or publish the alias on a custom domain your team has added"
	}
	return diagnostic.WrapMessage(diagnostic.MemberHostnameDepthExceeded, message+".", errors.New("alias hostname depth rejected"))
}

func aliasScope(project projectConfiguration, name string, services publisherServices) clientstate.AliasScope {
	return clientstate.AliasScope{Server: services.authenticated.ServerEndpoint,
		ProjectKey: clientproject.SharedProjectIdentity(project.Worktree, project.Root), TeamID: services.teamID,
		MembershipID: services.membershipID, Namespace: services.namespace, Name: name}
}

func registerProjectAlias(ctx context.Context, state *clientstate.Database, project projectConfiguration, name string, definition config.Alias, services publisherServices, tunnelID string, group clientstate.IntegrationScope) (clientstate.AliasSelection, error) {
	_, fingerprint, err := definition.DefinitionBytes(name)
	if err != nil {
		return clientstate.AliasSelection{}, err
	}
	return state.RegisterAlias(ctx, clientstate.AliasRegistration{Scope: aliasScope(project, name, services), Hostname: services.hostname,
		Service: definition.Service, TunnelID: tunnelID, IntegrationScope: group, Fingerprint: fingerprint})
}

type AliasChoice struct {
	Project       clientproject.Project
	Name          string
	Server        string
	Team          string
	Use           bool
	Force         bool
	Authenticated *auth.Client
}

func ChooseAlias(ctx context.Context, state *clientstate.Database, flags AliasChoice) (clientstate.AliasSelection, error) {
	project := projectConfiguration{Project: flags.Project}
	use, force, server, team, authenticated := flags.Use, flags.Force, flags.Server, flags.Team, flags.Authenticated
	if !project.Found() {
		return clientstate.AliasSelection{}, failure.Wrap("select alias", failure.ProjectConfigMissing, errors.New("project configuration with an alias is required"))
	}
	definition, found := project.Config.Aliases[flags.Name]
	if !found {
		return clientstate.AliasSelection{}, failure.Wrap("select alias", failure.ProjectConfigInvalid, errors.New("select an alias declared in this project's configuration"))
	}
	services, err := prepareAliasServices(ctx, state, project, flags.Name, definition, server, team, authenticated)
	if err != nil {
		return clientstate.AliasSelection{}, err
	}
	// validate the chosen server/domain before any local declaration or selection
	// write. a rejected nested name must not disturb the current owner.
	if use {
		if err := checkAliasHostnamePolicy(services); err != nil {
			return clientstate.AliasSelection{}, err
		}
	}
	scope := aliasScope(project, flags.Name, services)
	if use {
		snapshot, err := state.SnapshotProject(ctx, project.Root)
		if err != nil {
			return clientstate.AliasSelection{}, err
		}
		var receiver *clientstate.TunnelInfo
		for i := range snapshot.Tunnels {
			tunnel := &snapshot.Tunnels[i]
			if tunnel.Server == server && tunnel.Service == definition.Service && tunnel.State == clientstate.TunnelStateReady && !tunnel.IntegrationScope.IsZero() {
				if receiver != nil {
					return clientstate.AliasSelection{}, failure.Wrap("select alias service", failure.InvalidTunnelFlags, errors.New("more than one entry-service tunnel is running in this worktree"))
				}
				receiver = tunnel
			}
		}
		if receiver == nil {
			return clientstate.AliasSelection{}, failure.Wrap("select alias service", failure.AliasReceiverUnready, clientstate.ErrAliasReceiverUnavailable)
		}
		if _, err := registerProjectAlias(ctx, state, project, flags.Name, definition, services, receiver.ID, receiver.IntegrationScope); err != nil {
			return clientstate.AliasSelection{}, aliasChoiceError(err)
		}
	}
	var selected clientstate.AliasSelection
	if use {
		selected, err = state.SelectAlias(ctx, scope, project.Root, force)
	} else {
		selected, err = state.ReleaseAlias(ctx, scope, project.Root)
	}
	if err != nil {
		return clientstate.AliasSelection{}, aliasChoiceError(err)
	}
	return selected, nil
}

func aliasChoiceError(err error) error {
	reason := failure.ClientStateUnavailable
	switch {
	case errors.Is(err, clientstate.ErrAliasOwned):
		reason = failure.AliasOwned
	case errors.Is(err, clientstate.ErrAliasNotSelected), errors.Is(err, clientstate.ErrAliasSelectionStale):
		reason = failure.AliasNotSelected
	case errors.Is(err, clientstate.ErrAliasReceiverUnavailable), errors.Is(err, clientstate.ErrAliasNotFound):
		reason = failure.AliasReceiverUnready
	case errors.Is(err, clientstate.ErrAliasPolicyConflict):
		reason = failure.AliasPolicyConflict
	}
	return failure.Wrap("update alias selection", reason, err)
}

func startProjectAliases(ctx context.Context, state *clientstate.Database, project projectConfiguration, service, team string, parent publisherServices, base publisherservice.RunConfig, group clientstate.IntegrationScope, tunnel *clientstate.Tunnel, output *Presentation) func() {
	ctx, cancel := context.WithCancel(ctx)
	var workers sync.WaitGroup
	for _, name := range slices.Sorted(maps.Keys(project.Config.Aliases)) {
		definition := project.Config.Aliases[name]
		if definition.Service != service {
			continue
		}
		services, err := prepareAliasServices(ctx, state, project, name, definition, parent.authenticated.ServerEndpoint, team, parent.authenticated)
		if err != nil {
			reportIntegrationURL(tunnel, output, "alias unavailable", "app tunnel continues", clioutput.Text("alias "+name+" could not resolve its domain"))
			continue
		}
		if services.hostname == parent.hostname {
			reportIntegrationURL(tunnel, output, "alias name conflict", "choose a distinct alias name", clioutput.Text("alias "+name+" uses the entry service's hostname"))
			continue
		}
		selection, err := registerProjectAlias(ctx, state, project, name, definition, services, tunnel.ID(), group)
		if err != nil {
			reportIntegrationURL(tunnel, output, "alias unavailable", "app tunnel continues", clioutput.Text(failureMessage(aliasChoiceError(err))))
			continue
		}
		if err := checkAliasHostnamePolicy(services); err != nil {
			if selection.Project == project.Root {
				_ = state.RecordAliasFailure(ctx, selection, failure.MemberHostnameDepthExceeded)
				reportIntegrationURL(tunnel, output, "alias name rejected", "app tunnel continues", clioutput.Text("alias "+name+": "+err.Error()))
			}
			continue
		}
		policy := resolvedVisitorAccess{access: controlv1.Restricted}
		if definition.Access != nil {
			policy, err = resolveVisitorAccess(ctx, services.authenticated.Control, definition.Access, false, nil)
			if err != nil {
				_ = state.RecordAliasFailure(ctx, selection, failure.ServerUnavailable)
				continue
			}
		}
		var mu sync.Mutex
		lastReport := time.Time{}
		worker := projectAliasPublisher(state, services, selection, tunnel.ID(), base, policy, func(ready bool, err error) {
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				if time.Since(lastReport) < 30*time.Second {
					return
				}
				lastReport = time.Now()
				current, currentErr := state.AliasSelection(ctx, selection.Scope)
				if currentErr == nil && current.Project == project.Root {
					reason, typed := failure.ReasonOf(err)
					if !typed {
						reason = failure.IntegrationURLNotReady
					}
					_ = state.RecordAliasFailure(ctx, current, reason)
				}
				reportIntegrationURL(tunnel, output, "alias unavailable", "app tunnel continues; check tnl status", clioutput.Fields(clioutput.Field{Label: "alias", Value: name}))
			} else if ready {
				reportIntegrationURL(tunnel, output, "alias ready", "", clioutput.Fields(clioutput.Field{Label: "alias", Value: name}, clioutput.Field{Label: "public URL", Value: "https://" + services.hostname}))
			}
		})
		workers.Go(func() { worker.Maintain(ctx) })
	}
	return func() { cancel(); workers.Wait() }
}

func projectAliasPublisher(state *clientstate.Database, services publisherServices, selection clientstate.AliasSelection, tunnelID string, base publisherservice.RunConfig, policy resolvedVisitorAccess, report func(bool, error)) integrations.Publisher {
	return integrations.AliasPublisher(state, services.state, selection, tunnelID, func(ctx context.Context) (integrations.Snapshot, error) {
		access, err := base.Access(ctx)
		if err != nil {
			return integrations.Snapshot{}, err
		}
		parent, err := base.Control.GetPublisherService(ctx, base.ServiceID, access)
		if err != nil {
			return integrations.Snapshot{}, err
		}
		accessPolicy := &controlv1.ProjectHTTPAccess{Mode: &policy.access}
		if len(policy.prefixes) != 0 {
			prefixes := slices.Clone(policy.prefixes)
			accessPolicy.Ip = &prefixes
		}
		declaration := controlv1.ProjectServiceConfiguration{Target: "app", RequirePostQuantum: new(parent.RequirePostQuantum),
			Http: &controlv1.ProjectServiceHTTP{Access: accessPolicy, Limits: parent.HttpLimits}}
		trust, err := publisheridentity.ServiceTrust(parent)
		if err != nil {
			return integrations.Snapshot{}, err
		}
		declaration.TargetTls, err = foregroundTargetTLS(trust)
		if err != nil {
			return integrations.Snapshot{}, err
		}
		// election and receiver selection precede all remote setup. each alias
		// obtains its own exact service grant; the app's grant is never broadened.
		native, saved, err := selectNativeProjectPublisher(ctx, services, declaration)
		if err != nil {
			return integrations.Snapshot{}, err
		}
		cfg := publisherservice.RunConfig{Telemetry: base.Telemetry, Control: native, State: services.state, Access: native.Access,
			PublisherIdentityID: native.PublisherIdentityID(), PublisherGrantID: native.PublisherGrantID(), PublisherKeyID: native.PublisherKeyID(),
			ServiceID: saved.Id, Metadata: publisheridentity.ServiceMetadata(saved), Target: base.Target, Handler: base.Handler,
			InspectionMode: base.InspectionMode, PreferredRegions: slices.Clone(base.PreferredRegions),
			Mounts: slices.Clone(base.Mounts), ResolveHTTPTarget: base.ResolveHTTPTarget, TargetResolver: base.TargetResolver,
			HTTPResponseHooks: base.HTTPResponseHooks, AdmitRequest: base.AdmitRequest, TransportTLS: base.TransportTLS}
		return integrations.Snapshot{Config: cfg, Service: saved}, nil
	}, report)
}

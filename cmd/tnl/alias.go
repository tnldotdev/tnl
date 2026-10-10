package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/tnldotdev/tnl/internal/clientauth"
	"github.com/tnldotdev/tnl/internal/clientstate"
	"github.com/tnldotdev/tnl/internal/clioutput"
	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/diagnostic"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/integrationurls"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/projectconfig"
	"github.com/tnldotdev/tnl/internal/publisher"
	"github.com/tnldotdev/tnl/pkg/api/authorityv1"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

func prepareAliasServices(ctx context.Context, state *clientstate.Database, project projectConfiguration, name string, alias config.Alias, server, team string, authenticated *clientauth.Client) (publisherServices, error) {
	effective, err := project.EffectiveService(alias.Service)
	if err != nil {
		return publisherServices{}, err
	}
	domain := aliasDomainName(alias, effective)
	publicURL, relative := "", name
	if alias.PublicURL != nil {
		publicURL, relative = *alias.PublicURL, ""
	}
	services, err := preparePublisherServices(ctx, state, server, publicURL, relative, domain, team, false, authenticated)
	if err != nil {
		return publisherServices{}, err
	}
	if alias.PublicURL == nil {
		services.hostname = alias.RelativeName(name) + "." + services.namespace
		canonical, err := naming.CanonicalizeHostname(services.hostname)
		if err != nil || canonical != services.hostname {
			return publisherServices{}, failure.Wrap("resolve alias hostname", failure.ProjectConfigInvalid, errors.New("alias hostname exceeds DNS bounds"))
		}
	}
	return services, nil
}

func aliasDomainName(alias config.Alias, effective config.TNL) string {
	if alias.Domain != nil {
		return *alias.Domain
	}
	if effective.Tunnel != nil && effective.Tunnel.Domain != nil {
		return *effective.Tunnel.Domain
	}
	return ""
}

func checkAliasHostnamePolicy(services publisherServices) error {
	limit := services.authenticated.Discovery.ManagedDomainMaxMemberChildLabels
	if limit < 0 {
		return failure.Wrap("read alias hostname policy", failure.ServerResponseInvalid, errors.New("negative member hostname depth limit"))
	}
	depth, member := naming.ChildDepth(services.hostname, services.namespace)
	if !member || services.publicURLScope != controlv1.Member || services.domainKind != authorityv1.Managed || limit == 0 || depth <= limit {
		return nil
	}
	name := strings.TrimSuffix(services.hostname, "."+services.namespace)
	message := fmt.Sprintf("%s needs %d labels beneath your namespace, but this server allows %d on its managed domain. use a one-label alias name", name, depth, limit)
	if services.customDomainAvailable {
		message += ", or publish the alias on a custom domain your team has added"
	}
	return diagnostic.WrapMessage(diagnostic.MemberHostnameDepthExceeded, message+".", errors.New("alias hostname depth rejected"))
}

func aliasScope(project projectConfiguration, name string, services publisherServices) clientstate.AliasScope {
	return clientstate.AliasScope{Server: services.authenticated.ServerEndpoint,
		ProjectKey: projectconfig.SharedProjectIdentity(project.Worktree, project.Root), TeamID: services.teamID,
		MembershipID: services.membershipID, Namespace: services.namespace, Name: name}
}

func registerProjectAlias(ctx context.Context, state *clientstate.Database, project projectConfiguration, name string, definition config.Alias, services publisherServices, tunnelID, group string) (clientstate.AliasSelection, error) {
	_, fingerprint, err := definition.DefinitionBytes(name)
	if err != nil {
		return clientstate.AliasSelection{}, err
	}
	return state.RegisterAlias(ctx, clientstate.AliasRegistration{Scope: aliasScope(project, name, services), Hostname: services.hostname,
		Service: definition.Service, TunnelID: tunnelID, IntegrationGroup: group, Fingerprint: fingerprint})
}

func runAliasChoice(ctx context.Context, flags aliasChoiceCommand, project projectConfiguration, use, force bool, stdout, stderr io.Writer) error {
	if !project.Found() {
		return failure.Wrap("select alias", failure.ProjectConfigMissing, errors.New("project configuration with an alias is required"))
	}
	definition, found := project.Config.Aliases[flags.Name]
	if !found {
		return failure.Wrap("select alias", failure.ProjectConfigInvalid, errors.New("select an alias declared in this project's configuration"))
	}
	server, state, err := resolveServer(ctx, flags.StateDir, flags.ServerURL)
	if err != nil {
		return err
	}
	defer state.Close()
	authenticated, err := authenticatePublisher(ctx, state, server, flags.AccessToken, "tnl alias", os.Stdin, stderr)
	if err != nil {
		return err
	}
	team := flags.Team
	if team == "" {
		team = flags.ProjectTeam
	}
	services, err := prepareAliasServices(ctx, state, project, flags.Name, definition, server, team, authenticated)
	if err != nil {
		return err
	}
	// validate the chosen server/domain before any local declaration or selection
	// write. a rejected nested name must not disturb the current owner.
	if use {
		if err := checkAliasHostnamePolicy(services); err != nil {
			return err
		}
	}
	scope := aliasScope(project, flags.Name, services)
	if use {
		snapshot, err := state.SnapshotProject(ctx, project.Root)
		if err != nil {
			return err
		}
		var receiver *clientstate.TunnelInfo
		for i := range snapshot.Tunnels {
			tunnel := &snapshot.Tunnels[i]
			if tunnel.Server == server && tunnel.Service == definition.Service && tunnel.State == clientstate.TunnelStateReady && tunnel.IntegrationGroup != "" {
				if receiver != nil {
					return failure.Wrap("select alias service", failure.InvalidTunnelFlags, errors.New("more than one entry-service tunnel is running in this worktree"))
				}
				receiver = tunnel
			}
		}
		if receiver == nil {
			return failure.Wrap("select alias service", failure.AliasReceiverUnready, clientstate.ErrAliasReceiverUnavailable)
		}
		if _, err := registerProjectAlias(ctx, state, project, flags.Name, definition, services, receiver.ID, receiver.IntegrationGroup); err != nil {
			return aliasChoiceError(err)
		}
	}
	var selected clientstate.AliasSelection
	command, status := "tnl alias use", "selected"
	if use {
		selected, err = state.SelectAlias(ctx, scope, project.Root, force)
	} else {
		command, status = "tnl alias release", "default restored"
		selected, err = state.ReleaseAlias(ctx, scope, project.Root)
	}
	if err != nil {
		return aliasChoiceError(err)
	}
	return writeHumanFrame(stdout, command, status, "tnl status shows alias readiness", clioutput.Fields(
		clioutput.Field{Label: "alias", Value: flags.Name}, clioutput.Field{Label: "public URL", Value: "https://" + selected.Hostname},
		clioutput.Field{Label: "selected worktree", Value: selected.Project},
	))
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

func startProjectAliases(ctx context.Context, state *clientstate.Database, project projectConfiguration, service, team string, parent publisherServices, base publisher.Config, group string, tunnel *clientstate.Tunnel, output *publishOutput) func() {
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
		if services.hostname == base.Hostname {
			reportIntegrationURL(tunnel, output, "alias name conflict", "choose a distinct alias name", clioutput.Text("alias "+name+" uses the entry service's hostname"))
			continue
		}
		selection, err := registerProjectAlias(ctx, state, project, name, definition, services, tunnel.ID(), group)
		if err != nil {
			reportIntegrationURL(tunnel, output, "alias unavailable", "app tunnel continues", clioutput.Text(presentFailure(aliasChoiceError(err)).message))
			continue
		}
		if err := checkAliasHostnamePolicy(services); err != nil {
			if selection.Project == project.Root {
				_ = state.RecordAliasFailure(ctx, selection, failure.MemberHostnameDepthExceeded)
				reportIntegrationURL(tunnel, output, "alias name rejected", "app tunnel continues", clioutput.Text("alias "+name+": "+err.Error()))
			}
			continue
		}
		prefixes := base.AllowedIPPrefixes
		if definition.AllowIP != nil || definition.AllowAllIPs != nil {
			policy, err := resolveIPPolicy(ctx, services.authenticated.Control, definition.AllowIP, definition.AllowAllIPs != nil && *definition.AllowAllIPs)
			if err != nil {
				_ = state.RecordAliasFailure(ctx, selection, failure.ServerUnavailable)
				continue
			}
			prefixes = policy.prefixes
		}
		config := services.config(base.Target, slices.Clone(prefixes), base.Limits)
		config.Purpose = controlv1.Alias
		config.Mounts, config.ObserveResponse = base.Mounts, base.ObserveResponse
		config.AdmitRequest = base.AdmitRequest
		var mu sync.Mutex
		lastReport := time.Time{}
		worker := integrationurls.AliasPublisher(state, services.state, selection, tunnel.ID(), config, func(event publisher.Event, err error) {
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
			} else if event.Type == publisher.EventReady {
				reportIntegrationURL(tunnel, output, "alias ready", "", clioutput.Fields(clioutput.Field{Label: "alias", Value: name}, clioutput.Field{Label: "public URL", Value: event.PublicURL}))
			}
		})
		workers.Go(func() { worker.Maintain(ctx) })
	}
	return func() { cancel(); workers.Wait() }
}

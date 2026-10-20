package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"

	"github.com/tnldotdev/tnl/internal/clientauth"
	"github.com/tnldotdev/tnl/internal/clientstate"
	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/projectconfig"
	"github.com/tnldotdev/tnl/internal/projectmeta"
	"github.com/tnldotdev/tnl/pkg/api/authorityv1"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

type projectMetadataResolver struct {
	state       *clientstate.Database
	input       io.Reader
	diagnostics io.Writer
	command     string
	project     projectConfiguration

	savedServerLoaded bool
	savedServer       string
	clients           map[string]*clientauth.Client
	identities        map[string]authorityv1.IdentityContext
	contexts          map[string]teamContext
	silent            bool
}

func newProjectMetadataResolver(
	state *clientstate.Database,
	project projectConfiguration,
	input io.Reader,
	diagnostics io.Writer,
	command string,
) *projectMetadataResolver {
	return &projectMetadataResolver{
		state: state, project: project, input: input, diagnostics: diagnostics, command: command,
		clients: make(map[string]*clientauth.Client), identities: make(map[string]authorityv1.IdentityContext),
		contexts: make(map[string]teamContext),
	}
}

func (r *projectMetadataResolver) Seed(server string, client *clientauth.Client) {
	if client != nil {
		r.clients[server] = client
	}
}

func (r *projectMetadataResolver) LoadFallbackServer(ctx context.Context) error {
	_, err := r.server(ctx, nil)
	return err
}

func (r *projectMetadataResolver) Generate(ctx context.Context) (projectmeta.Metadata, error) {
	hasPublic := r.project.Config.OAuth || len(r.project.Config.Webhooks) != 0 || len(r.project.Config.Aliases) != 0
	for _, service := range r.project.Config.Services {
		hasPublic = hasPublic || config.IsPublicService(service) || config.PublisherName(service) != "local"
	}
	if !hasPublic {
		metadata := projectmeta.Metadata{Version: projectmeta.Version, Services: map[string]projectmeta.Service{}}
		if r.project.Worktree.Label.FullLabel != "" {
			metadata.Worktree = &projectmeta.Worktree{Label: r.project.Worktree.Label}
		}
		return metadata, metadata.Validate()
	}
	root, err := r.project.EffectiveService("")
	if err != nil {
		return projectmeta.Metadata{}, err
	}
	_, current, err := r.resolveContext(ctx, root)
	if err != nil {
		return projectmeta.Metadata{}, err
	}
	selectedDomain := ""
	if root.Tunnel != nil && root.Tunnel.Domain != nil {
		selectedDomain = *root.Tunnel.Domain
	}
	domain, err := readyDomain(current, selectedDomain)
	if err != nil {
		return projectmeta.Metadata{}, err
	}
	metadata := projectmeta.Metadata{
		Version: projectmeta.Version, Namespace: namespaceForMembership(current, domain),
		Services: make(map[string]projectmeta.Service, len(r.project.Config.Services)),
	}
	if r.project.Worktree.Label.FullLabel != "" {
		metadata.Worktree = &projectmeta.Worktree{Label: r.project.Worktree.Label}
	}
	server, err := r.server(ctx, root.Server)
	if err != nil {
		return projectmeta.Metadata{}, err
	}
	if r.project.Config.OAuth {
		oauth, err := projectIntegrationOrigin(ctx, r.state, r.project.Project, server, metadata.Namespace, "oauth")
		if err != nil {
			return projectmeta.Metadata{}, err
		}
		metadata.OAuth = &oauth
	}
	names := make([]string, 0, len(r.project.Config.Services))
	for name := range r.project.Config.Services {
		if !config.IsPublicService(r.project.Config.Services[name]) && config.PublisherName(r.project.Config.Services[name]) == "local" {
			continue
		}
		names = append(names, name)
	}
	slices.Sort(names)
	for _, name := range names {
		effective, err := r.project.EffectiveService(name)
		if err != nil {
			return projectmeta.Metadata{}, err
		}
		_, serviceContext, err := r.resolveContext(ctx, effective)
		if err != nil {
			return projectmeta.Metadata{}, fmt.Errorf("service %q: %w", name, err)
		}
		var serviceMetadata projectmeta.Service
		if config.PublisherName(r.project.Config.Services[name]) != "local" {
			serviceServer, serverErr := r.server(ctx, effective.Server)
			if serverErr != nil {
				return projectmeta.Metadata{}, serverErr
			}
			source, sourceErr := r.project.SourceIdentity(ctx)
			if sourceErr != nil {
				return projectmeta.Metadata{}, sourceErr
			}
			client, clientErr := r.client(ctx, serviceServer)
			if clientErr != nil {
				return projectmeta.Metadata{}, clientErr
			}
			// the source-bound visitor lookup provides the current endpoint and
			// exposure. never infer managed exposure from protocol or local config.
			assigned, lookupErr := client.Control.GetProjectPrivateService(ctx, source.Key, name, controlv1.GetProjectPrivateServiceParams{TeamId: serviceContext.team.Id, SourceFingerprint: source.Fingerprint})
			if lookupErr != nil {
				return projectmeta.Metadata{}, fmt.Errorf("read applied remote service %q: %w", name, lookupErr)
			}
			if assigned.TeamId != serviceContext.team.Id || assigned.Id == "" || string(assigned.Name) != config.ServiceName(name, r.project.Config.Services[name]) || assigned.ManagedTls == nil || !assigned.Enabled || string(assigned.Protocol) != config.Protocol(r.project.Config.Services[name]) {
				return projectmeta.Metadata{}, fmt.Errorf("remote service %q has no matching current endpoint; run tnl apply", name)
			}
			endpoint := assigned.ManagedTls
			domain, domainErr := readyDomainForHostname(serviceContext.domains, endpoint.Hostname)
			if domainErr != nil {
				return projectmeta.Metadata{}, domainErr
			}
			serviceMetadata, err = projectmeta.NewEndpoint(domain.CanonicalDomain, endpoint.Hostname, string(assigned.Protocol), endpoint.Port, endpoint.Public)
		} else {
			serviceMetadata, err = configuredProjectService(name, r.project.Worktree, effective, serviceContext)
		}
		if err != nil {
			return projectmeta.Metadata{}, fmt.Errorf("service %q: %w", name, err)
		}
		if paths := config.ServicePaths(r.project.Config.Services[name]); len(paths) > 0 {
			serviceMetadata.Paths = make(map[string]projectmeta.Path, len(paths))
			for prefix, mount := range paths {
				serviceMetadata.Paths[prefix] = projectmeta.Path{
					Service: mount.Service, URL: serviceMetadata.URL + prefix, StripPrefix: mount.StripPrefix,
				}
			}
		}
		metadata.Services[name] = serviceMetadata
	}
	metadata.Webhooks, err = projectWebhookMetadata(ctx, r.state, r.project.Project, server, metadata)
	if err != nil {
		return projectmeta.Metadata{}, err
	}
	metadata.Aliases, err = projectAliasMetadata(ctx, r, metadata)
	if err != nil {
		return projectmeta.Metadata{}, err
	}
	if err := metadata.Validate(); err != nil {
		return projectmeta.Metadata{}, err
	}
	return metadata, nil
}

func projectAliasMetadata(ctx context.Context, resolver *projectMetadataResolver, metadata projectmeta.Metadata) (map[string]projectmeta.Alias, error) {
	aliases := make(map[string]projectmeta.Alias)
	for name, definition := range resolver.project.Config.Aliases {
		if _, included := metadata.Services[definition.Service]; !included {
			continue
		}
		effective, err := resolver.project.EffectiveService(definition.Service)
		if err != nil {
			return nil, err
		}
		_, current, err := resolver.resolveContext(ctx, effective)
		if err != nil {
			return nil, err
		}
		domainName := aliasDomainName(definition, effective)
		publicURL := ""
		if definition.PublicURL != nil {
			publicURL = *definition.PublicURL
		}
		nameFlag := name
		if publicURL != "" {
			nameFlag = ""
		}
		hostname, domain, _, err := resolvePublishHostname(publicURL, nameFlag, domainName, current)
		if err != nil {
			return nil, err
		}
		if definition.PublicURL == nil {
			hostname = definition.RelativeName(name) + "." + namespaceForMembership(current, domain)
		}
		aliases[name] = projectmeta.Alias{Hostname: hostname, URL: "https://" + hostname, Service: definition.Service}
	}
	return aliases, nil
}

func projectWebhookMetadata(ctx context.Context, state *clientstate.Database, project projectconfig.Project, server string, metadata projectmeta.Metadata) (map[string]projectmeta.Webhook, error) {
	result := map[string]projectmeta.Webhook{}
	for name, definition := range project.Config.Webhooks {
		namespace := metadata.Namespace
		if definition.Service != "" {
			service, found := metadata.Services[definition.Service]
			if !found {
				continue
			}
			namespace = service.Namespace
		}
		origin, err := projectIntegrationOrigin(ctx, state, project, server, namespace, "hooks")
		if err != nil {
			return nil, err
		}
		methods := slices.Clone(definition.Methods)
		if len(methods) == 0 {
			methods = []string{"POST"}
		}
		result[name] = projectmeta.Webhook{Hostname: origin.Hostname, URL: origin.URL + definition.Path, Service: definition.Service, Path: definition.Path, Methods: methods}
	}
	return result, nil
}

func configuredProjectService(
	service string,
	worktree projectconfig.Worktree,
	effective config.TNL,
	current teamContext,
) (projectmeta.Service, error) {
	publicURL, name, selectedDomain := "", "", ""
	ephemeral := false
	if effective.Tunnel != nil {
		if effective.Tunnel.PublicURL != nil {
			publicURL = *effective.Tunnel.PublicURL
		}
		if effective.Tunnel.Name != nil {
			name = *effective.Tunnel.Name
		}
		if effective.Tunnel.Domain != nil {
			selectedDomain = *effective.Tunnel.Domain
		}
		ephemeral = effective.Tunnel.Ephemeral != nil && *effective.Tunnel.Ephemeral
	}
	if publicURL == "" && name == "" && !ephemeral {
		name = projectconfig.ServiceWorktreeLabel(service, worktree)
	}
	hostname, domain, _, err := resolvePublishHostname(publicURL, name, selectedDomain, current)
	if err != nil {
		return projectmeta.Service{}, err
	}
	protocol := config.ServiceProtocol(effective.Publish)
	return projectmeta.NewService(namespaceForMembership(current, domain), hostname, protocol, nil)
}

func (r *projectMetadataResolver) resolveContext(
	ctx context.Context,
	effective config.TNL,
) (*clientauth.Client, teamContext, error) {
	server, err := r.server(ctx, effective.Server)
	if err != nil {
		return nil, teamContext{}, err
	}
	client, err := r.client(ctx, server)
	if err != nil {
		return nil, teamContext{}, err
	}
	team := ""
	if effective.Team != nil {
		team = *effective.Team
	}
	key := server + "\x00" + team
	if current, found := r.contexts[key]; found {
		return client, current, nil
	}
	identity, found := r.identities[server]
	if !found {
		identity, err = client.Authority.IdentityContext(ctx)
		if err != nil {
			return nil, teamContext{}, err
		}
		r.identities[server] = identity
	}
	store, err := r.state.Server(ctx, server)
	if err != nil {
		return nil, teamContext{}, err
	}
	session := teamSession{
		store: store, authenticated: client, api: client.Authority,
		identity: identity, projectTeam: team,
	}
	current, err := session.currentWithDomains(ctx)
	if err != nil {
		return nil, teamContext{}, err
	}
	r.contexts[key] = current
	return client, current, nil
}

func (r *projectMetadataResolver) server(ctx context.Context, configured *string) (string, error) {
	if configured != nil {
		return clientstate.CanonicalServer(*configured)
	}
	if !r.savedServerLoaded {
		server, found, err := r.state.SavedServer(ctx)
		if err != nil {
			return "", err
		}
		if !found {
			server = defaultServerURL
		}
		r.savedServer, r.savedServerLoaded = server, true
	}
	return r.savedServer, nil
}

func (r *projectMetadataResolver) client(ctx context.Context, server string) (*clientauth.Client, error) {
	if client, found := r.clients[server]; found {
		return client, nil
	}
	diagnostics := r.diagnostics
	if diagnostics == nil {
		diagnostics = io.Discard
	}
	input := r.input
	if input == nil {
		input = os.Stdin
	}
	var client *clientauth.Client
	var err error
	if r.silent {
		client, err = authenticateRuntime(ctx, r.state, server)
	} else {
		client, err = authenticatePublisher(ctx, r.state, server, "", r.command, input, diagnostics)
	}
	if err != nil {
		return nil, err
	}
	if client.ServerEndpoint != server {
		return nil, errors.New("authenticated server does not match project configuration")
	}
	r.clients[server] = client
	return client, nil
}

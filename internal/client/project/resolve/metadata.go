package resolve

import (
	"context"
	"errors"
	"fmt"
	"os"
	"slices"

	clientauth "github.com/tnldotdev/tnl/internal/client/auth"
	controlclient "github.com/tnldotdev/tnl/internal/client/control"
	projectconfig "github.com/tnldotdev/tnl/internal/client/project"
	projectmeta "github.com/tnldotdev/tnl/internal/client/project/meta"
	clientserver "github.com/tnldotdev/tnl/internal/client/server"
	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	"github.com/tnldotdev/tnl/internal/client/team"
	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/pkg/api/authorityv1"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

type MetadataResolver struct {
	state   *clientstate.Database
	project projectconfig.Project

	savedServerLoaded bool
	savedServer       string
	clients           map[string]*clientauth.Client
	identities        map[string]authorityv1.IdentityContext
	contexts          map[string]team.Context
	authenticate      func(context.Context, *clientstate.Database, string) (*clientauth.Client, error)
}

// NewMetadataResolver borrows state; the caller retains its lifetime. authenticate
// supplies command UI when needed; nil uses noninteractive runtime authentication.
func NewMetadataResolver(state *clientstate.Database, project projectconfig.Project, authenticate func(context.Context, *clientstate.Database, string) (*clientauth.Client, error)) *MetadataResolver {
	return &MetadataResolver{
		state: state, project: project, authenticate: authenticate,
		clients: make(map[string]*clientauth.Client), identities: make(map[string]authorityv1.IdentityContext),
		contexts: make(map[string]team.Context),
	}
}

func (r *MetadataResolver) Seed(server string, client *clientauth.Client) {
	if client != nil {
		r.clients[server] = client
	}
}

func (r *MetadataResolver) Generate(ctx context.Context) (projectmeta.Metadata, error) {
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
	_, current, err := r.Context(ctx, root)
	if err != nil {
		return projectmeta.Metadata{}, err
	}
	selectedDomain := ""
	if root.Tunnel != nil && root.Tunnel.Domain != nil {
		selectedDomain = *root.Tunnel.Domain
	}
	domain, err := current.ReadyDomain(selectedDomain)
	if err != nil {
		return projectmeta.Metadata{}, err
	}
	namespace, _ := current.Namespace(domain)
	metadata := projectmeta.Metadata{
		Version: projectmeta.Version, Namespace: namespace,
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
		oauth, err := IntegrationOrigin(ctx, r.state, r.project, server, metadata.Namespace, "oauth")
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
		_, serviceContext, err := r.Context(ctx, effective)
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
			assigned, lookupErr := client.Control.GetProjectPrivateService(ctx, source.Key, name, controlv1.GetProjectPrivateServiceParams{TeamId: serviceContext.Team().Id, SourceFingerprint: source.Fingerprint})
			if errors.Is(lookupErr, controlclient.ErrNotFound) {
				// local startup does not apply remote services. include their
				// endpoints only after control has a current visitor projection.
				continue
			}
			if lookupErr != nil {
				return projectmeta.Metadata{}, fmt.Errorf("read applied remote service %q: %w", name, lookupErr)
			}
			if assigned.TeamId != serviceContext.Team().Id || assigned.Id == "" || string(assigned.Name) != config.ServiceName(name, r.project.Config.Services[name]) || assigned.ManagedTls == nil || !assigned.Enabled || string(assigned.Protocol) != config.Protocol(r.project.Config.Services[name]) {
				return projectmeta.Metadata{}, fmt.Errorf("remote service %q has no matching current endpoint; run tnl apply", name)
			}
			endpoint := assigned.ManagedTls
			domain, domainErr := team.ReadyDomainForHostname(serviceContext.Domains(), endpoint.Hostname)
			if domainErr != nil {
				return projectmeta.Metadata{}, domainErr
			}
			serviceMetadata, err = projectmeta.NewEndpoint(domain.CanonicalDomain, endpoint.Hostname, string(assigned.Protocol), endpoint.Port, endpoint.Public)
		} else {
			serviceMetadata, err = ConfiguredService(name, r.project.Worktree, effective, serviceContext)
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
	metadata.Webhooks, err = projectWebhookMetadata(ctx, r.state, r.project, server, metadata)
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

func projectAliasMetadata(ctx context.Context, resolver *MetadataResolver, metadata projectmeta.Metadata) (map[string]projectmeta.Alias, error) {
	aliases := make(map[string]projectmeta.Alias)
	for name, definition := range resolver.project.Config.Aliases {
		if _, included := metadata.Services[definition.Service]; !included {
			continue
		}
		effective, err := resolver.project.EffectiveService(definition.Service)
		if err != nil {
			return nil, err
		}
		_, current, err := resolver.Context(ctx, effective)
		if err != nil {
			return nil, err
		}
		domainName := ""
		if definition.Domain != nil {
			domainName = *definition.Domain
		} else if effective.Tunnel != nil && effective.Tunnel.Domain != nil {
			domainName = *effective.Tunnel.Domain
		}
		publicURL := ""
		if definition.PublicURL != nil {
			publicURL = *definition.PublicURL
		}
		nameFlag := name
		if publicURL != "" {
			nameFlag = ""
		}
		hostname, domain, _, err := PublishHostname(publicURL, nameFlag, domainName, current)
		if err != nil {
			return nil, err
		}
		if definition.PublicURL == nil {
			namespace, _ := current.Namespace(domain)
			hostname = definition.RelativeName(name) + "." + namespace
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
		origin, err := IntegrationOrigin(ctx, state, project, server, namespace, "hooks")
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

func ConfiguredService(
	service string,
	worktree projectconfig.Worktree,
	effective config.TNL,
	current team.Context,
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
	hostname, domain, _, err := PublishHostname(publicURL, name, selectedDomain, current)
	if err != nil {
		return projectmeta.Service{}, err
	}
	protocol := config.ServiceProtocol(effective.Publish)
	namespace, _ := current.Namespace(domain)
	return projectmeta.NewService(namespace, hostname, protocol, nil)
}

func (r *MetadataResolver) Context(
	ctx context.Context,
	effective config.TNL,
) (*clientauth.Client, team.Context, error) {
	server, err := r.server(ctx, effective.Server)
	if err != nil {
		return nil, team.Context{}, err
	}
	client, err := r.client(ctx, server)
	if err != nil {
		return nil, team.Context{}, err
	}
	selectedTeam := ""
	if effective.Team != nil {
		selectedTeam = *effective.Team
	}
	key := server + "\x00" + selectedTeam
	if current, found := r.contexts[key]; found {
		return client, current, nil
	}
	identity, found := r.identities[server]
	if !found {
		identity, err = client.Authority.IdentityContext(ctx)
		if err != nil {
			return nil, team.Context{}, err
		}
		r.identities[server] = identity
	}
	store, err := r.state.Server(ctx, server)
	if err != nil {
		return nil, team.Context{}, err
	}
	session := team.NewSession(nil, store, client, identity, team.Options{ProjectTeam: selectedTeam})
	current, err := session.CurrentWithDomains(ctx)
	if err != nil {
		return nil, team.Context{}, err
	}
	r.contexts[key] = current
	return client, current, nil
}

func (r *MetadataResolver) server(ctx context.Context, configured *string) (string, error) {
	if configured != nil {
		return clientstate.CanonicalServer(*configured)
	}
	if !r.savedServerLoaded {
		server, found, err := r.state.SavedServer(ctx)
		if err != nil {
			return "", err
		}
		if !found {
			server = clientserver.DefaultURL
		}
		r.savedServer, r.savedServerLoaded = server, true
	}
	return r.savedServer, nil
}

func (r *MetadataResolver) client(ctx context.Context, server string) (*clientauth.Client, error) {
	if client, found := r.clients[server]; found {
		return client, nil
	}
	var client *clientauth.Client
	var err error
	if r.authenticate != nil {
		client, err = r.authenticate(ctx, r.state, server)
	} else {
		if os.Getenv("TNL_ACCESS_TOKEN") != "" && os.Getenv("TNL_SERVER") == "" {
			return nil, failure.Wrap("select credential server", failure.InvalidTunnelFlags, errors.New("an explicit access token requires TNL_SERVER"))
		}
		client, err = clientauth.Authenticate(ctx, clientauth.Config{ServerEndpoint: server, State: r.state, AccessToken: os.Getenv("TNL_ACCESS_TOKEN")})
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

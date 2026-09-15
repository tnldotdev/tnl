package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"

	"github.com/tnldotdev/tnl/internal/clientauth"
	"github.com/tnldotdev/tnl/internal/clientstate"
	"github.com/tnldotdev/tnl/internal/clioutput"
	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/projectconfig"
	"github.com/tnldotdev/tnl/internal/projectmeta"
	"github.com/tnldotdev/tnl/pkg/api/authorityv1"
)

func runConfigGenerate(
	ctx context.Context,
	stateRoot string,
	project projectConfiguration,
	stdout, stderr io.Writer,
) error {
	if !project.Found() {
		return errors.New("no project configuration file found")
	}
	state, err := clientstate.Open(ctx, stateRoot)
	if err != nil {
		return err
	}
	defer state.Close()
	resolver := newProjectMetadataResolver(state, project, os.Stdin, stderr, "tnl config generate")
	metadata, err := resolver.Generate(ctx)
	if err != nil {
		return err
	}
	if err := projectmeta.Write(project.Root, metadata); err != nil {
		return err
	}
	actions, err := projectTypeIncludeActions(project)
	if err != nil {
		return err
	}
	fields := []clioutput.Field{
		clioutput.Field{Label: "metadata", Value: filepath.Join(project.Root, projectmeta.DirectoryName, projectmeta.JSONName)},
		clioutput.Field{Label: "declarations", Value: filepath.Join(project.Root, projectmeta.DirectoryName, projectmeta.DeclarationsName)},
	}
	blocks := []clioutput.Block{clioutput.Fields(fields...)}
	for _, action := range actions {
		blocks = append(blocks, clioutput.Section("action", clioutput.Text(action)))
	}
	return writeHumanFrame(stdout, "tnl config generate", "generated", "", blocks...)
}

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
	root, err := r.project.EffectiveService("")
	if err != nil {
		return projectmeta.Metadata{}, err
	}
	_, current, err := r.resolveContext(ctx, root)
	if err != nil {
		return projectmeta.Metadata{}, err
	}
	domain, err := defaultReadyDomain(current)
	if err != nil {
		return projectmeta.Metadata{}, err
	}
	metadata := projectmeta.Metadata{
		Version: projectmeta.Version, MemberNamespace: memberNamespace(current.membership, domain),
		Services:           make(map[string]projectmeta.Service, len(r.project.Config.Services)),
		ServiceDirectories: make(map[string]string, len(r.project.Config.Services)),
	}
	names := make([]string, 0, len(r.project.Config.Services))
	for name := range r.project.Config.Services {
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
		serviceMetadata, err := configuredProjectService(name, r.project.Worktree, effective, serviceContext)
		if err != nil {
			return projectmeta.Metadata{}, fmt.Errorf("service %q: %w", name, err)
		}
		metadata.Services[name] = serviceMetadata
		relative := r.project.RelativeServiceDirectories[name]
		if relative == "" {
			_, relative, err = r.project.ServiceDirectory(name)
			if err != nil {
				return projectmeta.Metadata{}, fmt.Errorf("service %q: %w", name, err)
			}
		}
		metadata.ServiceDirectories[name] = relative
	}
	if err := metadata.Validate(); err != nil {
		return projectmeta.Metadata{}, err
	}
	return metadata, nil
}

func configuredProjectService(
	service string,
	worktree projectconfig.Worktree,
	effective config.TNL,
	current teamContext,
) (projectmeta.Service, error) {
	hostname, subdomain := "", ""
	ephemeral := false
	if effective.Tunnel != nil {
		if effective.Tunnel.Host != nil {
			hostname = *effective.Tunnel.Host
		}
		if effective.Tunnel.Subdomain != nil {
			subdomain = *effective.Tunnel.Subdomain
		}
		ephemeral = effective.Tunnel.Ephemeral != nil && *effective.Tunnel.Ephemeral
	}
	if hostname == "" && subdomain == "" && !ephemeral {
		subdomain = projectconfig.ServiceWorktreeLabel(service, worktree.Label)
	}
	hostname, domain, _, err := resolvePublishHostname(hostname, subdomain, current)
	if err != nil {
		return projectmeta.Service{}, err
	}
	return projectmeta.Service{
		MemberNamespace: memberNamespace(current.membership, domain),
		Hostname:        hostname,
		URL:             "https://" + hostname,
	}, nil
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
	current, err := session.current(ctx)
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
	client, err := authenticatePublisher(ctx, r.state, server, "", r.command, input, diagnostics)
	if err != nil {
		return nil, err
	}
	if client.ServerEndpoint != server {
		return nil, errors.New("authenticated server does not match project configuration")
	}
	r.clients[server] = client
	return client, nil
}

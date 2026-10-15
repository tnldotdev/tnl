package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/tnldotdev/tnl/internal/clientauth"
	"github.com/tnldotdev/tnl/internal/clientruntime"
	"github.com/tnldotdev/tnl/internal/clientstate"
	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/filelock"
	"github.com/tnldotdev/tnl/internal/integrationurls"
	"github.com/tnldotdev/tnl/internal/localproxy"
	"github.com/tnldotdev/tnl/internal/localpublisher"
	"github.com/tnldotdev/tnl/internal/privateprotocol"
	"github.com/tnldotdev/tnl/internal/projectconfig"
	"github.com/tnldotdev/tnl/internal/projectmeta"
	"github.com/tnldotdev/tnl/internal/projectpublisher"
	"github.com/tnldotdev/tnl/internal/publisher"
)

type runtimeCommand struct {
	Endpoint      runtimeEndpointOptions `cmd:"" hidden:""`
	OwnerEndpoint runtimeOptions         `cmd:"" hidden:""`
	Serve         runtimeOptions         `cmd:"" hidden:""`
}
type runtimeOptions struct {
	Directory string `name:"directory" required:"" type:"path"`
	StateDir  string `name:"state-dir" env:"TNL_STATE_DIR" type:"path"`
}
type runtimeEndpointOptions struct {
	runtimeOptions `embed:""`
	Service        string `name:"service"`
	InvocationID   string `name:"invocation-id"`
}

// target discovery is supplied by the host container integration.
var runtimeTargetResolver projectpublisher.TargetResolver

var runtimeConfigurePublication func(context.Context, *clientstate.Database, projectconfig.Project, clientruntime.Service, *publisher.Config) error
var runtimeVisitorTLS func(context.Context, *clientstate.Database, projectconfig.Project, clientruntime.Service) (*tls.Config, error)
var runtimeAttachIntegrations func(context.Context, *clientstate.Database, projectconfig.Project, clientruntime.Service, *clientstate.Tunnel, *publisher.Config) (func(), error)

func runtimeProject(ctx context.Context, options runtimeOptions) (projectConfiguration, string, error) {
	root, err := clientStateRoot(options.StateDir)
	if err != nil {
		return projectConfiguration{}, "", err
	}
	directory, err := filepath.Abs(options.Directory)
	if err != nil {
		return projectConfiguration{}, "", err
	}
	directory, err = filepath.EvalSymlinks(directory)
	if err != nil {
		return projectConfiguration{}, "", err
	}
	state, err := clientstate.Open(ctx, root)
	if err != nil {
		return projectConfiguration{}, "", err
	}
	defer state.Close()
	salt, err := state.WorktreeHashSalt(ctx)
	if err != nil {
		return projectConfiguration{}, "", err
	}
	selection, err := projectconfig.SelectProjectConfig(ctx, directory, "", os.Getenv("TNL_CONFIG"), false)
	if err != nil {
		return projectConfiguration{}, "", err
	}
	project, err := projectconfig.Resolve(ctx, selection, directory, salt)
	if err != nil {
		return projectConfiguration{}, "", err
	}
	if selected := os.Getenv("TNL_SERVER"); selected != "" {
		canonical, err := clientstate.CanonicalServer(selected)
		if err != nil {
			return projectConfiguration{}, "", err
		}
		project.Config.Server = &canonical
	}
	return projectConfiguration{Project: project}, state.Root(), nil
}

func runtimeAvailable(ctx context.Context, endpoint privateprotocol.Endpoint) bool {
	return privateprotocol.Call(ctx, endpoint, "GET", "/v1/health", nil, nil) == nil
}

func ensureRuntimeOwner(ctx context.Context, project projectConfiguration, root string) (privateprotocol.Endpoint, error) {
	path, err := privateprotocol.DescriptorPath(root, project.Root)
	if err != nil {
		return privateprotocol.Endpoint{}, err
	}
	if endpoint, err := privateprotocol.ReadEndpoint(path); err == nil && runtimeAvailable(ctx, endpoint) {
		return endpoint, nil
	}
	executable, err := os.Executable()
	if err != nil {
		return privateprotocol.Endpoint{}, err
	}
	command := exec.Command(executable, "runtime", "serve", "--directory", project.Root, "--state-dir", root)
	if err := command.Start(); err != nil {
		return privateprotocol.Endpoint{}, err
	}
	go func() { _ = command.Wait() }()
	timer := time.NewTimer(15 * time.Second)
	defer timer.Stop()
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	for {
		if endpoint, err := privateprotocol.ReadEndpoint(path); err == nil && runtimeAvailable(ctx, endpoint) {
			return endpoint, nil
		}
		select {
		case <-ctx.Done():
			return privateprotocol.Endpoint{}, ctx.Err()
		case <-timer.C:
			return privateprotocol.Endpoint{}, failure.Wrap("start project owner", failure.ClientStateUnavailable, errors.New("local publisher did not start"))
		case <-ticker.C:
		}
	}
}

func runRuntimeOwnerEndpoint(ctx context.Context, options runtimeOptions, output io.Writer) error {
	project, root, err := runtimeProject(ctx, options)
	if err != nil {
		return err
	}
	endpoint, err := ensureRuntimeOwner(ctx, project, root)
	if err != nil {
		return err
	}
	return json.NewEncoder(output).Encode(endpoint)
}

func runRuntimeEndpoint(ctx context.Context, options runtimeEndpointOptions, output io.Writer) error {
	project, root, err := runtimeProject(ctx, options.runtimeOptions)
	if err != nil {
		return err
	}
	request := privateprotocol.CapabilityRequest{Scope: "app"}
	if options.InvocationID != "" {
		if options.Service != "" {
			return errors.New("select a service or invocation")
		}
		request.Scope, request.InvocationId = "invocation", &options.InvocationID
	} else {
		name, err := project.AppService(options.Directory, options.Service)
		if err != nil {
			return err
		}
		request.Service = &name
	}
	owner, err := ensureRuntimeOwner(ctx, project, root)
	if err != nil {
		return err
	}
	var endpoint privateprotocol.Endpoint
	if err := privateprotocol.Call(ctx, owner, "POST", "/v1/capabilities", request, &endpoint); err != nil {
		return err
	}
	return json.NewEncoder(output).Encode(endpoint)
}

type appPreparation struct {
	configuration projectpublisher.Configuration
	project       projectConfiguration
	framework     privateprotocol.Framework
	assignment    privateprotocol.Assignment
	invocation    *privateprotocol.Invocation
}

type appRuntime struct {
	manager      *clientruntime.Manager
	workers      *projectpublisher.Workers
	capabilities *privateprotocol.Capabilities
	project      projectConfiguration
	state        *clientstate.Database
	mu           sync.Mutex
	prepareMu    sync.Mutex
	prepared     map[string]appPreparation
	// visitor and admission integration is attached before worker fencing wraps
	// callbacks. this applies equally to SDK, named CLI and invocation workers.
	AttachPublication func(context.Context, clientruntime.Service, *publisher.Config) error
}

func authenticateRuntime(ctx context.Context, state *clientstate.Database, server string) (*clientauth.Client, error) {
	if os.Getenv("TNL_ACCESS_TOKEN") != "" && os.Getenv("TNL_SERVER") == "" {
		return nil, failure.Wrap("select credential server", failure.InvalidTunnelFlags, errors.New("an explicit access token requires TNL_SERVER"))
	}
	return clientauth.Authenticate(ctx, clientauth.Config{ServerEndpoint: server, State: state, AccessToken: os.Getenv("TNL_ACCESS_TOKEN"), Diagnostics: io.Discard})
}

func configuredRuntimeServices(project projectConfiguration) []clientruntime.Service {
	services := make([]clientruntime.Service, 0, len(project.Config.Services))
	for name, definition := range project.Config.Services {
		readiness := clientruntime.Readiness{Path: "/"}
		if definition.HTTP != nil && definition.HTTP.Readiness != nil {
			readiness.Path = definition.HTTP.Readiness.Path
		}
		services = append(services, clientruntime.Service{Name: name, Directory: ".", ServiceProtocol: config.Protocol(definition), Readiness: readiness})
	}
	slices.SortFunc(services, func(a, b clientruntime.Service) int { return strings.Compare(a.Name, b.Name) })
	return services
}

func runRuntimeServe(ctx context.Context, options runtimeOptions) error {
	project, root, err := runtimeProject(ctx, options)
	if err != nil {
		return err
	}
	path, err := privateprotocol.DescriptorPath(root, project.Root)
	if err != nil {
		return err
	}
	lock, err := filelock.Acquire(path+".lock", filelock.Nonblocking, os.Geteuid())
	if errors.Is(err, filelock.ErrLocked) {
		return nil
	}
	if err != nil {
		return err
	}
	defer lock.Close()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return err
	}
	capabilities, err := privateprotocol.NewCapabilities("http://" + listener.Addr().String())
	if err != nil {
		return err
	}
	defer listener.Close()
	state, err := clientstate.Open(ctx, root)
	if err != nil {
		return err
	}
	defer state.Close()
	a := &appRuntime{project: project, state: state, capabilities: capabilities, prepared: map[string]appPreparation{}}
	if runtimeConfigurePublication != nil {
		a.AttachPublication = func(ctx context.Context, service clientruntime.Service, cfg *publisher.Config) error {
			return runtimeConfigurePublication(ctx, state, project.Project, service, cfg)
		}
	}
	a.workers = &projectpublisher.Workers{Database: state, Configure: a.workerConfiguration}
	if runtimeVisitorTLS != nil {
		a.workers.VisitorTLS = func(ctx context.Context, service clientruntime.Service) (*tls.Config, error) {
			return runtimeVisitorTLS(ctx, state, project.Project, service)
		}
	}
	a.manager, err = clientruntime.New(ctx, project.Root, state, configuredRuntimeServices(project), a.workers.Run)
	if err != nil {
		return err
	}
	a.workers.Manager = a.manager
	a.manager.Alive = func(pid int) bool { return syscall.Kill(pid, 0) == nil }
	defer a.manager.Close()
	// unregister joins the publication after draining its visitor streams.
	server := &http.Server{Handler: a.handler(), BaseContext: func(net.Listener) context.Context { return ctx }, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 80 * time.Second, IdleTimeout: 10 * time.Second, MaxHeaderBytes: privateprotocol.MaxBytes}
	done := make(chan error, 1)
	go func() { done <- server.Serve(listener) }()
	defer func() {
		shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdown)
		_ = server.Close()
	}()
	if err := privateprotocol.WriteEndpoint(path, capabilities.Owner()); err != nil {
		return err
	}
	defer privateprotocol.RemoveEndpoint(path, capabilities.Owner().OwnerId)
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case err := <-done:
			if errors.Is(err, http.ErrServerClosed) {
				return nil
			}
			return err
		case <-ticker.C:
			if a.manager.Sweep(a.manager.Alive) {
				return nil
			}
			a.mu.Lock()
			for id := range a.prepared {
				if _, found := a.manager.ServiceForRegistration(id); !found {
					delete(a.prepared, id)
				}
			}
			a.mu.Unlock()
		}
	}
}

func (a *appRuntime) handler() http.Handler {
	return (&localpublisher.Server{Capabilities: a.capabilities, Manager: a.manager, Database: a.state, Project: a.project.Root, Prepare: a.prepare, Register: a.register, Acquire: a.acquire, Invocation: a.invocation, Check: a.workers.Check, AppService: func(name string) bool {
		service, found := a.project.Config.Services[name]
		return found && config.TargetType(service) == "app"
	}}).Handler()
}

func (a *appRuntime) register(request privateprotocol.Registration) error {
	a.mu.Lock()
	preparation, found := a.prepared[request.RegistrationID]
	a.mu.Unlock()
	if !found {
		return clientruntime.ErrRegistrationStale
	}
	// retain the app's reported origin for renewal, but never treat its
	// hostname as a container address. the worker resolves the selected service.
	return a.manager.Register(request.RegistrationID, request.Owner, request.Target, string(preparation.framework))
}

func (a *appRuntime) prepare(ctx context.Context, request privateprotocol.Prepare) (privateprotocol.Assignment, error) {
	if request.Version != 1 || !privateprotocol.ValidOwner(request.Owner) || request.PID <= 0 || !request.Framework.Valid() {
		return privateprotocol.Assignment{}, errors.New("invalid app preparation")
	}
	name, err := a.project.AppService(request.Directory, request.Service)
	if err != nil {
		return privateprotocol.Assignment{}, err
	}
	a.prepareMu.Lock()
	defer a.prepareMu.Unlock()
	finish := a.manager.BeginPreparation()
	defer finish()
	resolver := newProjectMetadataResolver(a.state, a.project, strings.NewReader(""), io.Discard, "app prepare")
	resolver.silent = true
	metadata, err := resolver.Generate(ctx)
	if err != nil {
		return privateprotocol.Assignment{}, err
	}
	if err := projectmeta.Write(ctx, a.project.Root, metadata); err != nil {
		return privateprotocol.Assignment{}, err
	}
	selected := metadata.Services[name]
	id, err := a.manager.Reserve(name, request.Owner, request.PID, selected.URL)
	if err != nil {
		return privateprotocol.Assignment{}, err
	}
	assignment := privateprotocol.Assignment{Version: 1, RegistrationID: id, Service: name, Hostname: selected.Hostname, PublicURL: selected.URL, Project: metadata.Public(true)}
	a.mu.Lock()
	a.prepared[id] = appPreparation{project: a.project, framework: request.Framework, assignment: assignment}
	a.mu.Unlock()
	return assignment, nil
}

func (a *appRuntime) acquire(ctx context.Context, request privateprotocol.Lease) (privateprotocol.Registration, error) {
	a.prepareMu.Lock()
	defer a.prepareMu.Unlock()
	finish := a.manager.BeginPreparation()
	defer finish()
	resolved, err := projectpublisher.ResolveTarget(ctx, a.project.Project, request.Service, runtimeTargetResolver)
	if err != nil {
		return privateprotocol.Registration{}, err
	}
	resolver := newProjectMetadataResolver(a.state, a.project, strings.NewReader(""), io.Discard, "named publish")
	resolver.silent = true
	metadata, err := resolver.Generate(ctx)
	if err != nil {
		return privateprotocol.Registration{}, err
	}
	selected := metadata.Services[request.Service]
	address := selected.URL
	if selected.Protocol != "http" {
		address = selected.Address
	}
	id, err := a.manager.Reserve(request.Service, request.Owner, request.Pid, address)
	if err != nil {
		return privateprotocol.Registration{}, err
	}
	a.mu.Lock()
	a.prepared[id] = appPreparation{project: a.project}
	a.mu.Unlock()
	registration := privateprotocol.Registration{Version: 1, RegistrationID: id, Owner: request.Owner, Target: string(*resolved.Target)}
	if err := a.manager.Register(id, request.Owner, registration.Target, ""); err != nil {
		_ = a.manager.Unregister(id, request.Owner)
		return privateprotocol.Registration{}, err
	}
	return registration, nil
}

func (a *appRuntime) workerConfiguration(ctx context.Context, service clientruntime.Service) (projectpublisher.Configuration, error) {
	a.mu.Lock()
	preparation, found := a.prepared[service.RegistrationID]
	a.mu.Unlock()
	if !found {
		return projectpublisher.Configuration{}, clientruntime.ErrRegistrationStale
	}
	if preparation.configuration.Publisher.Control != nil {
		return preparation.configuration, nil
	}
	project := preparation.project
	effective, err := project.EffectiveService(service.Name)
	if err != nil {
		return projectpublisher.Configuration{}, err
	}
	resolver := newProjectMetadataResolver(a.state, project, strings.NewReader(""), io.Discard, "project publish")
	resolver.silent = true
	server, err := resolver.server(ctx, effective.Server)
	if err != nil {
		return projectpublisher.Configuration{}, err
	}
	authenticated, err := resolver.client(ctx, server)
	if err != nil {
		return projectpublisher.Configuration{}, err
	}
	_, current, err := resolver.resolveContext(ctx, effective)
	if err != nil {
		return projectpublisher.Configuration{}, err
	}
	selected, err := configuredProjectService(service.Name, project.Worktree, effective, current)
	if err != nil {
		return projectpublisher.Configuration{}, err
	}
	services, err := preparePublisherServices(ctx, a.state, server, "https://"+selected.Hostname, "", "", valueOrEmpty(effective.Team), false, authenticated)
	if err != nil {
		return projectpublisher.Configuration{}, err
	}
	flags := tunnelFlags{}
	applyTunnelConfiguration(&flags, effective.Tunnel)
	policy, err := resolveIPPolicy(ctx, authenticated.Control, flags.AllowIP, flags.AllowAllIPs)
	if err != nil {
		return projectpublisher.Configuration{}, err
	}
	limits, err := config.ResolveWorkLimits(effectiveTunnelLimits(effective), service.ServiceProtocol)
	if err != nil {
		return projectpublisher.Configuration{}, err
	}
	inspectionPolicy, err := config.ResolveInspection(effective.Inspection, service.ServiceProtocol)
	if err != nil {
		return projectpublisher.Configuration{}, err
	}
	cfg := services.config(service.Target, policy.prefixes, limits)
	var binding *projectpublisher.TargetBinding
	{
		binding = runtimeTargetBinding(project.Project, service.Name, service.Target, nil)
		binding.Changed = func() {
			a.manager.Observe(clientruntime.Observation{Target: service.Target, RegistrationID: service.RegistrationID,
				PublishRunNumber: service.PublishRunNumber, Readiness: service.Readiness, CheckedAt: time.Now().UTC(), Reason: "runtime.target_changed"})
		}
		selected, err := binding.Capture(ctx)
		if err != nil {
			return projectpublisher.Configuration{}, err
		}
		cfg.Target = selected.Address
	}
	cfg.ResolveTarget = func(ctx context.Context) (string, string, error) {
		selected, err := binding.Capture(ctx)
		return selected.Address, selected.Identity, err
	}
	cfg.ControlURL, cfg.ProjectRoot, cfg.Service = server, project.Root, service.Name
	cfg.ServiceProtocol = protocolForService(project.Config.Services[service.Name])
	cfg.PreserveSavedURLTarget = true
	resolved := config.ServicePublish(project.Config.Services[service.Name])
	if resolved.TargetTLS != nil {
		cfg.TargetTLS = *resolved.TargetTLS
	}
	if resolved.TargetTLSName != nil {
		cfg.TargetTLSName = *resolved.TargetTLSName
	}
	if resolved.TargetCAFile != nil {
		cfg.TargetOptions, err = targetOptionsForCA(*resolved.TargetCAFile, project.Root)
		if err != nil {
			return projectpublisher.Configuration{}, err
		}
	}
	native, err := selectNativeProjectPublisher(ctx, services, cfg)
	if err != nil {
		return projectpublisher.Configuration{}, err
	}
	traffic, err := config.ResolveTrafficSelection(effectiveTunnelLimits(effective))
	if err != nil {
		return projectpublisher.Configuration{}, err
	}
	native, err = native.WithTraffic(traffic)
	if err != nil {
		return projectpublisher.Configuration{}, err
	}
	cfg.Control = native
	if a.AttachPublication != nil {
		if err := a.AttachPublication(ctx, service, &cfg); err != nil {
			return projectpublisher.Configuration{}, err
		}
	}
	for prefix, mount := range config.ServicePaths(project.Config.Services[service.Name]) {
		options := localproxy.TargetOptions{}
		mounted := config.ServicePublish(project.Config.Services[mount.Service])
		if mounted.TargetCAFile != nil {
			options, err = targetOptionsForCA(*mounted.TargetCAFile, project.Root)
			if err != nil {
				return projectpublisher.Configuration{}, err
			}
		}
		cfg.Mounts = append(cfg.Mounts, localproxy.Mount{Prefix: prefix, StripPrefix: mount.StripPrefix, Options: options, ResolveTarget: func() string {
			for _, candidate := range a.manager.Snapshot().Services {
				if candidate.Name == mount.Service && a.manager.Current(candidate.Name, candidate.RegistrationID, candidate.Target, 0) {
					return candidate.Target
				}
			}
			return ""
		}})
	}
	previewID, err := ensurePreview(ctx, a.state, services.state, services.routes, server, services.teamID, project.Root)
	if err != nil {
		return projectpublisher.Configuration{}, err
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
	configuration := projectpublisher.Configuration{Publisher: cfg, TargetBinding: binding, Inspection: inspectionPolicy, PrimaryRoot: project.Worktree.PrimaryCheckoutRoot(), SharedRoot: project.Worktree.PrimaryCheckoutRoot(), IntegrationGroup: group}
	configuration.Attach = func(ctx context.Context, tunnel *clientstate.Tunnel, cfg *publisher.Config) (func(), error) {
		required := project.Config.OAuth
		for _, definition := range project.Config.Webhooks {
			required = required || definition.Service == service.Name
		}
		for _, definition := range project.Config.Aliases {
			required = required || definition.Service == service.Name
		}
		if project.Config.OAuth {
			origin, _, err := projectOAuthPublisher(ctx, a.state, project.Project, server, valueOrEmpty(project.Config.Team), services.authenticated)
			if err != nil {
				return nil, err
			}
			cfg.ObserveResponse = integrationurls.Observer(a.state, server, origin.Hostname, group, tunnel.ID())
		}
		if runtimeAttachIntegrations != nil {
			return runtimeAttachIntegrations(ctx, a.state, project.Project, service, tunnel, cfg)
		}
		if required {
			return nil, failure.Wrap("attach project integration URLs", failure.IntegrationURLNotReady, errors.New("a scoped integration publisher is required"))
		}
		return nil, nil
	}
	return configuration, nil
}

func valueOrEmpty(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}
func effectiveTunnelLimits(effective config.TNL) *config.Limits {
	if effective.Tunnel == nil {
		return nil
	}
	return effective.Tunnel.Limits
}

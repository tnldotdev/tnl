package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/tnldotdev/tnl/internal/clientauth"
	"github.com/tnldotdev/tnl/internal/clientruntime"
	"github.com/tnldotdev/tnl/internal/clientstate"
	"github.com/tnldotdev/tnl/internal/controlclient"
	"github.com/tnldotdev/tnl/internal/diagnostic"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/filelock"
	"github.com/tnldotdev/tnl/internal/integrationurls"
	"github.com/tnldotdev/tnl/internal/localproxy"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/privateprotocol"
	"github.com/tnldotdev/tnl/internal/projectconfig"
	"github.com/tnldotdev/tnl/internal/projectmeta"
	"github.com/tnldotdev/tnl/internal/publisher"
)

type runtimeCommand struct {
	Start runtimeOptions `cmd:"" hidden:""`
	Serve runtimeOptions `cmd:"" hidden:""`
}
type runtimeOptions struct {
	Directory string `name:"directory" required:"" type:"path"`
	StateDir  string `name:"state-dir" env:"TNL_STATE_DIR" type:"path"`
}

func runtimeProject(ctx context.Context, options runtimeOptions) (projectConfiguration, string, error) {
	root, err := clientStateRoot(options.StateDir)
	if err != nil {
		return projectConfiguration{}, "", err
	}
	directory, err := filepath.EvalSymlinks(options.Directory)
	if err != nil {
		return projectConfiguration{}, "", err
	}
	state, err := clientstate.Open(ctx, root)
	if err != nil {
		return projectConfiguration{}, "", err
	}
	root = state.Root()
	salt, err := state.WorktreeHashSalt(ctx)
	closeErr := state.Close()
	if err != nil || closeErr != nil {
		return projectConfiguration{}, "", errors.Join(err, closeErr)
	}
	selection, err := projectconfig.SelectProjectConfig(ctx, directory, "", os.Getenv("TNL_CONFIG"), false)
	if err != nil {
		return projectConfiguration{}, "", err
	}
	project, err := projectconfig.Resolve(ctx, selection, directory, salt)
	if err != nil {
		return projectConfiguration{}, "", err
	}
	if !project.Found() || len(project.Config.Services) == 0 {
		return projectConfiguration{}, "", failure.Wrap("prepare app", failure.ProjectConfigMissing, errors.New("configure at least one project service"))
	}
	if selected := os.Getenv("TNL_SERVER"); selected != "" {
		canonical, err := clientstate.CanonicalServer(selected)
		if err != nil {
			return projectConfiguration{}, "", err
		}
		project.Config.Server = &canonical
	}
	// service registrations reuse saved URLs; ephemeral URLs are for one-off
	// tnl publish invocations, not app restarts.
	if project.Config.Tunnel != nil {
		tunnel := *project.Config.Tunnel
		value := false
		tunnel.Ephemeral = &value
		project.Config.Tunnel = &tunnel
	}
	for name, service := range project.Config.Services {
		if service.Tunnel != nil {
			tunnel := *service.Tunnel
			value := false
			tunnel.Ephemeral = &value
			service.Tunnel = &tunnel
			project.Config.Services[name] = service
		}
	}
	return projectConfiguration{Project: project}, root, nil
}

func runtimeSocket(project, state string) (string, error) {
	// a stable short directory keeps one identity across application environments
	// and fits Darwin's Unix socket path limit.
	directory, err := privateRuntimeDirectoryAt("/tmp")
	if err != nil {
		return "", err
	}
	return filepath.Join(directory, "app-"+clientruntime.Identity(project, state)+".sock"), nil
}

func runtimeHTTP(socket string) *http.Client {
	return &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{DisableKeepAlives: true, DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", socket)
	}}}
}

func runtimeAvailable(ctx context.Context, socket string) bool {
	request, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost/v1/health", nil)
	response, err := runtimeHTTP(socket).Do(request)
	if err != nil {
		return false
	}
	response.Body.Close()
	return response.StatusCode == http.StatusNoContent
}

func runRuntimeStart(ctx context.Context, options runtimeOptions, output io.Writer) error {
	project, state, err := runtimeProject(ctx, options)
	if err != nil {
		return err
	}
	socket, err := runtimeSocket(project.Root, state)
	if err != nil {
		return err
	}
	if !runtimeAvailable(ctx, socket) {
		binary, err := os.Executable()
		if err != nil {
			return err
		}
		command := exec.Command(binary, "--no-telemetry", "runtime", "serve", "--directory", project.Root, "--state-dir", state)
		command.Dir = project.Root
		command.Env = append(os.Environ(), "TNL_CONFIG="+project.Selection.Path)
		command.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
		command.Stdin, command.Stdout, command.Stderr = nil, io.Discard, io.Discard
		if err := command.Start(); err != nil {
			return err
		}
		go func() { _ = command.Wait() }()
		deadline := time.NewTimer(15 * time.Second)
		defer deadline.Stop()
		ticker := time.NewTicker(50 * time.Millisecond)
		defer ticker.Stop()
		for !runtimeAvailable(ctx, socket) {
			select {
			case <-ctx.Done():
				return context.Cause(ctx)
			case <-deadline.C:
				return failure.Wrap("start local publisher", failure.TunnelUnavailable, errors.New("local publisher did not start"))
			case <-ticker.C:
			}
		}
	}
	return json.NewEncoder(output).Encode(struct {
		Protocol int    `json:"protocol"`
		Socket   string `json:"socket"`
	}{privateprotocol.Version, socket})
}

type appPreparation struct {
	assignment privateprotocol.Assignment
	services   publisherServices
	policy     resolvedIPPolicy
	flags      tunnelFlags
	framework  string
	project    projectConfiguration
}

type appRuntime struct {
	manager   *clientruntime.Manager
	project   projectConfiguration
	state     *clientstate.Database
	mu        sync.Mutex
	prepareMu sync.Mutex
	prepared  map[string]appPreparation
}

func authenticateRuntime(ctx context.Context, state *clientstate.Database, server string) (*clientauth.Client, error) {
	if os.Getenv("TNL_ACCESS_TOKEN") != "" && os.Getenv("TNL_SERVER") == "" {
		return nil, failure.Wrap("select credential server", failure.InvalidTunnelFlags, errors.New("an explicit access token requires TNL_SERVER"))
	}
	// credential refresh and current validation belong to clientauth. the local
	// runtime cannot request an interactive login on an application's behalf.
	return clientauth.Authenticate(ctx, clientauth.Config{ServerEndpoint: server, State: state, AccessToken: os.Getenv("TNL_ACCESS_TOKEN"), Diagnostics: io.Discard})
}

func configuredRuntimeServices(project projectConfiguration) []clientruntime.Service {
	services := make([]clientruntime.Service, 0, len(project.Config.Services))
	for name := range project.Config.Services {
		effective, _ := project.EffectiveService(name)
		readiness := clientruntime.Readiness{Path: "/"}
		if effective.Readiness != nil {
			readiness.Path = effective.Readiness.Path
			if effective.Readiness.Status != nil {
				readiness.Status = *effective.Readiness.Status
			}
		}
		services = append(services, clientruntime.Service{Name: name, Directory: project.RelativeServiceDirectories[name], Readiness: readiness})
	}
	slices.SortFunc(services, func(a, b clientruntime.Service) int { return strings.Compare(a.Name, b.Name) })
	return services
}

func runRuntimeServe(ctx context.Context, options runtimeOptions) error {
	project, root, err := runtimeProject(ctx, options)
	if err != nil {
		return err
	}
	socket, err := runtimeSocket(project.Root, root)
	if err != nil {
		return err
	}
	lock, err := filelock.Acquire(socket+".lock", filelock.Nonblocking, os.Getuid())
	if errors.Is(err, filelock.ErrLocked) {
		return nil
	}
	if err != nil {
		return err
	}
	defer lock.Close()
	if info, err := os.Lstat(socket); err == nil {
		if info.Mode()&os.ModeSocket == 0 {
			return failure.Wrap("open local publisher socket", failure.DevSocketUnavailable, errors.New("local publisher socket path is occupied by a non-socket file"))
		}
		if err := os.Remove(socket); err != nil {
			return err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	listener, err := net.Listen("unix", socket)
	if err != nil {
		return err
	}
	defer listener.Close()
	defer os.Remove(socket)
	if err := os.Chmod(socket, 0600); err != nil {
		return err
	}
	state, err := clientstate.Open(ctx, root)
	if err != nil {
		return err
	}
	defer state.Close()
	runtime := &appRuntime{project: project, state: state, prepared: map[string]appPreparation{}}
	runtime.manager, err = clientruntime.New(ctx, project.Root, root, configuredRuntimeServices(project), runtime.publish)
	if err != nil {
		return err
	}
	runtime.manager.Alive = func(pid int) bool { return syscall.Kill(pid, 0) == nil }
	defer runtime.manager.Close()
	server := &http.Server{Handler: runtime.handler(), ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 10 * time.Second}
	done := make(chan error, 1)
	go func() { done <- server.Serve(listener) }()
	defer func() {
		closeCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(closeCtx)
		_ = server.Close()
	}()
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
			if runtime.manager.Sweep(runtime.manager.Alive) {
				return nil
			}
			runtime.mu.Lock()
			live := map[string]bool{}
			for _, service := range runtime.manager.Snapshot().Services {
				if service.RegistrationID != "" {
					live[service.RegistrationID] = true
				}
			}
			for id := range runtime.prepared {
				if !live[id] {
					delete(runtime.prepared, id)
				}
			}
			runtime.mu.Unlock()
		}
	}
}

var appOwnerPattern = regexp.MustCompile(`^[a-f0-9]{32}$`)

func (a *appRuntime) prepare(ctx context.Context, request privateprotocol.Prepare) (assignmentResult privateprotocol.Assignment, resultErr error) {
	finishPreparation := a.manager.BeginPreparation()
	defer finishPreparation()
	if request.Protocol != privateprotocol.Version || !appOwnerPattern.MatchString(request.Owner) || request.PID <= 0 || !slices.Contains([]string{"node", "bun", "vite", "next"}, request.Framework) {
		return privateprotocol.Assignment{}, failure.Wrap("prepare app", failure.ProjectConfigInvalid, errors.New("invalid app preparation"))
	}
	directory, err := filepath.EvalSymlinks(request.Directory)
	if err != nil || !pathInside(directory, a.project.Root) {
		return privateprotocol.Assignment{}, failure.Wrap("select app directory", failure.ProjectConfigInvalid, errors.Join(err, errors.New("app directory is outside the project")))
	}
	project, _, err := runtimeProject(ctx, runtimeOptions{Directory: directory, StateDir: a.state.Root()})
	if err != nil {
		return privateprotocol.Assignment{}, err
	}
	if project.Root != a.project.Root {
		return privateprotocol.Assignment{}, failure.Wrap("select app project", failure.ProjectConfigInvalid, errors.New("app preparation selected another project"))
	}
	name := request.Service
	if name == "" {
		longest := -1
		for candidate, path := range project.ServiceDirectories {
			if pathInside(directory, path) {
				if len(path) > longest {
					name, longest = candidate, len(path)
				} else if len(path) == longest {
					name = ""
				}
			}
		}
	}
	if !naming.ValidServiceName(name) {
		return privateprotocol.Assignment{}, failure.Wrap("select app service", failure.ServiceNotConfigured, errors.New("select a unique configured service"))
	}
	defer func() {
		if resultErr == nil {
			return
		}
		reason := "runtime.preparation_failed"
		if known, _, ok := failure.Describe(resultErr); ok {
			reason = string(known)
		}
		if errors.Is(resultErr, controlclient.ErrUnauthenticated) {
			reason = string(failure.Authentication)
		}
		a.manager.RecordFailure(name, reason)
	}()
	effective, err := project.EffectiveService(name)
	if err != nil {
		return privateprotocol.Assignment{}, err
	}
	a.prepareMu.Lock()
	defer a.prepareMu.Unlock()
	if err := a.manager.Configure(configuredRuntimeServices(project)); err != nil {
		return privateprotocol.Assignment{}, err
	}
	resolver := newProjectMetadataResolver(a.state, project, strings.NewReader(""), io.Discard, "app prepare")
	resolver.silent = true
	metadata, err := resolver.Generate(ctx)
	if err != nil {
		return privateprotocol.Assignment{}, err
	}
	server, err := resolver.server(ctx, effective.Server)
	if err != nil {
		return privateprotocol.Assignment{}, err
	}
	authenticated, err := resolver.client(ctx, server)
	if err != nil {
		return privateprotocol.Assignment{}, err
	}
	flags := tunnelFlags{RequestInspection: "summary"}
	applyTunnelConfiguration(&flags, effective.Tunnel)
	applyRequestInspection(&flags, effective)
	// app-led URLs remain saved across restarts, including configurations that
	// previously requested ephemeral development URLs.
	flags.Ephemeral = false
	selected := metadata.Services[name]
	services, err := preparePublisherServices(ctx, a.state, server, selected.URL, "", flags.Domain, valueOrEmpty(effective.Team), false, authenticated)
	if err != nil {
		return privateprotocol.Assignment{}, err
	}
	policy, err := resolveIPPolicy(ctx, authenticated.Control, flags.AllowIP, flags.AllowAllIPs)
	if err != nil {
		return privateprotocol.Assignment{}, err
	}
	assignment := privateprotocol.Assignment{Protocol: privateprotocol.Version, RegistrationID: "reg_" + strings.Repeat("0", 32), Service: name, Hostname: selected.Hostname, PublicURL: selected.URL, Project: metadata.Public(true)}
	payload, err := json.Marshal(assignment)
	if err != nil || len(payload) > privateprotocol.MaxBytes {
		return privateprotocol.Assignment{}, failure.Wrap("prepare app metadata", failure.ProjectConfigInvalid, errors.Join(err, errors.New("app metadata exceeds private protocol limit")))
	}
	if err := projectmeta.Write(ctx, a.project.Root, metadata); err != nil {
		return privateprotocol.Assignment{}, err
	}
	if err := ctx.Err(); err != nil {
		return privateprotocol.Assignment{}, err
	}
	id, err := a.manager.Reserve(name, request.Owner, request.PID, selected.URL)
	if err != nil {
		return privateprotocol.Assignment{}, err
	}
	assignment.RegistrationID = id
	a.mu.Lock()
	a.prepared[id] = appPreparation{assignment: assignment, services: services, policy: policy, flags: flags, framework: request.Framework, project: project}
	a.mu.Unlock()
	return assignment, nil
}

func valueOrEmpty(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}

func (a *appRuntime) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/health", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	mux.HandleFunc("GET /v1/status", func(w http.ResponseWriter, _ *http.Request) { privateprotocol.Write(w, 200, a.manager.Snapshot()) })
	mux.HandleFunc("POST /v1/observe", func(w http.ResponseWriter, r *http.Request) {
		var observation clientruntime.Observation
		if err := privateprotocol.Decode(w, r, &observation); err != nil {
			runtimeProblem(w, err)
			return
		}
		if !a.manager.Observe(observation) {
			runtimeProblem(w, clientruntime.ErrRegistrationStale)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("POST /v1/prepare", func(w http.ResponseWriter, r *http.Request) {
		var request privateprotocol.Prepare
		if err := privateprotocol.Decode(w, r, &request); err != nil {
			runtimeProblem(w, err)
			return
		}
		assignment, err := a.prepare(r.Context(), request)
		if err != nil {
			runtimeProblem(w, err)
			return
		}
		privateprotocol.Write(w, 200, assignment)
	})
	for _, operation := range []string{"register", "renew", "unregister"} {
		mux.HandleFunc("POST /v1/"+operation, func(w http.ResponseWriter, r *http.Request) {
			var request privateprotocol.Registration
			if err := privateprotocol.Decode(w, r, &request); err != nil {
				runtimeProblem(w, err)
				return
			}
			if request.Protocol != privateprotocol.Version {
				runtimeProblem(w, errors.New("unsupported protocol"))
				return
			}
			var err error
			switch operation {
			case "register":
				a.mu.Lock()
				preparation, found := a.prepared[request.RegistrationID]
				a.mu.Unlock()
				if !found {
					err = clientruntime.ErrRegistrationStale
				} else {
					err = a.manager.Register(request.RegistrationID, request.Owner, request.Target, preparation.framework)
				}
			case "renew":
				err = a.manager.Renew(request.RegistrationID, request.Owner)
			case "unregister":
				err = a.manager.Unregister(request.RegistrationID, request.Owner)
			}
			if err != nil {
				runtimeProblem(w, err)
				return
			}
			w.WriteHeader(http.StatusNoContent)
		})
	}
	return mux
}

func runtimeProblem(w http.ResponseWriter, err error) {
	code, message, status := "runtime.request_invalid", "local publisher request is invalid", 400
	switch {
	case errors.Is(err, clientruntime.ErrOwnerConflict):
		code, message, status = "runtime.owner_conflict", "another live app owns this service; stop it before starting another", 409
	case errors.Is(err, clientruntime.ErrRegistrationStale):
		code, message, status = "runtime.registration_stale", "app registration expired; prepare and register the listener again", 409
	case errors.Is(err, controlclient.ErrUnauthenticated):
		code, message, status = "runtime.authentication_required", "run tnl auth login, then start the app again", 401
	default:
		if _, definition, ok := failure.Describe(err); ok && definition.Class == failure.Unauthenticated {
			code, message, status = "runtime.authentication_required", "run tnl auth login, then start the app again", 401
		} else if _, ok := failure.Of(err); ok {
			presented := presentFailure(err)
			code, message, status = string(presented.reason), presented.message, 503
		}
	}
	privateprotocol.Write(w, status, privateprotocol.Problem{Code: code, Message: message})
}

func (a *appRuntime) publish(ctx context.Context, service clientruntime.Service, observe func(uint64, bool) error) (result error) {
	a.mu.Lock()
	preparation := a.prepared[service.RegistrationID]
	a.mu.Unlock()
	services, flags := preparation.services, preparation.flags
	project := preparation.project
	server := services.authenticated.ServerEndpoint
	group := projectIntegrationGroup(project.Project, services.namespace)
	tunnel, err := a.state.BeginTunnel(ctx, clientstate.BeginTunnelOptions{Command: clientstate.TunnelCommandDev, Server: server, Target: service.Target, Project: a.project.Root, Service: service.Name, IntegrationGroup: group})
	if err != nil {
		return err
	}
	ctx = tunnel.Context()
	defer func() {
		closeCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		result = errors.Join(result, tunnel.Finish(closeCtx, result))
	}()
	if err := tunnel.SetDevTarget(ctx, service.Framework, service.Target); err != nil {
		return err
	}
	output, err := newPublishOutput("human", "tnl", io.Discard, io.Discard, nil)
	if err != nil {
		return err
	}
	previewID, err := ensurePreview(ctx, a.state, services.state, services.routes, server, services.teamID, a.project.Root)
	if err != nil {
		return err
	}
	configuration := services.config(service.Target, preparation.policy.prefixes, flags.requestLimit())
	configuration.ControlURL = server
	configuration.BrowserLoginAvailable = services.authenticated.Discovery.BrowserLoginAvailable != nil && *services.authenticated.Discovery.BrowserLoginAvailable
	configuration.PreviewID, configuration.ProjectRoot, configuration.Service = previewID, a.project.Root, service.Name
	configuration.Feedback = project.Config.Feedback != nil && *project.Config.Feedback
	configuration.RequestInspection = flags.RequestInspection
	configuration.AdmitRequest = func(_ *http.Request, identity publisher.PublishRunIdentity) error {
		if !a.manager.Current(service.Name, service.RegistrationID, service.Target, identity.Number) {
			return diagnostic.Wrap(diagnostic.TargetUnavailable, clientruntime.ErrRegistrationStale)
		}
		return nil
	}
	recorder, err := newRequestRecorder(ctx, tunnel, a.project.Root, service.Name)
	if err != nil {
		return err
	}
	defer recorder.Close()
	configuration.ObserveRequest = requestObservation(recorder)
	configuration.Logf = func(_ string, _ ...any) {
		if ctx.Err() == nil {
			a.manager.RecordWarning(service.Name, service.RegistrationID, string(failure.TransportUnavailable))
		}
	}
	if project.Config.OAuth {
		origin, oauthServices, err := projectOAuthPublisher(ctx, a.state, project.Project, server, valueOrEmpty(project.Config.Team), services.authenticated)
		if err != nil {
			return err
		}
		stop := startOAuthIntegrationURL(ctx, a.state, oauthServices, origin, tunnel, output, nil)
		defer stop()
		configuration.ObserveResponse = integrationurls.Observer(a.state, server, origin.Hostname, group, tunnel.ID())
	}
	if len(project.Config.Webhooks) != 0 {
		stop := startWebhookIntegrationURL(ctx, a.state, services, project.Project, tunnel, service.Name, group, output, nil)
		defer stop()
	}
	for prefix, mount := range project.Config.Services[service.Name].Paths {
		configuration.Mounts = append(configuration.Mounts, localproxy.Mount{Prefix: prefix, StripPrefix: mount.StripPrefix, ResolveTarget: func() string {
			for _, candidate := range a.manager.Snapshot().Services {
				if candidate.Name == mount.Service && a.manager.Current(candidate.Name, candidate.RegistrationID, candidate.Target, 0) {
					return candidate.Target
				}
			}
			return ""
		}})
	}
	var probes sync.WaitGroup
	probeCtx, cancelProbes := context.WithCancel(ctx)
	defer func() { cancelProbes(); probes.Wait() }()
	configuration.Observe = func(event publisher.Event) error {
		if event.Type == publisher.EventPublicURLAssigned {
			preview, err := services.routes.AddPreviewPublicURL(ctx, previewID, event.PublicURLID)
			if err != nil {
				return err
			}
			if preview.Id != previewID || preview.TeamId != services.teamID || !slices.Contains(preview.PublicUrlIds, event.PublicURLID) {
				return failure.Wrap("associate preview", failure.ServerResponseInvalid, errors.New("preview omitted assigned public URL"))
			}
		}
		if err := handlePublisherEvent(ctx, tunnel, output, event); err != nil {
			return err
		}
		switch event.Type {
		case publisher.EventProvisioningStep:
			a.manager.SetProvisioningStage(service.Name, service.RegistrationID, event.PublishRunNumber, event.ProvisioningStage)
		case publisher.EventProvisioning, publisher.EventDraining:
			return observe(event.PublishRunNumber, false)
		case publisher.EventProvisioningStalled:
			a.manager.RecordWarning(service.Name, service.RegistrationID, string(diagnostic.ProvisioningStalled))
		case publisher.EventReady:
			if err := observe(event.PublishRunNumber, true); err != nil {
				return err
			}
			copy := service
			copy.PublicURL, copy.PublishRunNumber, copy.Routable = event.PublicURL, event.PublishRunNumber, true
			probes.Add(1)
			go func() { defer probes.Done(); a.check(probeCtx, copy) }()
		}
		return nil
	}
	if len(project.Config.Aliases) != 0 {
		stop := startProjectAliases(ctx, a.state, project, service.Name, valueOrEmpty(project.Config.Team), services, configuration, group, tunnel, output)
		defer stop()
	}
	return publisher.Run(ctx, configuration)
}

func (a *appRuntime) check(ctx context.Context, service clientruntime.Service) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	for attempt := 0; ctx.Err() == nil; attempt++ {
		observation := clientruntime.Probe(ctx, service, nil)
		if !a.manager.Observe(observation) || observation.Ready {
			return
		}
		timer := time.NewTimer(clientruntime.RetryDelay(attempt))
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}

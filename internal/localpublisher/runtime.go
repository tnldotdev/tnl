package localpublisher

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/tnldotdev/tnl/internal/clientauth"
	"github.com/tnldotdev/tnl/internal/clientruntime"
	"github.com/tnldotdev/tnl/internal/clientstate"
	"github.com/tnldotdev/tnl/internal/config"
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
	"github.com/tnldotdev/tnl/internal/publisherauth"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

type runtimeOptions struct {
	Directory     string
	StateDir      string
	App           bool
	Service       string
	AdHoc         bool
	NoTelemetry   bool
	RemoteScope   func(context.Context, projectconfig.Project, bool, bool, string) (localPublisherEndpoint, error)
	QueueSDKReady func(context.Context, *clientstate.Database, string, string, string, string)
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
	var project projectconfig.Project
	if os.Getenv("TNL_PUBLISHER_EXTERNAL") == "1" {
		root := directory
		if selection.Path != "" {
			root = filepath.Dir(selection.Path)
		}
		file, readErr := os.Open(filepath.Join(root, projectmeta.DirectoryName, projectmeta.JSONName))
		if readErr != nil {
			return projectConfiguration{}, "", failure.Wrap("read mounted project metadata", failure.ProjectConfigInvalid,
				errors.Join(readErr, errors.New("run tnl config generate on the host before starting the external publisher")))
		}
		defer file.Close()
		data, readErr := io.ReadAll(io.LimitReader(file, projectmeta.MaxFileBytes+1))
		if readErr != nil || len(data) > projectmeta.MaxFileBytes {
			return projectConfiguration{}, "", failure.Wrap("read mounted project metadata", failure.ProjectConfigInvalid,
				errors.Join(readErr, errors.New("run tnl config generate on the host before starting the external publisher")))
		}
		var metadata projectmeta.Metadata
		if err := json.Unmarshal(data, &metadata); err != nil || metadata.Worktree == nil {
			return projectConfiguration{}, "", failure.Wrap("read mounted project metadata", failure.ProjectConfigInvalid,
				errors.Join(err, errors.New("worktree label is missing from generated metadata")))
		}
		if err := metadata.Validate(); err != nil {
			return projectConfiguration{}, "", failure.Wrap("read mounted project metadata", failure.ProjectConfigInvalid, err)
		}
		project, err = projectconfig.ResolveForPublisher(ctx, selection, directory, salt, metadata.Worktree.Label)
	} else {
		project, err = projectconfig.Resolve(ctx, selection, directory, salt)
	}
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

func runtimeKey(project, state string) (string, error) {
	directory, err := clientstate.RuntimeDir(state)
	if err != nil {
		return "", failure.Wrap("open local publisher runtime directory", failure.ClientStateUnavailable, err)
	}
	return filepath.Join(directory, "app-"+clientruntime.Identity(project, filepath.Dir(directory))), nil
}

func runtimeAvailable(ctx context.Context, key string) bool {
	endpoint, err := readRuntimeTCPEndpoint(key)
	if err != nil {
		return false
	}
	request, _ := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.URL+"/v1/status", nil)
	request.Header.Set("Authorization", "Bearer "+endpoint.Credential)
	request.Close = true
	client := &http.Client{Timeout: 2 * time.Second, Transport: &http.Transport{DisableKeepAlives: true, Proxy: nil}}
	response, err := client.Do(request)
	if err != nil {
		return false
	}
	_, readErr := io.Copy(io.Discard, response.Body)
	closeErr := response.Body.Close()
	return readErr == nil && closeErr == nil && response.StatusCode == http.StatusOK
}

func runRuntimeEndpoint(ctx context.Context, options runtimeOptions, output io.Writer) error {
	project, state, err := runtimeProject(ctx, options)
	if err != nil {
		return err
	}
	key, err := runtimeKey(project.Root, state)
	if err != nil {
		return err
	}
	endpointPath := runtimeTCPEndpointPath(key)
	spawn := true
	if options.App && options.AdHoc || options.Service != "" && !options.App {
		return failure.Wrap("select local publisher credential", failure.InvalidCommand, errors.New("select one endpoint scope"))
	}
	if options.App {
		selected := options.Service
		var names []string
		for _, service := range configuredRuntimeServices(project) {
			if service.ServiceProtocol == "" {
				names = append(names, service.Name)
			}
		}
		if selected == "" && len(names) == 1 {
			selected = names[0]
		}
		if !slices.Contains(names, selected) {
			return failure.Wrap("select app credential", failure.ServiceNotConfigured, errors.New("select one configured app service"))
		}
		options.Service = selected
		endpointPath = runtimeAppEndpointPath(key, selected)
		if project.Config.Publisher == nil || project.Config.Publisher.Type == "local" {
			err = ensureAppPublisherEndpoint(ctx, key, selected)
		}
		if err != nil {
			return err
		}
	} else if options.AdHoc {
		endpointPath = runtimeAdHocEndpointPath(key)
	}
	if selection := project.Config.Publisher; selection != nil && selection.Type != "local" {
		spawn = false
		if options.RemoteScope == nil {
			return failure.Wrap("select external publisher", failure.ClientStateUnavailable, errors.New("publisher owner request is unavailable"))
		}
		credential, err := options.RemoteScope(ctx, project.Project, options.App, options.AdHoc, options.Service)
		if err != nil {
			return err
		}
		if err := writeRuntimeTCPEndpoint(endpointPath, credential); err != nil {
			return failure.Wrap("save external publisher endpoint", failure.ClientStateUnavailable, err)
		}
	}
	return json.NewEncoder(output).Encode(struct {
		Version int    `json:"version"`
		Path    string `json:"path"`
		Spawn   bool   `json:"spawn"`
	}{privateprotocol.Version, endpointPath, spawn})
}

type appPreparation struct {
	assignment  privateprotocol.Assignment
	services    publisherServices
	policy      resolvedIPPolicy
	flags       tunnelFlags
	framework   privateprotocol.Framework
	telemetry   string
	noTelemetry bool
	project     projectConfiguration
	named       bool
	resolve     func() string
}

type appRuntime struct {
	manager       *clientruntime.Manager
	adhoc         *clientruntime.AdHocManager
	project       projectConfiguration
	state         *clientstate.Database
	authHTTP      *http.Client
	noTelemetry   bool
	queueSDKReady func(context.Context, *clientstate.Database, string, string, string, string)
	mu            sync.Mutex
	prepareMu     sync.Mutex
	prepared      map[string]appPreparation
	ownersMu      sync.Mutex
	owners        map[string]*publisherauth.Owner
}

func (a *appRuntime) publisherOwner(auth *clientauth.Client, teamID string) (*publisherauth.Owner, error) {
	a.ownersMu.Lock()
	defer a.ownersMu.Unlock()
	if a.owners == nil {
		a.owners = make(map[string]*publisherauth.Owner)
	}
	key := auth.ServerEndpoint + "\x00" + teamID
	if owner := a.owners[key]; owner != nil {
		return owner, nil
	}
	owner, err := publisherauth.Interactive(auth, "local-publisher")
	if err == nil {
		a.owners[key] = owner
	}
	return owner, err
}

func (a *appRuntime) closeOwners(ctx context.Context) error {
	a.ownersMu.Lock()
	owners := make([]*publisherauth.Owner, 0, len(a.owners))
	for _, owner := range a.owners {
		owners = append(owners, owner)
	}
	clear(a.owners)
	a.ownersMu.Unlock()
	var result error
	for _, owner := range owners {
		result = errors.Join(result, owner.Close(ctx))
	}
	return result
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
		service := project.Config.Services[name]
		protocol := config.ServiceProtocol(effective.Publish)
		named := service.Target != nil && service.Target.Type != "app"
		if !named && protocol != "http" {
			continue
		}
		readiness := clientruntime.Readiness{Path: "/"}
		if protocol == "http" && effective.Readiness != nil {
			readiness.Path = effective.Readiness.Path
		}
		if named && protocol != "http" {
			readiness = clientruntime.Readiness{}
		}
		entry := clientruntime.Service{Name: name, Directory: project.RelativeServiceDirectories[name], Readiness: readiness}
		if named {
			entry.ServiceProtocol = protocol
			if effective.Publish != nil && effective.Publish.Target != nil {
				entry.Target = string(*effective.Publish.Target)
			}
		}
		services = append(services, entry)
	}
	slices.SortFunc(services, func(a, b clientruntime.Service) int { return strings.Compare(a.Name, b.Name) })
	return services
}

func runRuntimeServe(ctx context.Context, options runtimeOptions) (result error) {
	// the app process starts this worker. when it exits, the other registered
	// apps reconnect to a worker they own instead of relying on an orphan.
	parentPID := os.Getppid()
	project, root, err := runtimeProject(ctx, options)
	if err != nil {
		return err
	}
	key, err := runtimeKey(project.Root, root)
	if err != nil {
		return err
	}
	lock, err := filelock.Acquire(key+".lock", filelock.Nonblocking, os.Getuid())
	if errors.Is(err, filelock.ErrLocked) {
		return nil
	}
	if err != nil {
		return err
	}
	defer lock.Close()
	state, err := clientstate.Open(ctx, root)
	if err != nil {
		return err
	}
	defer state.Close()
	runtime := &appRuntime{project: project, state: state, noTelemetry: options.NoTelemetry, queueSDKReady: options.QueueSDKReady, prepared: map[string]appPreparation{}}
	defer func() {
		closeCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		result = errors.Join(result, runtime.closeOwners(closeCtx))
	}()
	runtime.manager, err = clientruntime.New(ctx, project.Root, root, configuredRuntimeServices(project), runtime.publish)
	if err != nil {
		return err
	}
	// external clients may live in another PID namespace. their leases, rather
	// than the publisher's process table, establish continued ownership.
	if selection := project.Config.Publisher; selection != nil && selection.Type != "local" {
		runtime.manager.Alive = func(pid int) bool { return pid > 0 }
	} else {
		runtime.manager.Alive = func(pid int) bool { return syscall.Kill(pid, 0) == nil }
	}
	defer runtime.manager.Close()
	runtime.adhoc = clientruntime.NewAdHocManager(ctx, runtime.publishAdHoc, runtime.manager.Alive, runtime.manager.BeginPreparation)
	defer runtime.adhoc.Close()
	listen := "127.0.0.1:0"
	external := false
	if selection := project.Config.Publisher; selection != nil && selection.Type != "local" {
		external = true
		listen = net.JoinHostPort("0.0.0.0", strconv.Itoa(*selection.ContainerPort))
		for _, service := range configuredRuntimeServices(project) {
			if service.ServiceProtocol != "" {
				continue
			}
			base := os.Getenv("TNL_PUBLISHER_APP_ENDPOINT_DIR")
			resolved, resolveErr := filepath.EvalSymlinks(base)
			if !filepath.IsAbs(base) || resolveErr != nil || pathInside(resolved, project.Root) {
				return failure.Wrap("start Docker publisher", failure.ProjectConfigInvalid,
					errors.New("set TNL_PUBLISHER_APP_ENDPOINT_DIR to private per-service volume mounts outside the project"))
			}
		}
	}
	tcpServer, tcpDone, err := startRuntimeTCPWithProjectOptions(key, runtime.handler(), listen, "", project.Config.Publisher, configuredRuntimeServices(project)...)
	if err != nil {
		return err
	}
	defer func() {
		_ = stopRuntimeTCP(context.Background(), tcpServer, key)
	}()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case err := <-tcpDone:
			return fmt.Errorf("serve local publisher TCP API: %w", err)
		case <-ticker.C:
			if !external && os.Getppid() != parentPID {
				return nil
			}
			if runtime.manager.Sweep(runtime.manager.Alive) && !external {
				return nil
			}
			runtime.adhoc.Sweep()
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

func (a *appRuntime) prepare(ctx context.Context, request privateprotocol.Prepare) (assignmentResult privateprotocol.Assignment, resultErr error) {
	finishPreparation := a.manager.BeginPreparation()
	defer finishPreparation()
	if request.Version != privateprotocol.Version || !privateprotocol.ValidOwner(request.Owner) || request.PID <= 0 || !request.Framework.Valid() {
		return privateprotocol.Assignment{}, failure.Wrap("prepare app", failure.ProjectConfigInvalid, errors.New("invalid app preparation"))
	}
	scope := localPublisherScopeFrom(ctx)
	project := a.project
	var directory string
	var err error
	if scope.kind == localScopeApp && a.project.Config.Publisher != nil && a.project.Config.Publisher.Type != "local" {
		// the app has a credential scoped to this project and service, but its
		// container may mount the project at a different absolute path.
		if !filepath.IsAbs(request.Directory) || strings.ContainsRune(request.Directory, 0) {
			return privateprotocol.Assignment{}, failure.Wrap("select app directory", failure.ProjectConfigInvalid, errors.New("app directory must be absolute"))
		}
	} else {
		directory, err = filepath.EvalSymlinks(request.Directory)
		if err != nil || !pathInside(directory, a.project.Root) {
			return privateprotocol.Assignment{}, failure.Wrap("select app directory", failure.ProjectConfigInvalid, errors.Join(err, errors.New("app directory is outside the project")))
		}
		project, _, err = runtimeProject(ctx, runtimeOptions{Directory: directory, StateDir: a.state.Root()})
		if err != nil {
			return privateprotocol.Assignment{}, err
		}
		if project.Root != a.project.Root {
			return privateprotocol.Assignment{}, failure.Wrap("select app project", failure.ProjectConfigInvalid, errors.New("app preparation selected another project"))
		}
	}
	name := request.Service
	if name == "" && scope.kind == localScopeApp {
		return privateprotocol.Assignment{}, failure.Wrap("select app service", failure.ServiceNotConfigured, errors.New("pass the configured app service name"))
	}
	if name == "" {
		for _, candidate := range project.Config.Services {
			if candidate.Target != nil && candidate.Target.Type == "app" {
				return privateprotocol.Assignment{}, failure.Wrap("select app service", failure.ServiceNotConfigured,
					errors.New("pass the configured service name to tnl.prepare"))
			}
		}
	}
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
	if target := project.Config.Services[name].Target; target != nil && target.Type != "app" {
		return privateprotocol.Assignment{}, failure.Wrap("select app service", failure.ServiceNotConfigured, errors.New("this service requires tnl publish instead of an app registration"))
	}
	if scope := localPublisherScopeFrom(ctx); scope.kind == localScopeApp && scope.service != name {
		return privateprotocol.Assignment{}, failure.Wrap("select app service", failure.ServiceNotConfigured, errors.New("app credential is scoped to another service"))
	}
	a.prepareMu.Lock()
	defer a.prepareMu.Unlock()
	if err := a.manager.Configure(configuredRuntimeServices(project)); err != nil {
		return privateprotocol.Assignment{}, err
	}
	resolver := newProjectMetadataResolver(a.state, project)
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
	flags := tunnelFlags{InspectionMode: config.InspectionSummary}
	applyTunnelConfiguration(&flags, effective.Tunnel)
	applyInspection(&flags, effective)
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
	assignment := privateprotocol.Assignment{Version: privateprotocol.Version, RegistrationID: "reg_" + strings.Repeat("0", 32), Service: name, Hostname: selected.Hostname, PublicURL: selected.URL, Project: metadata.Public(true)}
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
	a.prepared[id] = appPreparation{assignment: assignment, services: services, policy: policy, flags: flags, framework: request.Framework, project: project,
		telemetry: request.Owner + "\x00" + name, noTelemetry: request.TelemetryDisabled}
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
	mux.HandleFunc("POST /v1/ad-hoc/register", func(w http.ResponseWriter, r *http.Request) {
		var request privateprotocol.AdHocRegister
		if err := privateprotocol.Decode(w, r, &request); err != nil {
			runtimeProblem(w, err)
			return
		}
		status, err := a.adhoc.Register(request)
		if err != nil {
			runtimeProblem(w, err)
			return
		}
		privateprotocol.Write(w, http.StatusOK, status)
	})
	for _, operation := range []string{"status", "renew", "unregister"} {
		mux.HandleFunc("POST /v1/ad-hoc/"+operation, func(w http.ResponseWriter, r *http.Request) {
			var request privateprotocol.Registration
			if err := privateprotocol.Decode(w, r, &request); err != nil || request.Version != privateprotocol.Version {
				runtimeProblem(w, err)
				return
			}
			var err error
			switch operation {
			case "status":
				status, statusErr := a.adhoc.Status(request.RegistrationID, request.Owner)
				if statusErr == nil {
					privateprotocol.Write(w, http.StatusOK, status)
					return
				}
				err = statusErr
			case "renew":
				err = a.adhoc.Renew(request.RegistrationID, request.Owner)
			case "unregister":
				err = a.adhoc.Unregister(request.RegistrationID, request.Owner)
			}
			if err != nil {
				runtimeProblem(w, err)
				return
			}
			w.WriteHeader(http.StatusNoContent)
		})
	}
	mux.HandleFunc("GET /v1/status", func(w http.ResponseWriter, r *http.Request) {
		snapshot := a.manager.Snapshot()
		if probe := r.URL.Query().Get("probe"); probe != "" {
			if !naming.ValidServiceName(probe) {
				runtimeProblem(w, errors.New("only the project owner may check a configured service"))
				return
			}
			for index := range snapshot.Services {
				service := &snapshot.Services[index]
				if service.Name == probe && service.Registered && service.Routable && service.ServiceProtocol != "" && service.ServiceProtocol != "http" {
					service.Ready = clientruntime.ProbeTCP(r.Context(), service.PublicURL, service.ServiceProtocol,
						tcpVisitorTLSPassthrough(a.project, service.Name), nil) == nil
				}
			}
		}
		if scope := localPublisherScopeFrom(r.Context()); scope.kind != localScopeOwner {
			snapshot.Services = slices.DeleteFunc(snapshot.Services, func(service clientruntime.Service) bool {
				return scope.kind != localScopeApp || service.Name != scope.service
			})
		}
		privateprotocol.Write(w, 200, namedProjectSnapshot(snapshot))
	})
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
			if request.Version != privateprotocol.Version {
				runtimeProblem(w, errors.New("unsupported protocol"))
				return
			}
			var err error
			if scope := localPublisherScopeFrom(r.Context()); scope.kind == localScopeApp {
				a.mu.Lock()
				prepared, found := a.prepared[request.RegistrationID]
				a.mu.Unlock()
				if !found || prepared.assignment.Service != scope.service {
					runtimeProblem(w, clientruntime.ErrRegistrationStale)
					return
				}
			}
			switch operation {
			case "register":
				a.mu.Lock()
				preparation, found := a.prepared[request.RegistrationID]
				a.mu.Unlock()
				if !found {
					err = clientruntime.ErrRegistrationStale
				} else {
					target := request.Target
					target, err = a.registeredAppTarget(r.Context(), preparation.assignment.Service, target, request.BoundHost)
					if err == nil {
						err = a.manager.Register(request.RegistrationID, request.Owner, target, string(preparation.framework))
					}
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
	a.namedHandler(mux)
	a.publisherAuthHandler(mux)
	return mux
}

func (a *appRuntime) registeredAppTarget(ctx context.Context, service, target, boundHost string) (string, error) {
	publisher := a.project.Config.Publisher
	if publisher == nil || publisher.Type == "local" {
		return target, nil
	}
	origin, err := url.Parse(target)
	if err != nil || origin.Hostname() == "" || origin.Port() == "" || origin.User != nil || origin.Path != "" || origin.RawQuery != "" || origin.Fragment != "" ||
		(origin.Scheme != "http" && origin.Scheme != "https") {
		return "", failure.Wrap("register app listener", failure.ProjectConfigInvalid, errors.New("app target must be a canonical HTTP origin"))
	}
	if localPublisherScopeFrom(ctx).kind != localScopeApp || boundHost != "0.0.0.0" && boundHost != "::" {
		return "", failure.Wrap("register app listener", failure.ProjectConfigInvalid,
			errors.New("docker app must register with its service credential and listen on all container interfaces"))
	}
	if ip := net.ParseIP(origin.Hostname()); ip == nil || !ip.IsLoopback() {
		return "", failure.Wrap("register app listener", failure.ProjectConfigInvalid,
			errors.New("docker app must report its own bound listener port"))
	}
	if publisher.Compose == nil || !naming.ValidServiceName(service) {
		return "", failure.Wrap("register app listener", failure.ProjectConfigInvalid,
			errors.New("docker apps require a publisher in the same Compose project"))
	}
	return origin.Scheme + "://" + net.JoinHostPort(service, origin.Port()), nil
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
	server := services.Authenticated.ServerEndpoint
	group := ""
	command := clientstate.TunnelCommandDev
	if preparation.named {
		command = clientstate.TunnelCommandPublish
	}
	if service.ServiceProtocol == "" || service.ServiceProtocol == "http" {
		group = projectIntegrationGroup(project.Project, services.Namespace)
	}
	tunnel, err := a.state.BeginTunnel(ctx, clientstate.BeginTunnelOptions{
		Command: command, Server: server, Target: service.Target, Project: a.project.Root, Service: service.Name,
		ServiceProtocol: controlv1.PublicURLServiceProtocol(service.ServiceProtocol), IntegrationGroup: group,
	})
	if err != nil {
		return err
	}
	ctx = tunnel.Context()
	defer func() {
		closeCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		result = errors.Join(result, tunnel.Finish(closeCtx, result))
	}()
	if preparation.named {
		if err := a.manager.Started(service.RegistrationID, tunnel.ID()); err != nil {
			return err
		}
	} else {
		if err := tunnel.SetDevTarget(ctx, service.Framework, service.Target); err != nil {
			return err
		}
	}
	output := &publishOutput{}
	previewID := ""
	if group != "" {
		previewID, err = ensurePreview(ctx, a.state, services.State, services.Routes, server, services.TeamID, a.project.Root)
		if err != nil {
			return err
		}
	}
	traffic, err := flags.traffic()
	if err != nil {
		return failure.Wrap("validate traffic limits", failure.InvalidTunnelFlags, err)
	}
	services.Traffic = traffic
	owner, err := a.publisherOwner(services.Authenticated, services.TeamID)
	if err != nil {
		return err
	}
	services.RunControl = &publisherauth.RunControl{Client: services.Authenticated.PublisherControl, Owner: owner}
	configuration := services.config(service.Target, preparation.policy.prefixes, flags.limits(), traffic)
	configuration.ServiceProtocol = controlv1.PublicURLServiceProtocol(service.ServiceProtocol)
	configuration.ResolveTarget = preparation.resolve
	effective, err := project.EffectiveService(service.Name)
	if err != nil {
		return err
	}
	if effective.Publish != nil && effective.Publish.TargetCAFile != nil {
		configuration.TargetOptions, err = targetOptionsForCA(*effective.Publish.TargetCAFile, project.Root)
		if err != nil {
			return err
		}
	}
	if effective.Publish != nil {
		if effective.Publish.TargetTLS != nil {
			configuration.TargetTLS = *effective.Publish.TargetTLS
		}
		if effective.Publish.TargetTLSName != nil {
			configuration.TargetTLSName = *effective.Publish.TargetTLSName
		}
	}
	if effective.Tunnel != nil && effective.Tunnel.VisitorTLS != nil {
		configuration.VisitorTLSPassthrough = *effective.Tunnel.VisitorTLS == "passthrough"
	}
	configuration.ControlURL = server
	configuration.BrowserLoginAvailable = services.Authenticated.Discovery.BrowserLoginAvailable != nil && *services.Authenticated.Discovery.BrowserLoginAvailable
	configuration.PreviewID, configuration.ProjectRoot, configuration.Service = previewID, a.project.Root, service.Name
	configuration.Feedback = (service.ServiceProtocol == "" || service.ServiceProtocol == "http") && project.Config.Feedback != nil && *project.Config.Feedback
	configuration.InspectionMode = flags.InspectionMode
	configuration.AdmitRequest = func(_ *http.Request, identity publisher.PublishRunIdentity) error {
		if !a.manager.Current(service.Name, service.RegistrationID, service.Target, identity.Number) {
			return diagnostic.Wrap(diagnostic.TargetUnavailable, clientruntime.ErrRegistrationStale)
		}
		return nil
	}
	configuration.AdmitConnection = func(identity publisher.PublishRunIdentity) error {
		if !a.manager.Current(service.Name, service.RegistrationID, service.Target, identity.Number) {
			return diagnostic.Wrap(diagnostic.TargetUnavailable, clientruntime.ErrRegistrationStale)
		}
		return nil
	}
	recorder, err := newInspectionRecorder(ctx, tunnel, a.project.Root, service.Name, flags)
	if err != nil {
		return err
	}
	defer recorder.Close()
	configuration.ObserveRequest = httpObservation(recorder)
	if (service.ServiceProtocol == "mysql" || service.ServiceProtocol == "postgres") && !configuration.VisitorTLSPassthrough {
		configuration.ObserveDatabase = sqlObservation(recorder, flags.InspectionMode)
	}
	if service.ServiceProtocol == "redis" {
		configuration.ObserveRedis = redisObservation(recorder)
	}
	configuration.Logf = func(_ string, _ ...any) {
		if ctx.Err() == nil {
			a.manager.RecordWarning(service.Name, service.RegistrationID, string(failure.TransportUnavailable))
		}
	}
	if group != "" && project.Config.OAuth {
		origin, oauthServices, err := projectOAuthPublisher(ctx, a.state, project.Project, server, valueOrEmpty(project.Config.Team), services.Authenticated)
		if err != nil {
			return err
		}
		oauthOwner, err := a.publisherOwner(oauthServices.Authenticated, oauthServices.TeamID)
		if err != nil {
			return err
		}
		oauthServices.RunControl = &publisherauth.RunControl{Client: oauthServices.Authenticated.PublisherControl, Owner: oauthOwner}
		stop := startOAuthIntegrationURL(ctx, a.state, oauthServices, origin, tunnel, output, nil)
		defer stop()
		configuration.ObserveResponse = integrationurls.Observer(a.state, server, origin.Hostname, group, tunnel.ID())
	}
	if group != "" && len(project.Config.Webhooks) != 0 {
		stop := startWebhookIntegrationURL(ctx, a.state, services, project.Project, tunnel, service.Name, group, output, nil)
		defer stop()
	}
	for prefix, mount := range config.ServicePaths(project.Config.Services[service.Name]) {
		options := localproxy.TargetOptions{}
		mounted, err := project.EffectiveService(mount.Service)
		if err != nil {
			return err
		}
		if mounted.Publish != nil && mounted.Publish.TargetCAFile != nil {
			options, err = targetOptionsForCA(*mounted.Publish.TargetCAFile, project.Root)
			if err != nil {
				return err
			}
		}
		configuration.Mounts = append(configuration.Mounts, localproxy.Mount{Prefix: prefix, StripPrefix: mount.StripPrefix, Options: options, ResolveTarget: func() string {
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
		if event.Type == publisher.EventPublicURLAssigned && previewID != "" {
			preview, err := services.Routes.AddPreviewPublicURL(ctx, previewID, event.PublicURLID)
			if err != nil {
				return err
			}
			if preview.Id != previewID || preview.TeamId != services.TeamID || !slices.Contains(preview.PublicUrlIds, event.PublicURLID) {
				return failure.Wrap("associate preview", failure.ServerResponseInvalid, errors.New("preview omitted assigned public URL"))
			}
		}
		if err := RecordPublisherEvent(ctx, tunnel, event); err != nil {
			return err
		}
		if preparation.named {
			if err := a.manager.RecordPublication(service.RegistrationID, clientruntime.PublicationEvent{
				Type: string(event.Type), PublicURLID: event.PublicURLID, Hostname: event.Hostname,
				PublicURL: event.PublicURL, PublishRunNumber: event.PublishRunNumber,
				Transport: string(event.Transport), PolicyDenials: event.PolicyDenials,
			}); err != nil {
				return err
			}
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
			if !a.noTelemetry && !preparation.noTelemetry && a.queueSDKReady != nil {
				a.queueSDKReady(ctx, a.state, preparation.telemetry, "dev", server, service.Framework)
			}
			copy := service
			copy.PublicURL, copy.PublishRunNumber, copy.Routable = event.PublicURL, event.PublishRunNumber, true
			if service.ServiceProtocol == "" || service.ServiceProtocol == "http" {
				probes.Add(1)
				go func() { defer probes.Done(); a.check(probeCtx, copy) }()
			} else {
				probes.Add(1)
				go func() {
					defer probes.Done()
					a.checkTCP(probeCtx, copy, tcpVisitorTLSPassthrough(a.project, service.Name))
				}()
			}
		}
		return nil
	}
	if group != "" && len(project.Config.Aliases) != 0 {
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

func (a *appRuntime) checkTCP(ctx context.Context, service clientruntime.Service, passthrough bool) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	for attempt := 0; ctx.Err() == nil; attempt++ {
		err := clientruntime.ProbeTCP(ctx, service.PublicURL, service.ServiceProtocol, passthrough, nil)
		observation := clientruntime.Observation{
			RegistrationID: service.RegistrationID, PublishRunNumber: service.PublishRunNumber,
			CheckedAt: time.Now().UTC(), Ready: err == nil, Readiness: service.Readiness,
		}
		if err != nil {
			observation.Reason = "runtime.probe_failed"
		}
		if !a.manager.Observe(observation) || observation.Ready {
			return
		}
		timer := time.NewTimer(clientruntime.RetryDelay(attempt))
		select {
		case <-ctx.Done():
			timer.Stop()
		case <-timer.C:
		}
	}
}

package local

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/tnldotdev/tnl/internal/client/filelock"
	clientproject "github.com/tnldotdev/tnl/internal/client/project"
	"github.com/tnldotdev/tnl/internal/client/project/meta"
	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	clienttelemetry "github.com/tnldotdev/tnl/internal/client/telemetry"
	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/observability"
	"github.com/tnldotdev/tnl/internal/publisher"
	publisherapp "github.com/tnldotdev/tnl/internal/publisher/app"
	"github.com/tnldotdev/tnl/internal/publisher/invocation"
	"github.com/tnldotdev/tnl/internal/publisher/localapi"
	publisherprotocol "github.com/tnldotdev/tnl/internal/publisher/localapi/protocol"
	"github.com/tnldotdev/tnl/internal/publisher/target"
	api "github.com/tnldotdev/tnl/pkg/api/integrations/telemetry/v1"
)

type Options struct {
	Directory         string
	StateDir          string
	Snapshot          io.Reader
	TargetResolver    target.TargetResolver
	AttachPublication func(context.Context, publisherapp.Service, *publisher.Config) error
}

func ResolveProject(ctx context.Context, options Options) (clientproject.Project, string, error) {
	root := options.StateDir
	var err error
	if root == "" {
		root, err = clientstate.DefaultDir()
	}
	if err != nil {
		return clientproject.Project{}, "", err
	}
	directory, err := filepath.Abs(options.Directory)
	if err != nil {
		return clientproject.Project{}, "", err
	}
	directory, err = filepath.EvalSymlinks(directory)
	if err != nil {
		return clientproject.Project{}, "", err
	}
	if options.Snapshot != nil {
		project, err := clientproject.ReadSnapshot(options.Snapshot)
		if err != nil {
			return clientproject.Project{}, "", err
		}
		if project.Root != directory || project.Selection.Path != "" && filepath.Dir(project.Selection.Path) != directory {
			return clientproject.Project{}, "", errors.New("selected project snapshot belongs to another directory")
		}
		if err := config.ValidateTNL(project.Config); err != nil {
			return clientproject.Project{}, "", err
		}
		return project, root, nil
	}
	state, err := clientstate.Open(ctx, root)
	if err != nil {
		return clientproject.Project{}, "", err
	}
	defer state.Close()
	salt, err := state.WorktreeHashSalt(ctx)
	if err != nil {
		return clientproject.Project{}, "", err
	}
	selection, err := clientproject.SelectProjectConfig(ctx, directory, "", os.Getenv("TNL_CONFIG"), false)
	if err != nil {
		return clientproject.Project{}, "", err
	}
	project, err := clientproject.Resolve(ctx, selection, directory, salt)
	if err != nil {
		return clientproject.Project{}, "", err
	}
	if selected := os.Getenv("TNL_SERVER"); selected != "" {
		canonical, err := clientstate.CanonicalServer(selected)
		if err != nil {
			return clientproject.Project{}, "", err
		}
		project.Config.Server = &canonical
	}
	// leave implicit saved/hosted selection to the operation. only project
	// configuration and TNL_SERVER constrain an invocation's explicit server.
	return project, state.Root(), nil
}

func Available(ctx context.Context, endpoint publisherprotocol.Endpoint) bool {
	return publisherprotocol.Call(ctx, endpoint, "GET", "/v1/health", nil, nil) == nil
}

func EnsureOwner(ctx context.Context, project clientproject.Project, root string) (publisherprotocol.Endpoint, error) {
	path, err := publisherprotocol.DescriptorPath(root, project.Root)
	if err != nil {
		return publisherprotocol.Endpoint{}, err
	}
	_, digest, err := project.Snapshot()
	if err != nil {
		return publisherprotocol.Endpoint{}, err
	}
	selected := func(endpoint publisherprotocol.Endpoint) (publisherprotocol.Endpoint, error) {
		err := publisherprotocol.Call(ctx, endpoint, "GET", "/v1/health?configuration_digest="+digest, nil, nil)
		if err != nil {
			var response *publisherprotocol.ResponseError
			if errors.As(err, &response) && response.Code == string(failure.AppConfigurationConflict) {
				return publisherprotocol.Endpoint{}, failure.Wrap("reuse project owner", failure.AppConfigurationConflict, err)
			}
			return publisherprotocol.Endpoint{}, failure.Wrap("check project owner", failure.ClientStateUnavailable, err)
		}
		return endpoint, nil
	}
	if endpoint, err := publisherprotocol.ReadEndpoint(path); err == nil && Available(ctx, endpoint) {
		return selected(endpoint)
	}
	executable, err := os.Executable()
	if err != nil {
		return publisherprotocol.Endpoint{}, err
	}
	snapshot, _, err := project.Snapshot()
	if err != nil {
		return publisherprotocol.Endpoint{}, err
	}
	command := exec.Command(executable, "runtime", "serve", "--directory", project.Root, "--state-dir", root, "--snapshot-stdin")
	command.Env = observability.LaunchEnvironment(ctx, os.Environ())
	command.Stdin = bytes.NewReader(snapshot)
	if err := command.Start(); err != nil {
		return publisherprotocol.Endpoint{}, err
	}
	childDone := make(chan error, 1)
	go func() { childDone <- command.Wait() }()
	timer := time.NewTimer(15 * time.Second)
	defer timer.Stop()
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	for {
		if endpoint, err := publisherprotocol.ReadEndpoint(path); err == nil && Available(ctx, endpoint) {
			return selected(endpoint)
		}
		select {
		case err := <-childDone:
			if err != nil {
				return publisherprotocol.Endpoint{}, failure.Wrap("start project owner", failure.ClientStateUnavailable, err)
			}
			childDone = nil
		case <-ctx.Done():
			return publisherprotocol.Endpoint{}, ctx.Err()
		case <-timer.C:
			return publisherprotocol.Endpoint{}, failure.Wrap("start project owner", failure.ClientStateUnavailable, errors.New("local publisher did not start"))
		case <-ticker.C:
		}
	}
}

func OwnerEndpoint(ctx context.Context, options Options) (publisherprotocol.Endpoint, error) {
	project, root, err := ResolveProject(ctx, options)
	if err != nil {
		return publisherprotocol.Endpoint{}, err
	}
	return EnsureOwner(ctx, project, root)
}

func Endpoint(ctx context.Context, options Options, service, invocationID string) (publisherprotocol.Endpoint, error) {
	project, root, err := ResolveProject(ctx, options)
	if err != nil {
		return publisherprotocol.Endpoint{}, err
	}
	request := publisherprotocol.CapabilityRequest{Scope: "app"}
	if invocationID != "" {
		if service != "" {
			return publisherprotocol.Endpoint{}, errors.New("select a service or invocation")
		}
		request.Scope, request.InvocationId = "invocation", &invocationID
	} else {
		name, err := project.AppService(options.Directory, service)
		if err != nil {
			return publisherprotocol.Endpoint{}, err
		}
		request.Service = &name
	}
	owner, err := EnsureOwner(ctx, project, root)
	if err != nil {
		return publisherprotocol.Endpoint{}, err
	}
	var endpoint publisherprotocol.Endpoint
	if err := publisherprotocol.Call(ctx, owner, "POST", "/v1/capabilities", request, &endpoint); err != nil {
		return publisherprotocol.Endpoint{}, err
	}
	return endpoint, nil
}

type appPreparation struct {
	configuration     publisherapp.Configuration
	project           clientproject.Project
	framework         publisherprotocol.Framework
	assignment        publisherprotocol.Assignment
	invocation        *publisherprotocol.Invocation
	telemetryDisabled bool
}

type appRuntime struct {
	manager        *publisherapp.Manager
	workers        *publisherapp.Workers
	capabilities   *publisherprotocol.Capabilities
	project        clientproject.Project
	state          *clientstate.Database
	telemetry      atomic.Pointer[clienttelemetry.Collector]
	TargetResolver target.TargetResolver
	mu             sync.Mutex
	preparing      map[string]*appPreparationGate
	prepared       map[string]appPreparation
	// visitor and admission integration is attached before worker fencing wraps
	// callbacks. this applies equally to SDK, named CLI and invocation workers.
	AttachPublication func(context.Context, publisherapp.Service, *publisher.Config) error
}

type appPreparationGate struct {
	token chan struct{}
	users int
}

// serialize only competing preparations for the same service or invocation.
// no project-wide lock is held while authentication or discovery does I/O.
func (a *appRuntime) beginPreparation(ctx context.Context, name string) (func(), error) {
	a.mu.Lock()
	if a.preparing == nil {
		a.preparing = map[string]*appPreparationGate{}
	}
	gate := a.preparing[name]
	if gate == nil {
		gate = &appPreparationGate{token: make(chan struct{}, 1)}
		a.preparing[name] = gate
	}
	gate.users++
	a.mu.Unlock()
	releaseUser := func() {
		a.mu.Lock()
		defer a.mu.Unlock()
		gate.users--
		if gate.users == 0 {
			delete(a.preparing, name)
		}
	}
	select {
	case gate.token <- struct{}{}:
		return func() { <-gate.token; releaseUser() }, nil
	case <-ctx.Done():
		releaseUser()
		return nil, ctx.Err()
	}
}

func Serve(ctx context.Context, options Options) (result error) {
	ctx, finishStartup := observability.ClientOperation(ctx, "native.app.startup")
	defer func() { finishStartup(result) }()
	project, root, err := ResolveProject(ctx, options)
	if err != nil {
		return err
	}
	path, err := publisherprotocol.DescriptorPath(root, project.Root)
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
	capabilities, err := publisherprotocol.NewCapabilities("http://" + listener.Addr().String())
	if err != nil {
		return err
	}
	defer listener.Close()
	state, err := clientstate.Open(ctx, root)
	if err != nil {
		return err
	}
	defer state.Close()
	a := &appRuntime{project: project, state: state, capabilities: capabilities, prepared: map[string]appPreparation{}, TargetResolver: options.TargetResolver, AttachPublication: options.AttachPublication}
	// optional telemetry state opens independently; it cannot delay the local
	// API, app readiness, or a shared owner's other publications.
	telemetryCtx, cancelTelemetry := context.WithCancel(ctx)
	telemetryDone := make(chan struct{})
	go func() {
		defer close(telemetryDone)
		collector, err := clienttelemetry.New(telemetryCtx, clienttelemetry.Config{Root: root})
		if err != nil || collector == nil {
			return
		}
		a.telemetry.Store(collector)
		<-telemetryCtx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), clienttelemetry.RequestTimeout)
		defer cancel()
		collector.Close(shutdown)
	}()
	defer func() { cancelTelemetry(); <-telemetryDone }()
	a.workers = &publisherapp.Workers{Database: state, Configure: a.workerConfiguration, AutomaticReadiness: true}
	a.manager, err = publisherapp.New(observability.Independent(ctx), project.Root, state, publisherapp.ConfiguredServices(project), a.workers.Run)
	if err != nil {
		return err
	}
	a.workers.Manager = a.manager
	a.manager.Alive = func(pid int) bool { return syscall.Kill(pid, 0) == nil }
	defer func() {
		_, finish := observability.ClientOperation(observability.Independent(context.WithoutCancel(ctx)), "native.app.shutdown")
		a.manager.Close()
		finish(nil)
	}()
	// unregister joins the publication after draining its visitor streams.
	requestBase := observability.Independent(ctx)
	server := &http.Server{Handler: a.handler(), BaseContext: func(net.Listener) context.Context { return requestBase }, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 80 * time.Second, IdleTimeout: 10 * time.Second, MaxHeaderBytes: publisherprotocol.MaxBytes}
	done := make(chan error, 1)
	go func() { done <- server.Serve(listener) }()
	defer func() {
		shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdown)
		_ = server.Close()
	}()
	if err := publisherprotocol.WriteEndpoint(path, capabilities.Owner()); err != nil {
		return err
	}
	defer publisherprotocol.RemoveEndpoint(path, capabilities.Owner().OwnerId)
	finishStartup(nil)
	ctx = observability.Independent(ctx)
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
	return (&localapi.Server{Capabilities: a.capabilities, Manager: a.manager, Database: a.state, Project: a.project.Root, Prepare: a.prepare, RegisterContext: a.register, Acquire: a.acquire, Invocation: a.invocation, Check: a.workers.Check, ConfigurationDigest: func() (string, error) {
		_, digest, err := a.project.Snapshot()
		return digest, err
	}, AppService: func(name string) bool {
		service, found := a.project.Config.Services[name]
		return found && config.TargetType(service) == "app"
	}}).Handler()
}

func (a *appRuntime) register(ctx context.Context, request publisherprotocol.Registration) error {
	a.mu.Lock()
	preparation, found := a.prepared[request.RegistrationID]
	a.mu.Unlock()
	if !found {
		return publisherapp.ErrRegistrationStale
	}
	// retain the app's reported origin for renewal, but never treat its
	// hostname as a container address. the worker resolves the selected service.
	return a.manager.RegisterContext(ctx, request.RegistrationID, request.Owner, request.Target, string(preparation.framework))
}

func (a *appRuntime) prepare(ctx context.Context, request publisherprotocol.Prepare) (publisherprotocol.Assignment, error) {
	telemetryDisabled := request.TelemetryDisabled != nil && *request.TelemetryDisabled
	if request.Version != 1 || !publisherprotocol.ValidOwner(request.Owner) || request.PID <= 0 || !request.Framework.Valid() {
		return publisherprotocol.Assignment{}, errors.New("invalid app preparation")
	}
	name, err := a.project.AppService(request.Directory, request.Service)
	if err != nil {
		return publisherprotocol.Assignment{}, err
	}
	release, err := a.beginPreparation(ctx, name)
	if err != nil {
		return publisherprotocol.Assignment{}, err
	}
	defer release()
	finish := a.manager.BeginPreparation()
	defer finish()
	metadata, err := a.operations(a.project).Metadata(ctx)
	if err != nil {
		return publisherprotocol.Assignment{}, err
	}
	if err := meta.Write(ctx, a.project.Root, metadata); err != nil {
		return publisherprotocol.Assignment{}, err
	}
	selected := metadata.Services[name]
	id, err := a.manager.Reserve(name, request.Owner, request.PID, selected.URL)
	if err != nil {
		return publisherprotocol.Assignment{}, err
	}
	assignment := publisherprotocol.Assignment{Version: 1, RegistrationID: id, Service: name, Hostname: selected.Hostname, PublicURL: selected.URL, Project: metadata.Public(true)}
	a.mu.Lock()
	a.prepared[id] = appPreparation{project: a.project, framework: request.Framework, assignment: assignment, telemetryDisabled: telemetryDisabled}
	a.mu.Unlock()
	return assignment, nil
}

func (a *appRuntime) acquire(ctx context.Context, request publisherprotocol.Lease) (publisherprotocol.Registration, error) {
	telemetryDisabled := request.TelemetryDisabled != nil && *request.TelemetryDisabled
	_, digest, err := a.project.Snapshot()
	if err != nil {
		return publisherprotocol.Registration{}, err
	}
	if request.ConfigurationDigest != digest {
		return publisherprotocol.Registration{}, failure.Wrap("acquire configured service", failure.AppConfigurationConflict, publisherapp.ErrOwnerConflict)
	}
	release, err := a.beginPreparation(ctx, request.Service)
	if err != nil {
		return publisherprotocol.Registration{}, err
	}
	defer release()
	finish := a.manager.BeginPreparation()
	defer finish()
	resolved, err := target.ResolveTarget(ctx, a.project, request.Service, a.resolver())
	if err != nil {
		return publisherprotocol.Registration{}, failure.Wrap("resolve named service target", failure.InvalidTunnelFlags, err)
	}
	metadata, err := a.operations(a.project).Metadata(ctx)
	if err != nil {
		if _, classified := failure.ReasonOf(err); classified {
			return publisherprotocol.Registration{}, err
		}
		return publisherprotocol.Registration{}, failure.Wrap("resolve named service metadata", failure.ProjectConfigInvalid, err)
	}
	selected := metadata.Services[request.Service]
	address := selected.URL
	id, err := a.manager.Reserve(request.Service, request.Owner, request.Pid, address)
	if err != nil {
		return publisherprotocol.Registration{}, failure.Wrap("reserve named service", failure.ClientStateUnavailable, err)
	}
	a.mu.Lock()
	a.prepared[id] = appPreparation{project: a.project, telemetryDisabled: telemetryDisabled}
	a.mu.Unlock()
	registration := publisherprotocol.Registration{Version: 1, RegistrationID: id, Owner: request.Owner, Target: string(*resolved.Target)}
	if err := a.manager.RegisterContext(ctx, id, request.Owner, registration.Target, ""); err != nil {
		_ = a.manager.Unregister(id, request.Owner)
		return publisherprotocol.Registration{}, err
	}
	return registration, nil
}

func (a *appRuntime) workerConfiguration(ctx context.Context, service publisherapp.Service) (publisherapp.Configuration, error) {
	a.mu.Lock()
	preparation, found := a.prepared[service.RegistrationID]
	a.mu.Unlock()
	if !found {
		return publisherapp.Configuration{}, publisherapp.ErrRegistrationStale
	}
	var configuration publisherapp.Configuration
	var err error
	if definition, configured := preparation.project.Config.Services[service.Name]; configured && !config.IsPublicService(definition) {
		configuration, err = a.operations(preparation.project).ServiceConfiguration(ctx, service)
	} else if preparation.configuration.Publisher.Control != nil {
		configuration = preparation.configuration
	} else {
		configuration, err = a.operations(preparation.project).PublicConfiguration(ctx, service)
	}
	if err != nil {
		return publisherapp.Configuration{}, err
	}
	configuration.Telemetry = a.telemetry.Load()
	configuration.TelemetryDisabled = preparation.telemetryDisabled
	framework := api.PublicationReadyFramework(preparation.framework)
	if framework.Valid() {
		configuration.TelemetryFramework = framework
	} else if preparation.framework != "" {
		configuration.TelemetryFramework = api.PublicationReadyFrameworkOther
	}
	return configuration, nil
}

func (a *appRuntime) operations(project clientproject.Project) *invocation.ProjectRuntime {
	operations := invocation.NewProjectRuntime(project, a.state, a.manager, a.resolver())
	operations.AttachPublication = a.AttachPublication
	return operations
}

func (a *appRuntime) resolver() target.TargetResolver {
	if a.TargetResolver != nil {
		return a.TargetResolver
	}
	return target.Resolver{}
}

func valueOrEmpty(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}

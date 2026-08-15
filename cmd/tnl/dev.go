package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/tnldotdev/tnl/internal/clientstate"
	"github.com/tnldotdev/tnl/internal/diagnostic"
	"github.com/tnldotdev/tnl/internal/filelock"
	"github.com/tnldotdev/tnl/internal/localproxy"
	"github.com/tnldotdev/tnl/internal/projectconfig"
	"github.com/tnldotdev/tnl/internal/projectmeta"
	"github.com/tnldotdev/tnl/internal/publisher"
)

const (
	devProtocolVersion       = "1"
	devRegistrationWait      = 30 * time.Second
	devShutdownWait          = 5 * time.Second
	maxDevRequestBytes       = 16 << 10
	defaultDevStartupTimeout = 2 * time.Minute
)

type devCommand struct {
	openOptions    `embed:""`
	remoteFlags    `embed:""`
	tunnelFlags    `embed:""`
	Service        string        `arg:"" name:"service" optional:"" help:"Configured service name."`
	Command        []string      `kong:"-"`
	Port           int           `name:"port" help:"Port for the local service. Usually detected automatically."`
	StartupTimeout time.Duration `name:"startup-timeout" help:"Time to wait for the local service to start and report its target."`

	commandDir          string
	serverFromConfig    bool
	selectedTeam        string
	projectRoot         string
	project             projectConfiguration
	useMetadataHostname bool
}

type childExitError struct {
	code int
}

func (e *childExitError) Error() string { return fmt.Sprintf("command exited with status %d", e.code) }

func runDev(ctx context.Context, flags devCommand, stdin io.Reader, stdout, stderr io.Writer, reporters ...telemetryReporter) (result error) {
	telemetry := optionalTelemetryReporter(reporters)
	command, err := resolveDevCommand(flags.Command, flags.commandDir)
	if err != nil {
		return err
	}
	flags.Command = command
	if flags.Port < 0 || flags.Port > 65535 {
		return diagnostic.Wrap(diagnostic.TargetInvalid, errors.New("port must be between 1 and 65535"))
	}
	if flags.StartupTimeout <= 0 || flags.StartupTimeout > 10*time.Minute {
		return errors.New("startup timeout must be greater than zero and at most 10 minutes")
	}

	forcedTarget := ""
	if flags.Port != 0 {
		forcedTarget, err = localproxy.NormalizeTarget(strconv.Itoa(flags.Port))
		if err != nil {
			return err
		}
	}
	if flags.projectRoot == "" {
		flags.projectRoot, err = currentProjectRoot(ctx)
		if err != nil {
			return err
		}
	}
	serverURL, state, err := resolveServer(ctx, flags.StateDir, flags.ServerURL)
	if err != nil {
		return err
	}
	defer state.Close()
	if flags.project.Root == "" {
		worktree, resolveErr := projectconfig.ResolveWorktree(ctx, flags.projectRoot)
		if resolveErr != nil {
			return fmt.Errorf("resolve development worktree: %w", resolveErr)
		}
		salt, saltErr := state.WorktreeHashSalt(ctx)
		if saltErr != nil {
			return saltErr
		}
		flags.project = projectConfiguration{
			Project: projectconfig.Project{
				Root: flags.projectRoot, Worktree: projectconfig.ApplyWorktreeHashSalt(worktree, salt),
				ServiceDirectories: map[string]string{}, RelativeServiceDirectories: map[string]string{},
			},
		}
	}
	metadataResolver := newProjectMetadataResolver(state, flags.project, stdin, stderr, "tnl dev")
	if err := metadataResolver.LoadFallbackServer(ctx); err != nil {
		return err
	}
	if !flags.project.Found() {
		flags.project.Config.Server = &serverURL
		if flags.selectedTeam != "" {
			flags.project.Config.Team = &flags.selectedTeam
		}
		metadataResolver.project = flags.project
	}
	authenticated, err := authenticatePublisher(ctx, state, serverURL, flags.AccessToken, "tnl dev", stdin, stderr)
	if err != nil {
		return err
	}
	metadataResolver.Seed(serverURL, authenticated)
	metadata, err := metadataResolver.Generate(ctx)
	if err != nil {
		return err
	}
	if flags.project.Found() {
		if err := projectmeta.Write(flags.project.Root, metadata); err != nil {
			return err
		}
	}
	if flags.useMetadataHostname {
		if service, found := metadata.Services[flags.Service]; found {
			flags.Host = service.Hostname
		}
	}
	allowedIPPrefixes, currentIP, err := resolveIPPolicy(ctx, authenticated.Control, flags.AllowIP, flags.AllowAllIPs)
	if err != nil {
		return err
	}
	services, err := preparePublisherServices(
		ctx, state, serverURL, flags.Host, flags.Subdomain, flags.selectedTeam, flags.Ephemeral, authenticated,
	)
	if err != nil {
		return err
	}
	tunnel, err := state.BeginTunnel(ctx, clientstate.BeginTunnelOptions{
		Command: clientstate.TunnelCommandDev, Server: serverURL, Target: forcedTarget,
		Project: flags.projectRoot, Service: flags.Service,
	})
	if err != nil {
		return err
	}
	ctx = tunnel.Context()
	defer func() {
		if cause := context.Cause(ctx); cause != nil && (result == nil || errors.Is(result, context.Canceled)) {
			result = cause
		}
		finishCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		result = errors.Join(result, tunnel.Finish(finishCtx, result))
	}()

	bootstrap, err := newDevBootstrap(ctx, forcedTarget, flags.projectRoot, flags.Service)
	if err != nil {
		return err
	}
	defer bootstrap.Close()

	child, err := startDevProcess(flags.Command, devEnvironment(bootstrap, flags.Port), stdin, stdout, stderr, flags.commandDir)
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, child.Stop(devShutdownWait)) }()

	assignment := devConfigurationResponse{
		Protocol: 1, TunnelID: tunnel.ID(), Service: nullableService(flags.Service),
		MemberNamespace: services.memberNamespace, Hostname: services.hostname,
		PublicURL: "https://" + services.hostname,
		Project:   runtimeProjectMetadata(metadata, flags.Service, services.memberNamespace, services.hostname),
	}
	var configuration *devConfigurationRequest
	target := forcedTarget
	targetIsReady := false
	var targetReady <-chan error
	var cancelTargetReady context.CancelFunc
	var lateConfiguration <-chan devConfigurationResult
	if target == "" {
		registrationTimeout := min(flags.StartupTimeout, devRegistrationWait)
		configurationCtx, cancelConfiguration := context.WithTimeout(ctx, registrationTimeout)
		configured := make(chan devConfigurationResult, 1)
		go func() {
			configuration, err := bootstrap.Configuration(configurationCtx)
			configured <- devConfigurationResult{configuration: configuration, err: err}
		}()
		select {
		case <-child.Done():
			cancelConfiguration()
			return childResult(child.Err())
		case configuredResult := <-configured:
			cancelConfiguration()
			if configuredResult.err != nil {
				if errors.Is(configuredResult.err, context.DeadlineExceeded) {
					return diagnostic.WrapMessage(
						diagnostic.FrameworkRegistrationTimeout,
						"development server did not connect to tnl; configure @tnldotdev/tnl/next or @tnldotdev/tnl/vite, or use --port",
						configuredResult.err,
					)
				}
				return configuredResult.err
			}
			configuration = &configuredResult.configuration
		case <-ctx.Done():
			cancelConfiguration()
			return context.Cause(ctx)
		}
	} else {
		configured := make(chan devConfigurationResult, 1)
		go func() {
			configuration, err := bootstrap.Configuration(ctx)
			configured <- devConfigurationResult{configuration: configuration, err: err}
		}()
		startupCtx, cancelStartup := context.WithTimeout(ctx, flags.StartupTimeout)
		cancelTargetReady = cancelStartup
		defer cancelTargetReady()
		ready := make(chan error, 1)
		targetReady = ready
		go func() { ready <- localproxy.WaitForTarget(startupCtx, target) }()
		select {
		case <-child.Done():
			return childResult(child.Err())
		case configuredResult := <-configured:
			cancelTargetReady()
			targetReady = nil
			if configuredResult.err != nil {
				return configuredResult.err
			}
			configuration = &configuredResult.configuration
		case err := <-targetReady:
			cancelTargetReady()
			if err != nil {
				if errors.Is(err, context.DeadlineExceeded) {
					return diagnostic.WrapMessage(
						diagnostic.TargetUnavailable,
						fmt.Sprintf("development server did not listen on %s before the startup timeout", target),
						err,
					)
				}
				return err
			}
			targetIsReady = true
			lateConfiguration = configured
		case <-ctx.Done():
			return context.Cause(ctx)
		}
	}

	framework := ""
	completeConfiguration := func(configuration devConfigurationRequest) (string, error) {
		bootstrap.Resolve(assignment, nil)
		targetCtx, cancelTarget := context.WithTimeout(ctx, flags.StartupTimeout)
		reported, err := waitForDevTarget(targetCtx, bootstrap, child)
		cancelTarget()
		if err != nil {
			if errors.Is(err, context.DeadlineExceeded) {
				return "", diagnostic.WrapMessage(
					diagnostic.FrameworkRegistrationTimeout,
					"development server did not report its listening target before the startup timeout",
					err,
				)
			}
			return "", err
		}
		if err := tunnel.SetDevTarget(ctx, configuration.Framework, reported.Target); err != nil {
			return "", err
		}
		return reported.Target, nil
	}
	if configuration != nil {
		framework = configuration.Framework
		target, err = completeConfiguration(*configuration)
		if err != nil {
			return err
		}
	}

	var frameworkDone <-chan devFrameworkResult
	if lateConfiguration != nil {
		done := make(chan devFrameworkResult, 1)
		frameworkDone = done
		go func() {
			configuredResult := <-lateConfiguration
			if configuredResult.err != nil {
				done <- devFrameworkResult{err: configuredResult.err}
				return
			}
			reportedTarget, err := completeConfiguration(configuredResult.configuration)
			done <- devFrameworkResult{
				framework: configuredResult.configuration.Framework,
				target:    reportedTarget,
				err:       err,
			}
		}()
	}

	if !targetIsReady {
		if targetReady == nil {
			startupCtx, cancelStartup := context.WithTimeout(ctx, flags.StartupTimeout)
			defer cancelStartup()
			ready := make(chan error, 1)
			targetReady = ready
			go func() { ready <- localproxy.WaitForTarget(startupCtx, target) }()
		}
		select {
		case <-child.Done():
			return childResult(child.Err())
		case err := <-targetReady:
			if err != nil {
				if errors.Is(err, context.DeadlineExceeded) {
					return diagnostic.WrapMessage(
						diagnostic.TargetUnavailable,
						fmt.Sprintf("development server did not listen on %s before the startup timeout", target),
						err,
					)
				}
				return err
			}
		case <-ctx.Done():
			return context.Cause(ctx)
		}
	}
	output, err := newPublishOutput("human", "tnl dev", stdout, stderr, browserOpener(flags.Open))
	if err != nil {
		return err
	}
	output.setFramework(framework)
	if err := output.starting(tunnel.ID(), target); err != nil {
		return err
	}
	if currentIP != "" {
		if err := output.currentIP(currentIP); err != nil {
			return err
		}
	}
	publishCtx, cancelPublish := context.WithCancel(ctx)
	defer cancelPublish()
	publishDone := make(chan error, 1)
	go func() {
		publisherConfig := services.config(target, allowedIPPrefixes)
		publisherConfig.Logf = output.logf
		publisherConfig.Observe = withTelemetryObserver(telemetry, "dev", serverURL, telemetryFramework(framework), func(event publisher.Event) error {
			return handlePublisherEvent(publishCtx, tunnel, output, event)
		})
		publishDone <- publisher.Run(publishCtx, publisherConfig)
	}()

	for {
		select {
		case configuredResult := <-frameworkDone:
			frameworkDone = nil
			if configuredResult.err != nil {
				cancelPublish()
				<-publishDone
				return configuredResult.err
			}
			if configuredResult.target != target {
				cancelPublish()
				<-publishDone
				return diagnostic.Wrap(
					diagnostic.TargetMismatch,
					errors.New("development target changed after publishing started"),
				)
			}
			framework = configuredResult.framework
			output.setFramework(framework)
		case <-child.Done():
			cancelPublish()
			publishErr := <-publishDone
			if err := childResult(child.Err()); err != nil {
				return err
			}
			if publishErr != nil && !errors.Is(publishErr, context.Canceled) {
				return publishErr
			}
			return nil
		case err := <-publishDone:
			if ctx.Err() != nil && errors.Is(err, context.Canceled) {
				return context.Cause(ctx)
			}
			return err
		case <-ctx.Done():
			cancelPublish()
			<-publishDone
			return context.Cause(ctx)
		}
	}
}

type devConfigurationResult struct {
	configuration devConfigurationRequest
	err           error
}

type devFrameworkResult struct {
	framework string
	target    string
	err       error
}

type devTargetResult struct {
	target devTargetRequest
	err    error
}

func waitForDevTarget(ctx context.Context, bootstrap *devBootstrap, child *devProcess) (devTargetRequest, error) {
	targeted := make(chan devTargetResult, 1)
	go func() {
		target, err := bootstrap.Target(ctx)
		targeted <- devTargetResult{target: target, err: err}
	}()
	select {
	case <-child.Done():
		if err := childResult(child.Err()); err != nil {
			return devTargetRequest{}, err
		}
		return devTargetRequest{}, errors.New("development server command exited before target registration")
	case result := <-targeted:
		return result.target, result.err
	case <-ctx.Done():
		return devTargetRequest{}, context.Cause(ctx)
	}
}

type devBootstrap struct {
	socket         string
	lock           *filelock.Lock
	forcedPort     string
	server         *http.Server
	done           chan struct{}
	closing        chan struct{}
	configurations chan devConfigurationRequest
	targets        chan devTargetResult
	resolved       chan struct{}

	mu               sync.Mutex
	configuration    *devConfigurationRequest
	target           *devTargetRequest
	targetErr        error
	assignment       devConfigurationResponse
	configurationErr error
	serveErr         error
	resolveOnce      sync.Once
	closeOnce        sync.Once
	closeErr         error
}

type devConfigurationRequest struct {
	Protocol  int    `json:"protocol"`
	Framework string `json:"framework"`
}

type devConfigurationResponse struct {
	Protocol        int                        `json:"protocol"`
	TunnelID        string                     `json:"tunnelID"`
	Service         *string                    `json:"service"`
	MemberNamespace string                     `json:"memberNamespace"`
	Hostname        string                     `json:"hostname"`
	PublicURL       string                     `json:"publicURL"`
	Project         projectmeta.PublicMetadata `json:"project"`
}

func nullableService(service string) *string {
	if service == "" {
		return nil
	}
	return &service
}

func runtimeProjectMetadata(
	metadata projectmeta.Metadata,
	service, memberNamespace, hostname string,
) projectmeta.PublicMetadata {
	project := metadata.Public(true)
	if service == "" {
		project.MemberNamespace = memberNamespace
		return project
	}
	project.Services[service] = projectmeta.Service{
		MemberNamespace: memberNamespace,
		Hostname:        hostname,
		URL:             "https://" + hostname,
	}
	return project
}

type devTargetRequest struct {
	Protocol  int    `json:"protocol"`
	Framework string `json:"framework"`
	Target    string `json:"target"`
}

func newDevBootstrap(ctx context.Context, forcedTarget, projectRoot string, services ...string) (*devBootstrap, error) {
	forcedPort := ""
	if forcedTarget != "" {
		var err error
		forcedTarget, err = localproxy.NormalizeTarget(forcedTarget)
		if err != nil {
			return nil, err
		}
		_, forcedPort, err = net.SplitHostPort(strings.TrimPrefix(forcedTarget, "http://"))
		if err != nil {
			return nil, fmt.Errorf("read forced development target port: %w", err)
		}
	}
	if projectRoot == "" {
		cwd, err := os.Getwd()
		if err != nil {
			return nil, fmt.Errorf("resolve development worktree: %w", err)
		}
		worktree, err := projectconfig.ResolveWorktree(ctx, cwd)
		if err != nil {
			return nil, fmt.Errorf("resolve development worktree: %w", err)
		}
		projectRoot = worktree.Root
	}
	service := ""
	if len(services) != 0 {
		service = services[0]
	}
	dir, err := devRuntimeDirectory()
	if err != nil {
		return nil, err
	}
	stem := "dev-" + devSocketDigest(projectRoot, service)
	lock, err := acquireDevLock(filepath.Join(dir, stem+".lock"))
	if err != nil {
		return nil, err
	}
	cleanup := func() {
		_ = lock.Close()
	}
	bootstrap := &devBootstrap{
		socket: filepath.Join(dir, stem+".sock"), lock: lock,
		forcedPort: forcedPort,
		done:       make(chan struct{}), closing: make(chan struct{}),
		configurations: make(chan devConfigurationRequest, 1), targets: make(chan devTargetResult, 1),
		resolved: make(chan struct{}),
	}
	if info, statErr := os.Lstat(bootstrap.socket); statErr == nil {
		if info.Mode()&os.ModeSocket == 0 {
			cleanup()
			return nil, errors.New("development session socket path is occupied by a non-socket file")
		}
		if err := os.Remove(bootstrap.socket); err != nil {
			cleanup()
			return nil, fmt.Errorf("remove stale development session socket: %w", err)
		}
	} else if !errors.Is(statErr, os.ErrNotExist) {
		cleanup()
		return nil, fmt.Errorf("inspect development session socket: %w", statErr)
	}
	listener, err := net.Listen("unix", bootstrap.socket)
	if err != nil {
		cleanup()
		return nil, fmt.Errorf("listen on development session socket: %w", err)
	}
	if err := os.Chmod(bootstrap.socket, 0o600); err != nil {
		_ = listener.Close()
		_ = os.Remove(bootstrap.socket)
		cleanup()
		return nil, fmt.Errorf("secure development session socket: %w", err)
	}
	bootstrap.server = &http.Server{
		Handler:           http.HandlerFunc(bootstrap.handle),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       5 * time.Second,
		WriteTimeout:      10 * time.Minute,
		IdleTimeout:       5 * time.Second,
		MaxHeaderBytes:    8 << 10,
	}
	go func() {
		err := bootstrap.server.Serve(listener)
		if errors.Is(err, http.ErrServerClosed) || errors.Is(err, net.ErrClosed) {
			err = nil
		}
		bootstrap.mu.Lock()
		bootstrap.serveErr = err
		bootstrap.mu.Unlock()
		close(bootstrap.done)
	}()
	return bootstrap, nil
}

func devSocketDigest(projectRoot, service string) string {
	digest := sha256.Sum256([]byte(projectRoot + "\x00" + service))
	return hex.EncodeToString(digest[:8])
}

func devRuntimeDirectory() (string, error) {
	base := os.Getenv("XDG_RUNTIME_DIR")
	if base == "" {
		base = os.TempDir()
	}
	dir := filepath.Join(base, fmt.Sprintf("tnl-%d", os.Getuid()))
	if err := os.Mkdir(dir, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
		return "", fmt.Errorf("create development runtime directory: %w", err)
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return "", fmt.Errorf("inspect development runtime directory: %w", err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.IsDir() || info.Mode().Perm() != 0o700 || stat.Uid != uint32(os.Getuid()) {
		return "", errors.New("development runtime directory must be a user-owned directory with mode 0700")
	}
	return dir, nil
}

func acquireDevLock(path string) (*filelock.Lock, error) {
	lock, err := filelock.Acquire(path, filelock.Nonblocking, os.Getuid())
	if errors.Is(err, filelock.ErrLocked) {
		return nil, errors.New("another tnl dev is already running for this project service")
	}
	if err != nil {
		return nil, fmt.Errorf("lock development session: %w", err)
	}
	return lock, nil
}

func removeDevSocket(path string) error {
	err := os.Remove(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

func (b *devBootstrap) Close() error {
	if b == nil {
		return nil
	}
	b.closeOnce.Do(func() {
		close(b.closing)
		err := b.server.Close()
		<-b.done
		b.mu.Lock()
		serveErr := b.serveErr
		b.mu.Unlock()
		b.closeErr = errors.Join(
			err, serveErr, removeDevSocket(b.socket),
			b.lock.Close(),
		)
	})
	return b.closeErr
}

func (b *devBootstrap) Configuration(ctx context.Context) (devConfigurationRequest, error) {
	select {
	case configuration := <-b.configurations:
		return configuration, nil
	case <-b.done:
		b.mu.Lock()
		err := b.serveErr
		b.mu.Unlock()
		if err == nil {
			return devConfigurationRequest{}, errors.New("development session socket closed before configuration")
		}
		return devConfigurationRequest{}, fmt.Errorf("serve development session socket: %w", err)
	case <-ctx.Done():
		return devConfigurationRequest{}, ctx.Err()
	}
}

func (b *devBootstrap) Target(ctx context.Context) (devTargetRequest, error) {
	select {
	case result := <-b.targets:
		return result.target, result.err
	case <-b.done:
		b.mu.Lock()
		err := b.serveErr
		b.mu.Unlock()
		if err == nil {
			return devTargetRequest{}, errors.New("development session socket closed before target registration")
		}
		return devTargetRequest{}, fmt.Errorf("serve development session socket: %w", err)
	case <-ctx.Done():
		return devTargetRequest{}, ctx.Err()
	}
}

func (b *devBootstrap) Resolve(assignment devConfigurationResponse, err error) {
	b.resolveOnce.Do(func() {
		b.mu.Lock()
		b.assignment = assignment
		b.configurationErr = err
		b.mu.Unlock()
		close(b.resolved)
	})
}

func resolveDevCommand(command []string, directories ...string) ([]string, error) {
	if len(command) > 0 && command[0] == "--" {
		command = command[1:]
	}
	if len(command) == 0 {
		return nil, nil
	}
	path := ""
	var err error
	if filepath.Base(command[0]) == command[0] {
		directory := ""
		if len(directories) != 0 {
			directory = directories[0]
		}
		localPath, pathErr := filepath.Abs(filepath.Join(directory, "node_modules", ".bin", command[0]))
		if pathErr == nil {
			path, err = exec.LookPath(localPath)
		}
	}
	if path == "" {
		path, err = exec.LookPath(command[0])
	}
	if err != nil {
		return nil, fmt.Errorf("find development server command %q: %w", command[0], err)
	}
	resolved := append([]string(nil), command...)
	resolved[0] = path
	return resolved, nil
}

func (b *devBootstrap) handle(response http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost || (request.URL.Path != "/v1/configure" && request.URL.Path != "/v1/target") {
		http.NotFound(response, request)
		return
	}
	contentType, _, err := mime.ParseMediaType(request.Header.Get("Content-Type"))
	if err != nil || contentType != "application/json" {
		http.Error(response, "content type must be application/json", http.StatusUnsupportedMediaType)
		return
	}
	if request.URL.Path == "/v1/configure" {
		b.handleConfiguration(response, request)
		return
	}
	b.handleTarget(response, request)
}

func (b *devBootstrap) handleConfiguration(response http.ResponseWriter, request *http.Request) {
	var configuration devConfigurationRequest
	decoder := json.NewDecoder(io.LimitReader(request.Body, maxDevRequestBytes+1))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&configuration); err != nil {
		http.Error(response, "invalid development configuration", http.StatusBadRequest)
		return
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		http.Error(response, "invalid development configuration", http.StatusBadRequest)
		return
	}
	if configuration.Protocol != 1 || !validFrameworkName(configuration.Framework) {
		http.Error(response, "invalid development configuration", http.StatusBadRequest)
		return
	}
	b.mu.Lock()
	first := b.configuration == nil
	if !first && !reflect.DeepEqual(*b.configuration, configuration) {
		b.mu.Unlock()
		http.Error(response, "different development settings are already registered", http.StatusConflict)
		return
	}
	if first {
		configured := configuration
		b.configuration = &configured
	}
	b.mu.Unlock()
	if first {
		select {
		case b.configurations <- configuration:
		case <-b.closing:
			http.Error(response, "development session is closing", http.StatusServiceUnavailable)
			return
		}
	}

	select {
	case <-b.resolved:
		b.mu.Lock()
		assignment := b.assignment
		configurationErr := b.configurationErr
		b.mu.Unlock()
		if configurationErr != nil {
			http.Error(response, configurationErr.Error(), http.StatusInternalServerError)
			return
		}
		response.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(response).Encode(assignment); err != nil {
			return
		}
	case <-b.closing:
		http.Error(response, "development session closed before configuration completed", http.StatusServiceUnavailable)
	case <-request.Context().Done():
		return
	}
}

func (b *devBootstrap) handleTarget(response http.ResponseWriter, request *http.Request) {
	var targetRequest devTargetRequest
	decoder := json.NewDecoder(io.LimitReader(request.Body, maxDevRequestBytes+1))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&targetRequest); err != nil {
		http.Error(response, "invalid target registration", http.StatusBadRequest)
		return
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		http.Error(response, "invalid target registration", http.StatusBadRequest)
		return
	}
	if targetRequest.Protocol != 1 || !validFrameworkName(targetRequest.Framework) {
		http.Error(response, "invalid target registration", http.StatusBadRequest)
		return
	}
	target, err := localproxy.NormalizeTarget(targetRequest.Target)
	if err != nil {
		http.Error(response, "invalid target registration", http.StatusBadRequest)
		return
	}
	targetRequest.Target = target

	b.mu.Lock()
	if b.configuration == nil {
		b.mu.Unlock()
		http.Error(response, "development target was registered before configuration", http.StatusConflict)
		return
	}
	if b.configuration.Framework != targetRequest.Framework {
		b.mu.Unlock()
		http.Error(response, "target framework does not match development configuration", http.StatusConflict)
		return
	}
	if b.targetErr != nil {
		b.mu.Unlock()
		http.Error(response, "development target registration already failed", http.StatusConflict)
		return
	}
	first := b.target == nil
	if !first && !reflect.DeepEqual(*b.target, targetRequest) {
		b.mu.Unlock()
		http.Error(response, "a different development target is already registered", http.StatusConflict)
		return
	}
	if first && b.forcedPort != "" {
		_, registeredPort, splitErr := net.SplitHostPort(strings.TrimPrefix(target, "http://"))
		if splitErr != nil || registeredPort != b.forcedPort {
			mismatch := diagnostic.Wrap(
				diagnostic.TargetMismatch,
				fmt.Errorf("development server registered port %s instead of port %s required by tnl dev", registeredPort, b.forcedPort),
			)
			b.targetErr = mismatch
			b.mu.Unlock()
			select {
			case b.targets <- devTargetResult{err: mismatch}:
			case <-b.closing:
				http.Error(response, "development session is closing", http.StatusServiceUnavailable)
				return
			}
			http.Error(response, "registered target does not use the port forced by tnl dev --port", http.StatusConflict)
			return
		}
	}
	if first {
		registered := targetRequest
		b.target = &registered
	}
	b.mu.Unlock()
	if first {
		select {
		case b.targets <- devTargetResult{target: targetRequest}:
		case <-b.closing:
			http.Error(response, "development session is closing", http.StatusServiceUnavailable)
			return
		}
	}
	response.WriteHeader(http.StatusNoContent)
}

func validFrameworkName(value string) bool {
	if len(value) == 0 || len(value) > 32 {
		return false
	}
	for _, character := range value {
		if character < 'a' || character > 'z' {
			return false
		}
	}
	return true
}

func devEnvironment(bootstrap *devBootstrap, port int) []string {
	replacements := map[string]string{
		"TNL_DEV_PROTOCOL": devProtocolVersion,
		"TNL_DEV_SOCKET":   bootstrap.socket,
	}
	if port != 0 {
		replacements["TNL_DEV_PORT"] = strconv.Itoa(port)
		replacements["PORT"] = strconv.Itoa(port)
	}
	blocked := map[string]struct{}{
		"TNL_ACCESS_TOKEN": {}, "TNL_LOGIN_TOKEN": {}, "TNL_PROJECT_RUNTIME": {}, "TNL_TUNNEL_ID": {},
		"TNL_PUBLIC_HOSTNAME": {}, "TNL_PUBLIC_URL": {},
	}
	for key := range replacements {
		blocked[key] = struct{}{}
	}
	environment := make([]string, 0, len(os.Environ())+len(replacements))
	for _, entry := range os.Environ() {
		key, _, _ := strings.Cut(entry, "=")
		if _, found := blocked[key]; !found && !strings.HasPrefix(key, "TNL_DEV_") {
			environment = append(environment, entry)
		}
	}
	for key, value := range replacements {
		environment = append(environment, key+"="+value)
	}
	return environment
}

type devProcess struct {
	command *exec.Cmd
	done    chan struct{}
	stop    chan time.Duration
	err     error

	stopOnce   sync.Once
	cleanupErr error
}

func startDevProcess(command, environment []string, stdin io.Reader, stdout, stderr io.Writer, directories ...string) (*devProcess, error) {
	process := &devProcess{done: make(chan struct{}), stop: make(chan time.Duration, 1)}
	if len(command) == 0 {
		return process, nil
	}
	process.command = exec.Command(command[0], command[1:]...)
	if len(directories) != 0 {
		process.command.Dir = directories[0]
	}
	process.command.Env = environment
	process.command.Stdin = stdin
	process.command.Stdout = stdout
	process.command.Stderr = stderr
	process.command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := process.command.Start(); err != nil {
		return nil, fmt.Errorf("start development server command: %w", err)
	}
	processGroupID := process.command.Process.Pid
	leaderExited, watcherErr := watchDevProcessExit(processGroupID)
	go process.run(processGroupID, leaderExited, watcherErr)
	if watcherErr != nil {
		<-process.done
		return nil, process.cleanupErr
	}
	return process, nil
}

func (p *devProcess) Done() <-chan struct{} { return p.done }

func (p *devProcess) Err() error {
	<-p.done
	return p.err
}

func (p *devProcess) run(processGroupID int, leaderExited <-chan error, watcherSetupErr error) {
	if watcherSetupErr != nil {
		p.cleanupErr = errors.Join(
			fmt.Errorf("watch development server command: %w", watcherSetupErr),
			signalDevProcessGroup(processGroupID, syscall.SIGKILL),
		)
	} else {
		select {
		case watcherErr := <-leaderExited:
			p.cleanupErr = errors.Join(
				devProcessWatcherError(watcherErr),
				signalDevProcessGroup(processGroupID, syscall.SIGKILL),
			)
		case timeout := <-p.stop:
			p.cleanupErr = signalDevProcessGroup(processGroupID, syscall.SIGTERM)
			timer := time.NewTimer(timeout)
			select {
			case watcherErr := <-leaderExited:
				if !timer.Stop() {
					<-timer.C
				}
				p.cleanupErr = errors.Join(
					p.cleanupErr,
					devProcessWatcherError(watcherErr),
					signalDevProcessGroup(processGroupID, syscall.SIGKILL),
				)
			case <-timer.C:
				p.cleanupErr = errors.Join(
					p.cleanupErr,
					signalDevProcessGroup(processGroupID, syscall.SIGKILL),
				)
			}
		}
	}
	p.err = p.command.Wait()
	close(p.done)
}

func devProcessWatcherError(err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("watch development server command: %w", err)
}

func signalDevProcessGroup(processGroupID int, signal syscall.Signal) error {
	err := syscall.Kill(-processGroupID, signal)
	if err == nil || errors.Is(err, syscall.ESRCH) {
		return nil
	}
	return fmt.Errorf("send %s to development server process group: %w", signal, err)
}

func (p *devProcess) Stop(timeout time.Duration) error {
	if p == nil || p.command == nil || p.command.Process == nil {
		return nil
	}
	p.stopOnce.Do(func() {
		p.stop <- timeout
	})
	<-p.done
	return p.cleanupErr
}

func childResult(err error) error {
	if err == nil {
		return nil
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		code := exitErr.ExitCode()
		if code < 1 || code > 255 {
			code = 1
		}
		return &childExitError{code: code}
	}
	return fmt.Errorf("wait for development server command: %w", err)
}

package main

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/tnldotdev/tnl/internal/authorization"
	"github.com/tnldotdev/tnl/internal/clientauth"
	"github.com/tnldotdev/tnl/internal/clientstate"
	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/localproxy"
	"github.com/tnldotdev/tnl/internal/publisher"
	"github.com/tnldotdev/tnl/pkg/protocol/serverv1"
	"tailscale.com/tailcfg"
)

const (
	devProtocolVersion  = "1"
	devRegistrationWait = 30 * time.Second
	devShutdownWait     = 5 * time.Second
	maxDevRequestBytes  = 16 << 10
)

type devCommand struct {
	openOptions    `embed:""`
	Command        []string      `arg:"" name:"command" passthrough:"" help:"Development server command and arguments."`
	Port           int           `name:"port" help:"Literal loopback target port; normally registered by a framework integration."`
	StartupTimeout time.Duration `name:"startup-timeout" default:"2m" help:"Maximum time for target registration and startup."`
	ServerURL      string        `name:"server" env:"TNL_SERVER" help:"tnl server HTTPS origin; defaults to the selected server or https://control.tnl.dev."`
	AccessToken    string        `name:"access-token" env:"TNL_ACCESS_TOKEN" help:"Server access token; defaults to the saved login."`
	Name           string        `name:"name" env:"TNL_NAME" help:"Requested public name; omit for a fresh temporary name."`
	StateDir       string        `name:"state-dir" env:"TNL_STATE_DIR" type:"path" help:"Directory for persistent route state."`
}

type childExitError struct {
	code int
}

func (e *childExitError) Error() string { return fmt.Sprintf("command exited with status %d", e.code) }

func runDev(ctx context.Context, flags devCommand, stdin io.Reader, stdout, stderr io.Writer, reporters ...telemetryReporter) (result error) {
	telemetry := optionalTelemetryReporter(reporters)
	command, err := resolveDevCommand(flags.Command)
	if err != nil {
		return err
	}
	flags.Command = command
	if flags.Port < 0 || flags.Port > 65535 {
		return errors.New("port must be between 1 and 65535")
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

	bootstrap, err := newDevBootstrap(forcedTarget)
	if err != nil {
		return err
	}
	defer bootstrap.Close()

	child, err := startDevProcess(flags.Command, devEnvironment(bootstrap, flags.Port), stdin, stdout, stderr)
	if err != nil {
		return err
	}
	defer child.Stop(devShutdownWait)

	var configuration *devConfigurationRequest
	target := forcedTarget
	targetIsReady := false
	var targetReady <-chan error
	var cancelTargetReady context.CancelFunc
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
					return errors.New("development server did not connect to tnl; install and configure @tnldotdev/next or @tnldotdev/vite, or use --port")
				}
				return configuredResult.err
			}
			configuration = &configuredResult.configuration
		case <-ctx.Done():
			cancelConfiguration()
			return context.Cause(ctx)
		}
	} else {
		startupCtx, cancelStartup := context.WithTimeout(ctx, flags.StartupTimeout)
		cancelTargetReady = cancelStartup
		defer cancelTargetReady()
		ready := make(chan error, 1)
		targetReady = ready
		go func() { ready <- localproxy.WaitForTarget(startupCtx, target) }()
		select {
		case <-child.Done():
			return childResult(child.Err())
		case configured := <-bootstrap.configurations:
			cancelTargetReady()
			targetReady = nil
			configuration = &configured
		case err := <-targetReady:
			cancelTargetReady()
			if err != nil {
				if errors.Is(err, context.DeadlineExceeded) {
					return fmt.Errorf("development server did not listen on %s before the startup timeout", target)
				}
				return err
			}
			targetIsReady = true
		case <-ctx.Done():
			return context.Cause(ctx)
		}
	}

	configurationResolved := configuration == nil
	defer func() {
		if !configurationResolved {
			bootstrap.Resolve(devConfigurationResponse{}, errors.New("tnl dev could not configure the tunnel"))
		}
	}()

	options := devTunnelOptions{}
	framework := ""
	if configuration != nil {
		options = configuration.Options
		framework = configuration.Framework
	}
	serverValue := optionValue(options.Server)
	if flags.ServerURL != "" {
		serverValue = flags.ServerURL
	}
	name := optionValue(options.Name)
	if flags.Name != "" {
		name = flags.Name
	}
	allowedIPPrefixes, err := authorization.CanonicalizeIPPrefixes(options.AllowIP)
	if err != nil {
		return fmt.Errorf("invalid tnl dev allowIP: %w", err)
	}

	serverURL, state, err := resolveServer(ctx, flags.StateDir, serverValue)
	if err != nil {
		return err
	}
	defer state.Close()
	tunnel, err := state.BeginTunnel(ctx, clientstate.BeginTunnelOptions{
		Command: clientstate.TunnelCommandDev, Server: serverURL, Target: target,
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
	if framework != "" && target != "" {
		if err := tunnel.SetDevTarget(ctx, framework, target); err != nil {
			return err
		}
	}
	authenticated, err := clientauth.Authenticate(ctx, clientauth.Config{
		CoreEndpoint: serverURL, State: state, AccessToken: flags.AccessToken,
		Diagnostics: stderr, LoginToken: loginTokenPrompt(stdin, stderr),
	})
	if err != nil {
		return err
	}
	currentIP := ""
	if options.AllowCurrentIP {
		current, err := authenticated.Core.ClientIP(ctx)
		if err != nil {
			return fmt.Errorf("read current IP: %w", err)
		}
		address, err := netip.ParseAddr(current.Ip)
		if err != nil || address.Zone() != "" {
			return errors.New("server returned an invalid current IP")
		}
		currentIP = address.Unmap().String()
		allowedIPPrefixes, err = authorization.CanonicalizeIPPrefixes(append(allowedIPPrefixes, currentIP))
		if err != nil {
			return fmt.Errorf("combine allowed IP prefixes: %w", err)
		}
	}
	publisherState, err := state.Server(ctx, serverURL)
	if err != nil {
		return err
	}
	capabilities := authenticated.CoreCapabilities
	names, namingCapabilities, err := namingAPI(authenticated)
	if err != nil {
		return err
	}
	if capabilities.Transport.Type != serverv1.Tailcat || capabilities.Transport.Version != serverv1.TransportCapabilitiesVersionN1 {
		return errors.New("server does not support tailcat transport version 1")
	}
	if capabilities.HostnameSuffix == "" || capabilities.MaximumSubdomainDepth != 8 {
		return errors.New("server does not support the required naming contract")
	}
	if capabilities.Acme == nil || capabilities.Acme.AcmeProfile == "" {
		return errors.New("server does not support automatic certificates")
	}
	hostname, err := addPublishHostname(ctx, names, name, namingCapabilities)
	if err != nil {
		return err
	}
	routes, err := routeAPI(authenticated)
	if err != nil {
		return err
	}

	if configuration != nil {
		bootstrap.Resolve(devConfigurationResponse{
			Protocol: 1, TunnelID: tunnel.ID(), Hostname: hostname,
			PublicURL: "https://" + hostname,
		}, nil)
		configurationResolved = true
	}

	if target == "" {
		targetCtx, cancelTarget := context.WithTimeout(ctx, flags.StartupTimeout)
		reported, err := waitForDevTarget(targetCtx, bootstrap, child)
		cancelTarget()
		if err != nil {
			if errors.Is(err, context.DeadlineExceeded) {
				return errors.New("development server did not report its listening port before the startup timeout")
			}
			return err
		}
		target, err = localproxy.NormalizeTarget(strconv.Itoa(reported.Port))
		if err != nil {
			return err
		}
		if err := tunnel.SetDevTarget(ctx, framework, target); err != nil {
			return err
		}
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
					return fmt.Errorf("development server did not listen on %s before the startup timeout", target)
				}
				return err
			}
		case <-ctx.Done():
			return context.Cause(ctx)
		}
	}
	if err := bootstrap.Close(); err != nil {
		return err
	}

	output, err := newPublishOutput("human", stdout, stderr, browserOpener(flags.Open))
	if err != nil {
		return err
	}
	if err := output.starting(tunnel.ID(), target); err != nil {
		return err
	}
	if currentIP != "" {
		if err := output.currentIP(currentIP); err != nil {
			return err
		}
	}
	logger := log.New(stderr, "tnl: ", 0)
	publishCtx, cancelPublish := context.WithCancel(ctx)
	defer cancelPublish()
	publishDone := make(chan error, 1)
	go func() {
		publishDone <- publisher.Run(publishCtx, publisher.Config{
			Server: routes, Hostname: hostname, Target: target,
			AllowedIPPrefixes: allowedIPPrefixes,
			State:             publisherState, ACMEProfile: capabilities.Acme.AcmeProfile,
			RelayRegion: capabilities.Transport.RelayRegion, Logf: logger.Printf,
			LoadRegions: func(ctx context.Context) (map[string]*tailcfg.DERPRegion, error) {
				relayMap, err := authenticated.Core.RelayMap(ctx)
				if err != nil {
					return nil, fmt.Errorf("read server relay map: %w", err)
				}
				return config.DecodeRelayRegions(relayMap)
			},
			Observe: withTelemetryObserver(telemetry, "dev", serverURL, telemetryFramework(framework), func(event publisher.Event) error {
				switch event.Type {
				case publisher.EventRoute:
					return tunnel.SetRoute(publishCtx, event.RouteID, event.Hostname)
				case publisher.EventProvisioning:
					return tunnel.SetProvisioning(publishCtx, event.Version)
				case publisher.EventReady:
					if err := tunnel.SetReady(publishCtx, event.PublicURL, event.Version); err != nil {
						return err
					}
					return output.ready(event.PublicURL, event.Version)
				case publisher.EventDraining:
					return tunnel.SetDraining(context.WithoutCancel(publishCtx))
				}
				return nil
			}),
		})
	}()

	select {
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

type devConfigurationResult struct {
	configuration devConfigurationRequest
	err           error
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
	dir            string
	socket         string
	token          string
	forcedTarget   string
	server         *http.Server
	done           chan struct{}
	closing        chan struct{}
	configurations chan devConfigurationRequest
	targets        chan devTargetRequest
	resolved       chan struct{}

	mu               sync.Mutex
	configuration    *devConfigurationRequest
	target           *devTargetRequest
	assignment       devConfigurationResponse
	configurationErr error
	serveErr         error
	resolveOnce      sync.Once
	closeOnce        sync.Once
	closeErr         error
}

type devTunnelOptions struct {
	Server         *string  `json:"server,omitempty"`
	Name           *string  `json:"name,omitempty"`
	AllowIP        []string `json:"allowIP,omitempty"`
	AllowCurrentIP bool     `json:"allowCurrentIP,omitempty"`
}

type devConfigurationRequest struct {
	Protocol  int              `json:"protocol"`
	Framework string           `json:"framework"`
	Options   devTunnelOptions `json:"options"`
}

type devConfigurationResponse struct {
	Protocol  int    `json:"protocol"`
	TunnelID  string `json:"tunnelID"`
	Hostname  string `json:"hostname"`
	PublicURL string `json:"publicURL"`
}

type devTargetRequest struct {
	Protocol  int    `json:"protocol"`
	Framework string `json:"framework"`
	Port      int    `json:"port"`
}

func newDevBootstrap(forcedTarget string) (*devBootstrap, error) {
	// Unix socket paths are short on macOS, so avoid potentially deep custom state paths.
	dir, err := os.MkdirTemp("", "tnl-dev-")
	if err != nil {
		return nil, fmt.Errorf("create development session directory: %w", err)
	}
	cleanup := func() { _ = os.RemoveAll(dir) }
	if err := os.Chmod(dir, 0o700); err != nil {
		cleanup()
		return nil, fmt.Errorf("secure development session directory: %w", err)
	}
	var material [32]byte
	if _, err := rand.Read(material[:]); err != nil {
		cleanup()
		return nil, fmt.Errorf("generate development session token: %w", err)
	}
	bootstrap := &devBootstrap{
		dir: dir, socket: filepath.Join(dir, "control.sock"), token: hex.EncodeToString(material[:]),
		forcedTarget: forcedTarget,
		done:         make(chan struct{}), closing: make(chan struct{}),
		configurations: make(chan devConfigurationRequest, 1), targets: make(chan devTargetRequest, 1),
		resolved: make(chan struct{}),
	}
	listener, err := net.Listen("unix", bootstrap.socket)
	if err != nil {
		cleanup()
		return nil, fmt.Errorf("listen on development session socket: %w", err)
	}
	if err := os.Chmod(bootstrap.socket, 0o600); err != nil {
		_ = listener.Close()
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
		b.closeErr = errors.Join(err, serveErr, os.RemoveAll(b.dir))
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
	case target := <-b.targets:
		return target, nil
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

func resolveDevCommand(command []string) ([]string, error) {
	if len(command) > 0 && command[0] == "--" {
		command = command[1:]
	}
	if len(command) == 0 {
		return nil, errors.New("development server command is required after --")
	}
	path, err := exec.LookPath(command[0])
	if err != nil && filepath.Base(command[0]) == command[0] {
		localPath, pathErr := filepath.Abs(filepath.Join("node_modules", ".bin", command[0]))
		if pathErr == nil {
			path, err = exec.LookPath(localPath)
		}
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
	wantAuthorization := "Bearer " + b.token
	gotAuthorization := request.Header.Get("Authorization")
	if len(gotAuthorization) != len(wantAuthorization) || subtle.ConstantTimeCompare([]byte(gotAuthorization), []byte(wantAuthorization)) != 1 {
		http.Error(response, "unauthorized", http.StatusUnauthorized)
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
	if err := validateDevTunnelOptions(configuration.Options); err != nil {
		http.Error(response, err.Error(), http.StatusBadRequest)
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
		configured.Options.AllowIP = append([]string(nil), configuration.Options.AllowIP...)
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
	if targetRequest.Protocol != 1 || !validFrameworkName(targetRequest.Framework) ||
		targetRequest.Port < 1 || targetRequest.Port > 65535 {
		http.Error(response, "invalid target registration", http.StatusBadRequest)
		return
	}
	target, err := localproxy.NormalizeTarget(strconv.Itoa(targetRequest.Port))
	if err != nil {
		http.Error(response, "invalid target registration", http.StatusBadRequest)
		return
	}
	if b.forcedTarget != "" && b.forcedTarget != target {
		http.Error(response, "target port does not match tnl dev --port", http.StatusConflict)
		return
	}

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
	first := b.target == nil
	if !first && !reflect.DeepEqual(*b.target, targetRequest) {
		b.mu.Unlock()
		http.Error(response, "a different development target is already registered", http.StatusConflict)
		return
	}
	if first {
		registered := targetRequest
		b.target = &registered
	}
	b.mu.Unlock()
	if first {
		select {
		case b.targets <- targetRequest:
		case <-b.closing:
			http.Error(response, "development session is closing", http.StatusServiceUnavailable)
			return
		}
	}
	response.WriteHeader(http.StatusNoContent)
}

func validateDevTunnelOptions(options devTunnelOptions) error {
	if options.Server != nil && (*options.Server == "" || len(*options.Server) > 2048) {
		return errors.New("tnl server must be a non-empty HTTPS origin")
	}
	if options.Name != nil && (*options.Name == "" || len(*options.Name) > 253) {
		return errors.New("tnl name must be a non-empty hostname")
	}
	if len(options.AllowIP) > 64 {
		return errors.New("tnl allowIP accepts at most 64 entries")
	}
	for _, value := range options.AllowIP {
		if value == "" || len(value) > 128 {
			return errors.New("tnl allowIP entries must be non-empty IP addresses or prefixes")
		}
	}
	return nil
}

func optionValue(value *string) string {
	if value == nil {
		return ""
	}
	return *value
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
		"TNL_DEV_TOKEN":    bootstrap.token,
	}
	if port != 0 {
		replacements["TNL_DEV_PORT"] = strconv.Itoa(port)
		replacements["PORT"] = strconv.Itoa(port)
	}
	blocked := map[string]struct{}{
		"TNL_ACCESS_TOKEN": {}, "TNL_TUNNEL_ID": {},
		"TNL_PUBLIC_HOSTNAME": {}, "TNL_PUBLIC_URL": {},
	}
	for key := range replacements {
		blocked[key] = struct{}{}
	}
	environment := make([]string, 0, len(os.Environ())+len(replacements))
	for _, entry := range os.Environ() {
		key, _, _ := strings.Cut(entry, "=")
		if _, found := blocked[key]; !found {
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
	err     error
}

func startDevProcess(command, environment []string, stdin io.Reader, stdout, stderr io.Writer) (*devProcess, error) {
	process := &devProcess{done: make(chan struct{})}
	process.command = exec.Command(command[0], command[1:]...)
	process.command.Env = environment
	process.command.Stdin = stdin
	process.command.Stdout = stdout
	process.command.Stderr = stderr
	process.command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := process.command.Start(); err != nil {
		return nil, fmt.Errorf("start development server command: %w", err)
	}
	go func() {
		process.err = process.command.Wait()
		close(process.done)
	}()
	return process, nil
}

func (p *devProcess) Done() <-chan struct{} { return p.done }

func (p *devProcess) Err() error {
	<-p.done
	return p.err
}

func (p *devProcess) Stop(timeout time.Duration) error {
	if p == nil || p.command == nil || p.command.Process == nil {
		return nil
	}
	pid := p.command.Process.Pid
	signalErr := syscall.Kill(-pid, syscall.SIGTERM)
	if errors.Is(signalErr, syscall.ESRCH) {
		signalErr = nil
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-p.done:
		return signalErr
	case <-timer.C:
		killErr := syscall.Kill(-pid, syscall.SIGKILL)
		if errors.Is(killErr, syscall.ESRCH) {
			killErr = nil
		}
		<-p.done
		return errors.Join(signalErr, killErr)
	}
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

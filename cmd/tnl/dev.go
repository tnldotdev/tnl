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
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

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
	maxDevRequestBytes  = 1024
)

type devCommand struct {
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

func runDev(ctx context.Context, flags devCommand, stdin io.Reader, stdout, stderr io.Writer) error {
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

	serverURL, _, err := resolveServer(flags.StateDir, flags.ServerURL)
	if err != nil {
		return err
	}
	state, err := openClientState(flags.StateDir, serverURL)
	if err != nil {
		return err
	}
	client, err := authenticatedClient(serverURL, flags.AccessToken, state)
	if err != nil {
		return err
	}
	capabilities, err := client.Capabilities(ctx)
	if err != nil {
		return fmt.Errorf("read server capabilities: %w", err)
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
	hostname, err := addPublishHostname(ctx, client, flags.Name, capabilities)
	if err != nil {
		return err
	}

	target := ""
	if flags.Port != 0 {
		target, err = localproxy.NormalizeTarget(strconv.Itoa(flags.Port))
		if err != nil {
			return err
		}
	}
	bootstrap, err := newDevBootstrap(target)
	if err != nil {
		return err
	}
	defer bootstrap.Close()

	child, err := startDevProcess(flags.Command, devEnvironment(bootstrap, hostname, flags.Port), stdin, stdout, stderr)
	if err != nil {
		return err
	}
	defer child.Stop(devShutdownWait)

	startupCtx, cancelStartup := context.WithTimeout(ctx, flags.StartupTimeout)
	defer cancelStartup()
	if target == "" {
		registrationTimeout := min(flags.StartupTimeout, devRegistrationWait)
		registrationCtx, cancelRegistration := context.WithTimeout(startupCtx, registrationTimeout)
		registered := make(chan devTargetResult, 1)
		go func() {
			target, err := bootstrap.Target(registrationCtx)
			registered <- devTargetResult{target: target, err: err}
		}()
		select {
		case <-child.Done():
			cancelRegistration()
			return childResult(child.Err())
		case result := <-registered:
			cancelRegistration()
			if result.err != nil {
				if errors.Is(result.err, context.DeadlineExceeded) {
					return errors.New("development server did not register a target; install its tnl integration or use --port")
				}
				return result.err
			}
			target = result.target
		case <-ctx.Done():
			cancelRegistration()
			return ctx.Err()
		}
	}

	targetReady := make(chan error, 1)
	go func() { targetReady <- localproxy.WaitForTarget(startupCtx, target) }()
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
		return ctx.Err()
	}
	cancelStartup()

	output, err := newPublishOutput("human", stdout, stderr)
	if err != nil {
		return err
	}
	logger := log.New(stderr, "tnl: ", 0)
	publishCtx, cancelPublish := context.WithCancel(ctx)
	defer cancelPublish()
	publishDone := make(chan error, 1)
	go func() {
		publishDone <- publisher.Run(publishCtx, publisher.Config{
			Server: client, Hostname: hostname, Target: target,
			State: state, ACMEProfile: capabilities.Acme.AcmeProfile,
			RelayRegion: capabilities.Transport.RelayRegion, Logf: logger.Printf,
			LoadRegions: func(ctx context.Context) (map[string]*tailcfg.DERPRegion, error) {
				relayMap, err := client.RelayMap(ctx)
				if err != nil {
					return nil, fmt.Errorf("read server relay map: %w", err)
				}
				return config.DecodeRelayRegions(relayMap)
			},
			OnSessionReady: output.ready,
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
			return ctx.Err()
		}
		return err
	case <-ctx.Done():
		cancelPublish()
		<-publishDone
		return ctx.Err()
	}
}

type devTargetResult struct {
	target string
	err    error
}

type devBootstrap struct {
	dir     string
	socket  string
	token   string
	server  *http.Server
	done    chan struct{}
	targets chan string

	mu        sync.Mutex
	target    string
	serveErr  error
	closeOnce sync.Once
	closeErr  error
}

type devTargetRequest struct {
	Protocol  int    `json:"protocol"`
	Framework string `json:"framework"`
	Port      int    `json:"port"`
}

func newDevBootstrap(target string) (*devBootstrap, error) {
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
		done: make(chan struct{}), targets: make(chan string, 1), target: target,
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
		WriteTimeout:      5 * time.Second,
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
		err := b.server.Close()
		<-b.done
		b.mu.Lock()
		serveErr := b.serveErr
		b.mu.Unlock()
		b.closeErr = errors.Join(err, serveErr, os.RemoveAll(b.dir))
	})
	return b.closeErr
}

func (b *devBootstrap) Target(ctx context.Context) (string, error) {
	b.mu.Lock()
	target := b.target
	b.mu.Unlock()
	if target != "" {
		return target, nil
	}
	select {
	case target := <-b.targets:
		return target, nil
	case <-b.done:
		b.mu.Lock()
		err := b.serveErr
		b.mu.Unlock()
		if err == nil {
			return "", errors.New("development session socket closed before target registration")
		}
		return "", fmt.Errorf("serve development session socket: %w", err)
	case <-ctx.Done():
		return "", ctx.Err()
	}
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
	if request.Method != http.MethodPost || request.URL.Path != "/v1/target" {
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
	var registration devTargetRequest
	decoder := json.NewDecoder(io.LimitReader(request.Body, maxDevRequestBytes+1))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&registration); err != nil {
		http.Error(response, "invalid target registration", http.StatusBadRequest)
		return
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		http.Error(response, "invalid target registration", http.StatusBadRequest)
		return
	}
	if registration.Protocol != 1 || !validFrameworkName(registration.Framework) || registration.Port < 1 || registration.Port > 65535 {
		http.Error(response, "invalid target registration", http.StatusBadRequest)
		return
	}
	target, err := localproxy.NormalizeTarget(strconv.Itoa(registration.Port))
	if err != nil {
		http.Error(response, "invalid target registration", http.StatusBadRequest)
		return
	}

	b.mu.Lock()
	if b.target != "" && b.target != target {
		b.mu.Unlock()
		http.Error(response, "a different target is already registered", http.StatusConflict)
		return
	}
	first := b.target == ""
	b.target = target
	b.mu.Unlock()
	if first {
		select {
		case b.targets <- target:
		default:
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

func devEnvironment(bootstrap *devBootstrap, hostname string, port int) []string {
	replacements := map[string]string{
		"TNL_DEV_PROTOCOL":    devProtocolVersion,
		"TNL_DEV_SOCKET":      bootstrap.socket,
		"TNL_DEV_TOKEN":       bootstrap.token,
		"TNL_PUBLIC_HOSTNAME": hostname,
		"TNL_PUBLIC_URL":      "https://" + hostname,
	}
	if port != 0 {
		replacements["TNL_DEV_PORT"] = strconv.Itoa(port)
		replacements["PORT"] = strconv.Itoa(port)
	}
	blocked := map[string]struct{}{"TNL_ACCESS_TOKEN": {}}
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

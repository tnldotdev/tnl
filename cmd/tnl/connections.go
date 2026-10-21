package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/tnldotdev/tnl/internal/clientserver"
	"github.com/tnldotdev/tnl/internal/clientstate"
	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/connectionruntime"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/opaqueid"
	"github.com/tnldotdev/tnl/internal/projectconfig"
	credentialv1 "k8s.io/client-go/pkg/apis/clientauthentication/v1"
)

type connectionsCommand struct {
	Capabilities   connectionsCapabilities   `cmd:""`
	Context        connectionsContextOptions `cmd:""`
	Start          connectionsStartOptions   `cmd:""`
	Serve          connectionsServeOptions   `cmd:"" hidden:""`
	Status         connectionsHandleOptions  `cmd:""`
	Read           connectionsReadOptions    `cmd:"" help:"Read one prepared connection from its existing owner without starting or authenticating."`
	Stop           connectionsHandleOptions  `cmd:""`
	KubeCredential connectionsKubeOptions    `cmd:"" hidden:""`
}
type connectionsCapabilities struct {
	Output string `name:"output" enum:"json" default:"json"`
}
type connectionsContextOptions struct {
	Directory string   `name:"directory" required:"" type:"path"`
	CI        string   `name:"ci"`
	Service   []string `name:"service"`
	TeamID    string   `name:"team-id"`
	StateDir  string   `name:"state-dir" env:"TNL_STATE_DIR" type:"path"`
	Output    string   `name:"output" enum:"json" default:"json"`
}
type connectionsStartOptions struct {
	connectionsContextOptions `embed:""`
	RunnerTemp                string `name:"runner-temp" env:"RUNNER_TEMP" type:"path"`
	ParentPID                 int    `name:"parent-pid"`
	KubeTokenFile             string `name:"kube-token-file" type:"path"`
	KubeUserConfig            string `name:"kube-user-config" type:"path"`
	KubeUser                  string `name:"kube-user"`
	Namespace                 string `name:"namespace"`
}
type connectionsServeOptions struct {
	connectionsStartOptions `embed:""`
	OwnerDirectory          string `name:"owner-directory" required:"" type:"path"`
}
type connectionsHandleOptions struct {
	Handle string `name:"handle" required:"" type:"path"`
	Output string `name:"output" enum:"json" default:"json"`
}
type connectionsKubeOptions struct {
	connectionsHandleOptions `embed:""`
	Service                  string `name:"service" required:""`
}
type connectionsReadOptions struct {
	connectionsHandleOptions `embed:""`
	Service                  string `name:"service" required:""`
}

// the workload transport owner supplies this exact adapter at the merge seam.
// no synthetic identity/device, human login, or placeholder wire call is used.
var resolveConnectionTeam func(context.Context, string, string) (string, error)

func connectionProject(ctx context.Context, options connectionsContextOptions) (projectConfiguration, connectionruntime.Context, error) {
	if options.TeamID != "" && !opaqueid.Valid(options.TeamID, opaqueid.TeamPrefix) {
		return projectConfiguration{}, connectionruntime.Context{}, connectionruntime.ErrInvalid
	}
	directory, err := filepath.Abs(options.Directory)
	if err != nil {
		return projectConfiguration{}, connectionruntime.Context{}, err
	}
	directory, err = filepath.EvalSymlinks(directory)
	if err != nil {
		return projectConfiguration{}, connectionruntime.Context{}, err
	}
	selection, err := projectconfig.SelectProjectConfig(ctx, directory, "", os.Getenv("TNL_CONFIG"), false)
	if err != nil {
		return projectConfiguration{}, connectionruntime.Context{}, err
	}
	// CI source/worktree scope does not depend on a local human state database.
	project, err := projectconfig.Resolve(ctx, selection, directory, [32]byte{})
	if err != nil {
		return projectConfiguration{}, connectionruntime.Context{}, err
	}
	source, err := project.SourceIdentity(ctx)
	if err != nil {
		return projectConfiguration{}, connectionruntime.Context{}, err
	}
	server := clientserver.DefaultURL
	if project.Config.Server != nil {
		server = *project.Config.Server
	}
	if selected := os.Getenv("TNL_SERVER"); selected != "" {
		server = selected
	} else if options.CI == "" && project.Config.Server == nil {
		selected, database, err := resolveServer(ctx, options.StateDir, "")
		if err != nil {
			return projectConfiguration{}, connectionruntime.Context{}, err
		}
		server = selected
		if err := database.Close(); err != nil {
			return projectConfiguration{}, connectionruntime.Context{}, err
		}
	}
	server, err = clientstate.CanonicalServer(server)
	if err != nil {
		return projectConfiguration{}, connectionruntime.Context{}, err
	}
	services := slices.Clone(options.Service)
	if options.CI == "" && len(services) == 0 {
		for name, service := range project.Config.Services {
			if !isConnectPublicURL(service) {
				services = append(services, name)
			}
		}
	}
	if options.CI != "" {
		policy, ok := project.Config.CI[options.CI]
		if !ok {
			return projectConfiguration{}, connectionruntime.Context{}, connectionruntime.ErrInvalid
		}
		if len(services) == 0 {
			services = slices.Clone(policy.Services)
		}
		for _, name := range services {
			if !slices.Contains(policy.Services, name) {
				return projectConfiguration{}, connectionruntime.Context{}, connectionruntime.ErrInvalid
			}
		}
	}
	if len(services) == 0 {
		return projectConfiguration{}, connectionruntime.Context{}, connectionruntime.ErrInvalid
	}
	slices.Sort(services)
	for _, name := range services {
		if service, ok := project.Config.Services[name]; !ok || isConnectPublicURL(service) {
			return projectConfiguration{}, connectionruntime.Context{}, connectionruntime.ErrInvalid
		}
		effective, err := project.EffectiveService(name)
		if err != nil {
			return projectConfiguration{}, connectionruntime.Context{}, err
		}
		if effective.Server != nil {
			selected, err := clientstate.CanonicalServer(*effective.Server)
			if err != nil || selected != server {
				return projectConfiguration{}, connectionruntime.Context{}, connectionruntime.ErrInvalid
			}
		}
	}
	team := options.TeamID
	if team == "" && project.Config.Team != nil {
		team = *project.Config.Team
	}
	var appliedBinding *connectionruntime.Binding
	if binding, err := connectionruntime.ReadBinding(project.Root); err == nil && binding.Server == server && binding.ProjectKey == source.Key && binding.SourceID == source.Fingerprint {
		appliedBinding = &binding
	}
	if options.CI != "" && !opaqueid.Valid(team, opaqueid.TeamPrefix) {
		if appliedBinding != nil && appliedBinding.Team == team {
			team = appliedBinding.TeamID
		} else {
			if resolveConnectionTeam == nil {
				return projectConfiguration{}, connectionruntime.Context{}, connectionruntime.ErrTeam
			}
			team, err = resolveConnectionTeam(ctx, server, team)
			if err != nil {
				return projectConfiguration{}, connectionruntime.Context{}, err
			}
		}
	}
	encoded, err := json.Marshal(struct {
		Config   config.TNL
		Server   string
		Source   projectconfig.SourceIdentity
		Worktree string
		Binding  *connectionruntime.Binding
	}{project.Config, server, source, project.LocalWorktreeKey(), appliedBinding})
	if err != nil {
		return projectConfiguration{}, connectionruntime.Context{}, err
	}
	digest := sha256.Sum256(encoded)
	scope := connectionruntime.Context{Schema: 1, Directory: project.Root, ConfigDigest: hex.EncodeToString(digest[:]), Server: server, Audience: server, TeamID: team, ProjectKey: source.Key, SourceID: source.Fingerprint, WorktreeKey: project.LocalWorktreeKey(), ProjectLabel: source.Label, CI: options.CI, Services: services}
	return projectConfiguration{Project: project}, scope, scope.Validate()
}

func runConnections(ctx context.Context, command string, flags connectionsCommand, output io.Writer) (result error) {
	defer func() {
		if reason := connectionReason(result); reason != "" {
			result = failure.Wrap("manage native connections", reason, result)
		}
	}()
	switch command {
	case "runtime connections capabilities":
		return json.NewEncoder(output).Encode(map[string]any{"schema": 1, "capabilities": []string{"context", "start", "status", "stop", "connect", "read", "kube-credential"}, "workload_private": true, "opaque_private_preflight": true, "team_names": "applied_binding"})
	case "runtime connections context":
		_, scope, err := connectionProject(ctx, flags.Context)
		if err != nil {
			return err
		}
		return json.NewEncoder(output).Encode(scope)
	case "runtime connections start":
		return startConnections(ctx, flags.Start, os.Stdin, output)
	case "runtime connections serve":
		return serveConnectionsOwner(ctx, flags.Serve, os.Stdin, output)
	case "runtime connections read":
		return readPreparedConnection(ctx, flags.Read, output)
	case "runtime connections status", "runtime connections stop":
		options := flags.Status
		operation := "status"
		if strings.HasSuffix(command, " stop") {
			options, operation = flags.Stop, "stop"
		}
		h, err := connectionruntime.ReadHandle(options.Handle)
		if err != nil {
			if operation == "stop" {
				if _, missing := os.Lstat(options.Handle); errors.Is(missing, os.ErrNotExist) || errors.Is(err, connectionruntime.ErrExpired) {
					if err := waitConnectionsStopped(ctx, options.Handle); err != nil {
						return err
					}
					return json.NewEncoder(output).Encode(map[string]any{"schema": 1, "state": "stopped"})
				}
			}
			return err
		}
		var result json.RawMessage
		err = connectionruntime.Call(ctx, options.Handle, operation, connectionruntime.Request{Schema: 1, Directory: h.Directory, ConfigDigest: h.ConfigDigest}, &result)
		if err != nil {
			return err
		}
		if operation == "stop" {
			if err := waitConnectionsStopped(ctx, options.Handle); err != nil {
				return err
			}
			return json.NewEncoder(output).Encode(map[string]any{"schema": 1, "state": "stopped"})
		}
		return json.NewEncoder(output).Encode(result)
	case "runtime connections kube-credential":
		return runConnectionKubeCredential(ctx, flags.KubeCredential, output)
	}
	return connectionruntime.ErrInvalid
}

func readPreparedConnection(ctx context.Context, options connectionsReadOptions, output io.Writer) error {
	if !naming.ValidServiceName(options.Service) {
		return connectionruntime.ErrInvalid
	}
	bounded, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	handle, err := connectionruntime.ReadHandle(options.Handle)
	if err != nil {
		return err
	}
	var prepared connectionruntime.Prepared
	if err := connectionruntime.Call(bounded, options.Handle, "prepared", connectionruntime.Request{Schema: 1, Directory: handle.Directory, ConfigDigest: handle.ConfigDigest, Service: options.Service}, &prepared); err != nil {
		return err
	}
	if prepared.Schema != connectionruntime.Schema || prepared.Connection.Schema != connectionruntime.Schema {
		return connectionruntime.ErrInvalid
	}
	if !prepared.Connection.ExpiresAt.After(time.Now()) {
		return connectionruntime.ErrExpired
	}
	return json.NewEncoder(output).Encode(prepared)
}

// wait for joined drain/revocation, not merely the stop acknowledgement.
func waitConnectionsStopped(ctx context.Context, path string) error {
	deadline := time.NewTimer(20 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(25 * time.Millisecond)
	defer tick.Stop()
	for {
		if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
			return connectionruntime.ReadStopResult(path)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-deadline.C:
			return connectionruntime.ErrUnavailable
		case <-tick.C:
		}
	}
}

func startConnections(ctx context.Context, options connectionsStartOptions, input io.Reader, output io.Writer) error {
	if options.ParentPID < 0 || options.CI != "" && (options.ParentPID != 0 || options.RunnerTemp == "") {
		return connectionruntime.ErrInvalid
	}
	_, scope, err := connectionProject(ctx, options.connectionsContextOptions)
	if err != nil {
		return err
	}
	request := connectionruntime.StartRequest{Schema: 1, Context: scope}
	if options.CI != "" {
		if connectionruntime.ReadJSON(input, &request) != nil || request.Schema != 1 || request.Assertion == "" || !reflect.DeepEqual(request.Context, scope) {
			return connectionruntime.ErrInvalid
		}
	}
	parent := options.RunnerTemp
	if parent == "" {
		parent = os.TempDir()
	}
	directory, err := connectionruntime.NewDirectory(parent)
	if err != nil {
		return err
	}
	owned := false
	defer func() {
		if !owned {
			_ = os.RemoveAll(directory)
		}
	}()
	executable, err := os.Executable()
	if err != nil {
		return err
	}
	executable, err = filepath.EvalSymlinks(executable)
	if err != nil {
		return err
	}
	args := []string{"--no-telemetry", "runtime", "connections", "serve", "--directory", scope.Directory, "--owner-directory", directory}
	if options.CI != "" {
		args = append(args, "--ci", options.CI)
	}
	if options.TeamID != "" {
		args = append(args, "--team-id", options.TeamID)
	}
	if options.StateDir != "" {
		args = append(args, "--state-dir", options.StateDir)
	}
	if options.RunnerTemp != "" {
		args = append(args, "--runner-temp", options.RunnerTemp)
	}
	if options.ParentPID > 0 {
		args = append(args, "--parent-pid", strconv.Itoa(options.ParentPID))
	}
	for _, flag := range [][2]string{{"--kube-token-file", options.KubeTokenFile}, {"--kube-user-config", options.KubeUserConfig}, {"--kube-user", options.KubeUser}, {"--namespace", options.Namespace}} {
		if flag[1] != "" {
			args = append(args, flag[0], flag[1])
		}
	}
	for _, service := range scope.Services {
		args = append(args, "--service", service)
	}
	data, err := json.Marshal(request)
	if err != nil {
		return err
	}
	child := exec.Command(executable, args...)
	child.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	child.Stdin = bytes.NewReader(data)
	// keep runner tracking; retain no GitHub assertion-request bearer in owner env.
	for _, value := range os.Environ() {
		if !strings.HasPrefix(value, "ACTIONS_ID_TOKEN_REQUEST_TOKEN=") && !strings.HasPrefix(value, "ACTIONS_ID_TOKEN_REQUEST_URL=") {
			child.Env = append(child.Env, value)
		}
	}
	pipe, err := child.StdoutPipe()
	if err != nil {
		return err
	}
	if err := child.Start(); err != nil {
		return err
	}
	done := make(chan error, 1)
	go func() { done <- child.Wait() }()
	ready := make(chan struct {
		status connectionruntime.Status
		err    error
	}, 1)
	go func() {
		var state connectionruntime.Status
		err := connectionruntime.ReadJSON(pipe, &state)
		ready <- struct {
			status connectionruntime.Status
			err    error
		}{state, err}
	}()
	timer := time.NewTimer(40 * time.Second)
	defer timer.Stop()
	startupError := error(connectionruntime.ErrUnavailable)
	select {
	case result := <-ready:
		if result.err == nil && result.status.Schema == 1 && result.status.State == "ready" && result.status.PID == child.Process.Pid {
			if err := json.NewEncoder(output).Encode(result.status); err != nil {
				cleanup, cancel := context.WithTimeout(context.Background(), 20*time.Second)
				defer cancel()
				stopErr := connectionruntime.Call(cleanup, result.status.PrivateHandle, "stop", connectionruntime.Request{Schema: 1, Directory: scope.Directory, ConfigDigest: scope.ConfigDigest}, nil)
				select {
				case <-done:
				case <-cleanup.Done():
					_ = child.Process.Kill()
					<-done
				}
				return errors.Join(err, stopErr)
			}
			owned = true
			return nil
		}
		if result.err == nil && result.status.State == "failed" && result.status.Reason != "" {
			startupError = failure.Wrap("prepare native connections", failure.Reason(result.status.Reason), connectionruntime.ErrUnavailable)
		}
	case <-ctx.Done():
		startupError = context.Cause(ctx)
	case <-timer.C:
	}
	_ = child.Process.Signal(syscall.SIGTERM)
	select {
	case <-done:
	case <-time.After(20 * time.Second):
		_ = child.Process.Kill()
		<-done
	}
	return startupError
}

func serveConnectionsOwner(ctx context.Context, options connectionsServeOptions, input io.Reader, output io.Writer) error {
	if err := connectionruntime.VerifyDirectory(options.OwnerDirectory); err != nil {
		return err
	}
	project, scope, err := connectionProject(ctx, options.connectionsContextOptions)
	if err != nil {
		return err
	}
	var request connectionruntime.StartRequest
	if connectionruntime.ReadJSON(input, &request) != nil || request.Schema != 1 || !reflect.DeepEqual(request.Context, scope) || (scope.CI == "") != (request.Assertion == "") {
		return connectionruntime.ErrInvalid
	}
	backend := &nativeConnectionBackend{project: project, scope: scope, stateDir: options.StateDir, assertion: request.Assertion, directory: options.OwnerDirectory, runnerTemp: options.RunnerTemp, parentPID: options.ParentPID}
	request.Assertion = ""
	backend.kubeOptions = connectStartCommand{KubeTokenFile: options.KubeTokenFile, KubeUserConfig: options.KubeUserConfig, KubeUser: options.KubeUser, Namespace: options.Namespace}
	executable, err := os.Executable()
	if err != nil {
		return err
	}
	executable, err = filepath.EvalSymlinks(executable)
	if err != nil {
		return err
	}
	backend.executable = executable
	writer := &connectionReadinessWriter{Writer: output}
	err = connectionruntime.Serve(ctx, scope, options.OwnerDirectory, executable, backend, writer)
	if err != nil && !writer.written {
		reason := connectionReason(err)
		if reason == "" {
			reason = failure.ConnectionUnavailable
		}
		_ = json.NewEncoder(output).Encode(connectionruntime.Status{Schema: 1, State: "failed", Reason: string(reason)})
	}
	return err
}

type connectionReadinessWriter struct {
	io.Writer
	written bool
}

func (w *connectionReadinessWriter) Write(data []byte) (int, error) {
	w.written = true
	return w.Writer.Write(data)
}
func (w *connectionReadinessWriter) Close() error {
	if closer, ok := w.Writer.(io.Closer); ok {
		return closer.Close()
	}
	return nil
}
func connectionReason(err error) failure.Reason {
	if err == nil {
		return ""
	}
	if reason, ok := failure.ReasonOf(err); ok {
		return reason
	}
	switch {
	case errors.Is(err, connectionruntime.ErrTeam):
		return failure.ConnectionTeamBinding
	case errors.Is(err, connectionruntime.ErrTransport):
		return failure.ConnectionTransportMissing
	case errors.Is(err, connectionruntime.ErrUnauthorized):
		return failure.ConnectionHandleInvalid
	case errors.Is(err, connectionruntime.ErrExpired):
		return failure.ConnectionExpired
	case errors.Is(err, connectionruntime.ErrInvalid):
		return failure.ConnectionRequestInvalid
	case errors.Is(err, syscall.EADDRINUSE):
		return failure.ConnectionPortInUse
	case errors.Is(err, connectionruntime.ErrCleanup):
		return failure.ConnectionCleanupFailed
	case errors.Is(err, connectionruntime.ErrUnavailable):
		return failure.ConnectionUnavailable
	}
	return ""
}

func runConnectionKubeCredential(ctx context.Context, options connectionsKubeOptions, output io.Writer) error {
	h, err := connectionruntime.ReadHandle(options.Handle)
	if err != nil {
		return err
	}
	var credential credentialv1.ExecCredential
	if err := connectionruntime.Call(ctx, options.Handle, "kube-credential", connectionruntime.Request{Schema: 1, Directory: h.Directory, ConfigDigest: h.ConfigDigest, Service: options.Service}, &credential); err != nil {
		return err
	}
	return json.NewEncoder(output).Encode(credential)
}

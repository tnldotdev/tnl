package connector

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	connectorruntime "github.com/tnldotdev/tnl/internal/connector/runtime"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/observability"
)

func StartOwner(ctx context.Context, options OwnerStartOptions, input io.Reader, output io.Writer) error {
	if options.ParentPID < 0 {
		return connectorruntime.ErrInvalid
	}
	_, scope, err := connectionProject(ctx, options.ContextOptions)
	if err != nil {
		return err
	}
	request := connectorruntime.StartRequest{Schema: 1, Context: scope}
	return launchOwner(ctx, options, request, func(status connectorruntime.Status) error { return json.NewEncoder(output).Encode(status) })
}

// launchOwner transfers one ready, typed capability to its consumer. until that
// handoff succeeds, this operation retains the child and joins bounded cleanup.
func launchOwner(ctx context.Context, options OwnerStartOptions, request connectorruntime.StartRequest, readyOwner func(connectorruntime.Status) error) error {
	scope := request.Context
	return launchPreparedOwner(ctx, options, scope, request, readyOwner)
}

func launchPreparedOwner(ctx context.Context, options OwnerStartOptions, scope connectorruntime.Context, request any, readyOwner func(connectorruntime.Status) error) error {
	parent := options.RunnerTemp
	if parent == "" {
		parent = os.TempDir()
	}
	directory, err := connectorruntime.NewDirectory(parent)
	if err != nil {
		return err
	}
	if scope.Environment != nil { scope = environmentContext(*scope.Environment, directory) }
	if options.beforeStart != nil {
		if err := options.beforeStart(directory); err != nil {
			_ = os.RemoveAll(directory)
			return err
		}
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
	if scope.Environment != nil { args = []string{"--no-telemetry", "runtime", "connections", "environment-serve", "--owner-directory", directory} }
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
	if options.SDKRegistry != "" {
		args = append(args, "--sdk-registry", options.SDKRegistry)
	}
	if options.RequestHandle != "" {
		args = append(args, "--sdk-request-handle", options.RequestHandle)
	}
	for _, flag := range [][2]string{{"--kube-token-file", options.KubeTokenFile}, {"--kube-user-config", options.KubeUserConfig}, {"--kube-user", options.KubeUser}, {"--namespace", options.Namespace}} {
		if flag[1] != "" {
			args = append(args, flag[0], flag[1])
		}
	}
	if scope.Environment == nil { for _, service := range scope.Services { args = append(args, "--service", service) } }
	data, err := json.Marshal(request)
	if err != nil {
		return err
	}
	if scope.Environment != nil { data = append(data, '\n') }
	child := exec.Command(executable, args...)
	child.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	child.Stdin = bytes.NewReader(data)
	// keep runner tracking; retain no GitHub assertion-request bearer in owner env.
	for _, value := range os.Environ() {
		if !strings.HasPrefix(value, "ACTIONS_ID_TOKEN_REQUEST_TOKEN=") && !strings.HasPrefix(value, "ACTIONS_ID_TOKEN_REQUEST_URL=") && !strings.HasPrefix(value, "VERCEL_OIDC_TOKEN=") && !strings.HasPrefix(value, "VERCEL_TOKEN=") {
			child.Env = append(child.Env, value)
		}
	}
	child.Env = observability.LaunchEnvironment(ctx, child.Env)
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
		status connectorruntime.Status
		err    error
	}, 1)
	go func() {
		var state connectorruntime.Status
		err := connectorruntime.ReadJSON(pipe, &state)
		ready <- struct {
			status connectorruntime.Status
			err    error
		}{state, err}
	}()
	timer := time.NewTimer(40 * time.Second)
	defer timer.Stop()
	startupError := error(connectorruntime.ErrUnavailable)
	select {
	case result := <-ready:
		if result.err == nil && result.status.Schema == 1 && result.status.State == "ready" && result.status.PID == child.Process.Pid {
			if err := readyOwner(result.status); err != nil {
				cleanup, cancel := context.WithTimeout(context.Background(), 20*time.Second)
				defer cancel()
				stopErr := connectorruntime.Call(cleanup, result.status.ConnectionHandle, "stop", connectorruntime.Request{Schema: 1, Directory: scope.Directory, ConfigDigest: scope.ConfigDigest}, nil)
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
			startupError = failure.Wrap("prepare connector connections", failure.Reason(result.status.Reason), connectorruntime.ErrUnavailable)
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

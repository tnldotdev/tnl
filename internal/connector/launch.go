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
	"reflect"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/tnldotdev/tnl/internal/client/project/workloadmanifest"
	connectionruntime "github.com/tnldotdev/tnl/internal/connector/runtime"
	workloadclient "github.com/tnldotdev/tnl/internal/connector/workload"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/observability"
)

func StartOwner(ctx context.Context, options OwnerStartOptions, input io.Reader, output io.Writer) error {
	if options.ParentPID < 0 {
		return connectionruntime.ErrInvalid
	}
	project, scope, err := connectionProject(ctx, options.ContextOptions)
	if err != nil {
		return err
	}
	request := connectionruntime.StartRequest{Schema: 1, Context: scope}
	if options.Workload != "" {
		if connectionruntime.ReadJSON(input, &request) != nil || request.Schema != 1 || !reflect.DeepEqual(request.Context, scope) {
			return connectionruntime.ErrInvalid
		}
		if request.Assertion == "" {
			var hints workloadmanifest.Acquisition
			if options.Manifest != "" {
				m, e := workloadmanifest.Read(options.Manifest)
				if e != nil {
					return e
				}
				hints = m.Workloads[options.Workload].Acquisition
			} else {
				p := project.Config.Workloads[options.Workload]
				switch p.Provider {
				case "vercel":
					hints.Method = "vercel-oidc"
				case "fly":
					hints.Method = "fly-machine-api"
					hints.Audience = "https://fly.io/" + p.Org
				case "oidc":
					hints.Method = "token-file"
					hints.TokenFile = p.TokenFile
				default:
					return connectionruntime.ErrInvalid
				}
			}
			if hints.TokenFile != "" && !filepath.IsAbs(hints.TokenFile) {
				hints.TokenFile = filepath.Join(scope.Directory, hints.TokenFile)
			}
			request.Assertion, err = workloadclient.Acquire(ctx, hints, nil)
			if err != nil {
				return failure.Wrap("acquire workload assertion", failure.WorkloadAssertionUnavailable, err)
			}
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
	if options.Workload != "" {
		args = append(args, "--workload", options.Workload)
	}
	if options.Manifest != "" {
		args = append(args, "--workload-manifest", options.Manifest)
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

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"slices"
	"strings"
	"time"
)

type commandExecutor interface {
	Run(context.Context, string, ...string) ([]byte, error)
}

type osCommandExecutor struct{}

func (osCommandExecutor) Run(ctx context.Context, name string, arguments ...string) ([]byte, error) {
	command := exec.CommandContext(ctx, name, arguments...)
	command.Env = append(os.Environ(), "NO_COLOR=1")
	output, err := command.CombinedOutput()
	if err != nil {
		return output, fmt.Errorf("%s: %w: %s", name, err, strings.TrimSpace(string(output)))
	}
	return output, nil
}

type flyPlatform struct {
	binary   string
	org      string
	region   string
	executor commandExecutor
	progress *benchmarkProgress
}

type flyAddresses struct {
	IPv4 []string `json:"ipv4"`
	IPv6 []string `json:"ipv6"`
}

type flyMachine struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	State string `json:"state"`
}

type machineSpec struct {
	App           string
	Name          string
	Image         string
	Command       string
	Size          string
	Restart       string
	Env           map[string]string
	Ports         []string
	MachineConfig string
}

func (f flyPlatform) preflight(ctx context.Context) error {
	if _, err := exec.LookPath(f.binary); err != nil {
		return fmt.Errorf("find Fly CLI %q: %w", f.binary, err)
	}
	if _, err := f.executor.Run(ctx, f.binary, "auth", "whoami"); err != nil {
		return fmt.Errorf("authenticate Fly CLI: %w", err)
	}
	return nil
}

func (f flyPlatform) validateOrg(ctx context.Context) error {
	output, err := f.executor.Run(ctx, f.binary, "orgs", "list", "--json")
	if err != nil {
		return fmt.Errorf("list Fly organizations: %w", err)
	}
	var organizations map[string]string
	if err := json.Unmarshal(output, &organizations); err != nil {
		return fmt.Errorf("decode Fly organizations: %w", err)
	}
	if _, ok := organizations[f.org]; !ok {
		return fmt.Errorf("fly organization %q is not available to the authenticated identity", f.org)
	}
	return nil
}

func (f flyPlatform) createApp(ctx context.Context, name string) error {
	_, err := f.executor.Run(ctx, f.binary, "apps", "create", name, "--org", f.org, "--json", "--yes")
	if err != nil {
		return fmt.Errorf("create Fly app %s: %w", name, err)
	}
	return nil
}

func (f flyPlatform) destroyApp(ctx context.Context, name string) error {
	_, err := f.executor.Run(ctx, f.binary, "apps", "destroy", name, "--yes")
	if err != nil && !strings.Contains(err.Error(), "Could not find App") && !strings.Contains(err.Error(), "not found") {
		return fmt.Errorf("destroy Fly app %s: %w", name, err)
	}
	return nil
}

func (f flyPlatform) setSecrets(ctx context.Context, app string, values map[string]string) error {
	names := make([]string, 0, len(values))
	for name, value := range values {
		if value != "" {
			names = append(names, name)
		}
	}
	slices.Sort(names)
	arguments := []string{"secrets", "set", "--stage", "--app", app}
	for _, name := range names {
		arguments = append(arguments, name+"="+values[name])
	}
	if _, err := f.executor.Run(ctx, f.binary, arguments...); err != nil {
		return fmt.Errorf("stage secrets for Fly app %s: %w", app, redactCommandError(err, values))
	}
	return nil
}

func redactCommandError(err error, secrets map[string]string) error {
	return errors.New(redactSensitiveText(err.Error(), secrets))
}

func redactSensitiveText(message string, secrets map[string]string) string {
	for _, value := range secrets {
		if value != "" {
			message = strings.ReplaceAll(message, value, "[REDACTED]")
		}
	}
	return redactDatabaseText(message)
}

func (f flyPlatform) buildImage(ctx context.Context, app, label string) (string, error) {
	_, err := f.executor.Run(
		ctx, f.binary, "deploy", ".", "--app", app, "--dockerfile", "Dockerfile.bench",
		"--config", "benchmarks/fly-build.toml", "--build-only", "--push", "--image-label", label, "--yes",
	)
	if err != nil {
		return "", fmt.Errorf("build benchmark image: %w", err)
	}
	return "registry.fly.io/" + app + ":" + label, nil
}

func (f flyPlatform) allocateAddresses(ctx context.Context, app string, sharedIPv4 bool) (flyAddresses, error) {
	arguments := []string{"ips", "allocate-v4", "--app", app, "--yes"}
	if sharedIPv4 {
		arguments = append(arguments, "--shared")
	}
	if _, err := f.executor.Run(ctx, f.binary, arguments...); err != nil {
		return flyAddresses{}, fmt.Errorf("allocate Fly IPv4 for %s: %w", app, err)
	}
	if _, err := f.executor.Run(ctx, f.binary, "ips", "allocate-v6", "--app", app); err != nil {
		return flyAddresses{}, fmt.Errorf("allocate Fly IPv6 for %s: %w", app, err)
	}
	output, err := f.executor.Run(ctx, f.binary, "ips", "list", "--app", app, "--json")
	if err != nil {
		return flyAddresses{}, fmt.Errorf("list Fly addresses for %s: %w", app, err)
	}
	var rows []struct {
		Address string `json:"address"`
	}
	if err := json.Unmarshal(output, &rows); err != nil {
		return flyAddresses{}, fmt.Errorf("decode Fly addresses for %s: %w", app, err)
	}
	var result flyAddresses
	for _, row := range rows {
		address, err := netip.ParseAddr(row.Address)
		if err != nil {
			continue
		}
		if address.Is4() {
			result.IPv4 = append(result.IPv4, address.String())
		} else {
			result.IPv6 = append(result.IPv6, address.String())
		}
	}
	if len(result.IPv4) == 0 || len(result.IPv6) == 0 {
		return flyAddresses{}, fmt.Errorf("fly app %s did not receive both public address families", app)
	}
	return result, nil
}

func (f flyPlatform) runMachine(ctx context.Context, spec machineSpec) (flyMachine, error) {
	arguments := []string{"machine", "run", spec.Image}
	if spec.Command != "" {
		arguments = append(arguments, spec.Command)
	}
	arguments = append(arguments,
		"--app", spec.App, "--name", spec.Name, "--region", f.region, "--vm-size", spec.Size,
		"--restart", spec.Restart, "--autostop=off", "--detach",
	)
	names := make([]string, 0, len(spec.Env))
	for name := range spec.Env {
		names = append(names, name)
	}
	slices.Sort(names)
	for _, name := range names {
		arguments = append(arguments, "--env", name+"="+spec.Env[name])
	}
	for _, port := range spec.Ports {
		arguments = append(arguments, "--port", port)
	}
	if spec.MachineConfig != "" {
		arguments = append(arguments, "--machine-config", spec.MachineConfig)
	}
	launchCtx, cancel := context.WithTimeout(ctx, time.Minute)
	type launchResult struct {
		err error
	}
	launched := make(chan launchResult, 1)
	startedAt := time.Now()
	go func() {
		_, err := f.executor.Run(launchCtx, f.binary, arguments...)
		launched <- launchResult{err: err}
	}()
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	var launchErr error
launchWait:
	for {
		select {
		case result := <-launched:
			launchErr = result.err
			break launchWait
		case <-ticker.C:
			f.progress.printf("machine %s: waiting for Fly start (%s)", spec.Name, time.Since(startedAt).Truncate(time.Second))
		case <-launchCtx.Done():
			launchErr = launchCtx.Err()
			break launchWait
		}
	}
	cancel()
	if launchErr != nil {
		machine, listErr := f.machineByName(ctx, spec.App, spec.Name)
		if listErr == nil && machine.State == "started" {
			return machine, nil
		}
		if machine.ID != "" {
			return machine, fmt.Errorf("run Fly machine %s: %w (machine %s is %s)", spec.Name, launchErr, machine.ID, machine.State)
		}
		if listErr != nil {
			return flyMachine{}, fmt.Errorf("run Fly machine %s: %w (list after failure: %v)", spec.Name, launchErr, listErr)
		}
		return flyMachine{}, fmt.Errorf("run Fly machine %s: %w", spec.Name, launchErr)
	}
	deadline := time.Now().Add(2 * time.Minute)
	lastState := ""
	nextHeartbeat := time.Now().Add(10 * time.Second)
	for {
		machine, err := f.machineByName(ctx, spec.App, spec.Name)
		if err == nil && machine.State == "started" {
			return machine, nil
		}
		if err == nil && machine.ID != "" && machine.State != lastState {
			f.progress.printf("machine %s: state %s", spec.Name, machine.State)
			lastState = machine.State
			nextHeartbeat = time.Now().Add(10 * time.Second)
		} else if !time.Now().Before(nextHeartbeat) {
			state := machine.State
			if state == "" {
				state = "not listed"
			}
			f.progress.printf("machine %s: still waiting (state %s)", spec.Name, state)
			nextHeartbeat = time.Now().Add(10 * time.Second)
		}
		if err == nil && machine.ID != "" && spec.Restart == "no" && machine.State == "stopped" {
			return machine, fmt.Errorf("fly machine %s stopped before becoming ready", spec.Name)
		}
		if time.Now().After(deadline) {
			return machine, fmt.Errorf("fly machine %s did not become started (last state %q, last list error: %v)", spec.Name, machine.State, err)
		}
		if err := sleepContext(ctx, time.Second); err != nil {
			return flyMachine{}, err
		}
	}
}

func (f flyPlatform) machineByName(ctx context.Context, app, name string) (flyMachine, error) {
	machines, err := f.listMachines(ctx, app)
	if err != nil {
		return flyMachine{}, err
	}
	for _, machine := range machines {
		if machine.Name == name {
			return machine, nil
		}
	}
	return flyMachine{}, nil
}

func (f flyPlatform) waitMachineReady(ctx context.Context, app, machineID string, timeout time.Duration) error {
	return f.waitMachineCommandReady(
		ctx, app, machineID, "wget -q --spider http://127.0.0.1:9090/ready", timeout,
	)
}

func (f flyPlatform) waitMachineCommandReady(
	ctx context.Context,
	app, machineID, command string,
	timeout time.Duration,
) error {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	var lastErr error
	for {
		_, lastErr = f.machineCommand(ctx, app, machineID, command)
		if lastErr == nil {
			return nil
		}
		if err := sleepContext(ctx, 2*time.Second); err != nil {
			return fmt.Errorf("fly machine %s did not become ready: %w (last probe error: %v)", machineID, err, lastErr)
		}
	}
}

func (f flyPlatform) machineCommand(ctx context.Context, app, machineID, command string) ([]byte, error) {
	output, err := f.executor.Run(
		ctx, f.binary, "ssh", "console", "--app", app, "--machine", machineID,
		"--command", benchmarkShellCommand(command), "--pty=false",
	)
	if err != nil {
		return output, fmt.Errorf("run command on Fly machine %s: %w", machineID, err)
	}
	return output, nil
}

func benchmarkShellCommand(command string) string {
	return "/bin/sh -c '" + strings.ReplaceAll(command, "'", `'"'"'`) + "'"
}

func (f flyPlatform) machineDiagnostics(ctx context.Context, app string, machines []flyMachine) string {
	var sections []string
	for _, machine := range machines {
		for _, command := range []struct {
			label     string
			arguments []string
		}{
			{"status", []string{"machine", "status", machine.ID, "--app", app}},
			{"logs", []string{"logs", "--no-tail", "--app", app, "--machine", machine.ID}},
		} {
			output, err := f.executor.Run(ctx, f.binary, command.arguments...)
			text := strings.TrimSpace(string(output))
			if err != nil {
				if text != "" {
					text += "\n"
				}
				text += "command error: " + err.Error()
			}
			sections = append(sections, fmt.Sprintf("[%s %s]\n%s", machine.Name, command.label, text))
		}
	}
	return strings.Join(sections, "\n\n") + "\n"
}

func (f flyPlatform) runEphemeral(ctx context.Context, spec machineSpec) error {
	arguments := []string{"machine", "run", spec.Image}
	if spec.Command != "" {
		arguments = append(arguments, spec.Command)
	}
	arguments = append(arguments,
		"--app", spec.App, "--name", spec.Name, "--region", f.region, "--vm-size", spec.Size,
		"--restart", "no", "--autostop=off", "--rm",
	)
	names := make([]string, 0, len(spec.Env))
	for name := range spec.Env {
		names = append(names, name)
	}
	slices.Sort(names)
	for _, name := range names {
		arguments = append(arguments, "--env", name+"="+spec.Env[name])
	}
	if _, err := f.executor.Run(ctx, f.binary, arguments...); err != nil {
		return fmt.Errorf("run ephemeral Fly machine %s: %w", spec.Name, err)
	}
	return nil
}

func (f flyPlatform) listMachines(ctx context.Context, app string) ([]flyMachine, error) {
	output, err := f.executor.Run(ctx, f.binary, "machine", "list", "--app", app, "--json")
	if err != nil {
		return nil, err
	}
	var machines []flyMachine
	if err := json.Unmarshal(output, &machines); err != nil {
		return nil, fmt.Errorf("decode Fly machines for %s: %w", app, err)
	}
	return machines, nil
}

func (f flyPlatform) destroyMachines(ctx context.Context, app string) error {
	machines, err := f.listMachines(ctx, app)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			return nil
		}
		return err
	}
	if len(machines) == 0 {
		return nil
	}
	arguments := []string{"machine", "destroy", "--force", "--app", app}
	for _, machine := range machines {
		arguments = append(arguments, machine.ID)
	}
	_, err = f.executor.Run(ctx, f.binary, arguments...)
	return err
}

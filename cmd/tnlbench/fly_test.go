package main

import (
	"context"
	"errors"
	"os"
	"slices"
	"strings"
	"testing"
	"testing/synctest"
	"time"
)

type executorCall struct {
	name string
	args []string
}

type executorStub struct {
	calls     []executorCall
	responses [][]byte
	errs      []error
	err       error
}

type commandExecutorFunc func(context.Context, string, ...string) ([]byte, error)

func TestBenchmarkImageSecuresPublisherStateRoot(t *testing.T) {
	contents, err := os.ReadFile("../../Dockerfile.bench")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(contents), `chown 65532:65532 \"$TNL_BENCH_STATE_ROOT\" && chmod 0700 \"$TNL_BENCH_STATE_ROOT\"`) {
		t.Fatal("benchmark image does not secure the publisher state root")
	}
}

func (f commandExecutorFunc) Run(ctx context.Context, name string, arguments ...string) ([]byte, error) {
	return f(ctx, name, arguments...)
}

func (e *executorStub) Run(_ context.Context, name string, arguments ...string) ([]byte, error) {
	e.calls = append(e.calls, executorCall{name: name, args: append([]string(nil), arguments...)})
	if len(e.errs) != 0 {
		err := e.errs[0]
		e.errs = e.errs[1:]
		if err != nil {
			return nil, err
		}
	}
	if e.err != nil {
		return nil, e.err
	}
	if len(e.responses) == 0 {
		return nil, nil
	}
	response := e.responses[0]
	e.responses = e.responses[1:]
	return response, nil
}

func TestFlySecretsRedactCommandFailures(t *testing.T) {
	executor := &executorStub{err: errors.New("command failed for TOKEN=super-secret")}
	platform := flyPlatform{binary: "fly", executor: executor}
	err := platform.setSecrets(t.Context(), "app", map[string]string{"TOKEN": "super-secret", "EMPTY": ""})
	if err == nil || strings.Contains(err.Error(), "super-secret") || !strings.Contains(err.Error(), "[REDACTED]") {
		t.Fatalf("secret error = %v", err)
	}
	if slices.Contains(executor.calls[0].args, "EMPTY=") {
		t.Fatalf("empty secret was staged: %v", executor.calls[0].args)
	}
}

func TestFlyValidatesOrganizationAccess(t *testing.T) {
	organizations := []byte(`{"personal":"Chase Adams","tnl":"tnl"}`)
	executor := &executorStub{responses: [][]byte{organizations, organizations}}
	platform := flyPlatform{binary: "flyctl", org: "tnl", executor: executor}
	if err := platform.validateOrg(t.Context()); err != nil {
		t.Fatal(err)
	}
	platform.org = "missing"
	if err := platform.validateOrg(t.Context()); err == nil {
		t.Fatal("unavailable organization was accepted")
	}
}

func TestFlyBuildImageUsesExplicitConfig(t *testing.T) {
	executor := &executorStub{}
	platform := flyPlatform{binary: "flyctl", executor: executor}
	image, err := platform.buildImage(t.Context(), "benchmark-app", "benchmark-label")
	if err != nil {
		t.Fatal(err)
	}
	if image != "registry.fly.io/benchmark-app:benchmark-label" {
		t.Fatalf("image = %q", image)
	}
	want := []string{
		"deploy", ".", "--app", "benchmark-app", "--dockerfile", "Dockerfile.bench",
		"--config", "benchmarks/fly-build.toml", "--build-only", "--push", "--image-label", "benchmark-label", "--yes",
	}
	if len(executor.calls) != 1 || !slices.Equal(executor.calls[0].args, want) {
		t.Fatalf("calls = %#v", executor.calls)
	}
}

func TestFlyMachineRunUsesOneControlledCommand(t *testing.T) {
	executor := &executorStub{responses: [][]byte{nil, []byte(`[{"id":"machine-1","name":"relay-a-1","state":"started"}]`)}}
	platform := flyPlatform{binary: "fly", region: "sjc", executor: executor}
	machine, err := platform.runMachine(t.Context(), machineSpec{
		App: "relay-app", Name: "relay-a-1", Image: "registry/image:tag", Command: "/tnld serve",
		Size: "performance-1x", Restart: "always", Env: map[string]string{"TNLD_MODE": "relay"},
		Ports: []string{"443:443/tcp", "443:443/udp"}, Volumes: []string{"vol_state:/state"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if machine.ID != "machine-1" || len(executor.calls) != 2 || executor.calls[0].args[3] != "/tnld serve" ||
		!slices.Contains(executor.calls[0].args, "--autostop=off") || slices.Contains(executor.calls[0].args, "off") ||
		!slices.Contains(executor.calls[0].args, "vol_state:/state") {
		t.Fatalf("machine = %#v, calls = %#v", machine, executor.calls)
	}
}

func TestFlyCreatesAndDestroysExactVolume(t *testing.T) {
	executor := &executorStub{responses: [][]byte{
		[]byte(`{"id":"vol_123","name":"publisher_state_0","region":"sjc","size_gb":1}`), nil,
	}}
	platform := flyPlatform{binary: "fly", region: "sjc", executor: executor}
	volume, err := platform.createVolume(t.Context(), "publisher-app", "publisher_state_0", 1)
	if err != nil {
		t.Fatal(err)
	}
	if volume.ID != "vol_123" {
		t.Fatalf("volume = %#v", volume)
	}
	if err := platform.destroyVolume(t.Context(), "publisher-app", volume.ID); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(executor.calls[0].args, []string{
		"volumes", "create", "publisher_state_0", "--app", "publisher-app", "--region", "sjc",
		"--size", "1", "--scheduled-snapshots=false", "--json", "--yes",
	}) || !slices.Equal(executor.calls[1].args, []string{
		"volumes", "destroy", "vol_123", "--app", "publisher-app", "--yes",
	}) {
		t.Fatalf("calls = %#v", executor.calls)
	}
}

func TestFlyMachineRunWaitsForStartedState(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		executor := &executorStub{responses: [][]byte{
			nil,
			[]byte(`[{"id":"machine-1","name":"control-1","state":"created"}]`),
			[]byte(`[{"id":"machine-1","name":"control-1","state":"started"}]`),
		}}
		platform := flyPlatform{binary: "fly", region: "sjc", executor: executor}
		machine, err := platform.runMachine(t.Context(), machineSpec{
			App: "control-app", Name: "control-1", Image: "registry/image:tag", Command: "/tnld serve",
			Size: "performance-2x", Restart: "always",
		})
		if err != nil {
			t.Fatal(err)
		}
		if machine.State != "started" || len(executor.calls) != 3 {
			t.Fatalf("machine = %#v, calls = %#v", machine, executor.calls)
		}
	})
}

func TestFlyMachineRunReturnsFailedMachineIdentity(t *testing.T) {
	executor := &executorStub{
		errs: []error{errors.New("start failed"), nil},
		responses: [][]byte{
			[]byte(`[{"id":"machine-1","name":"publisher-1","state":"stopped"}]`),
		},
	}
	platform := flyPlatform{binary: "fly", region: "sjc", executor: executor}
	machine, err := platform.runMachine(t.Context(), machineSpec{
		App: "publisher-app", Name: "publisher-1", Image: "registry/image:tag", Command: "/tnlbench publisher",
		Size: "performance-2x", Restart: "no",
	})
	if err == nil || machine.ID != "machine-1" || machine.State != "stopped" {
		t.Fatalf("machine = %#v, error = %v", machine, err)
	}
}

func TestFlyMachineRunBoundsSilentFlyWait(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		executor := commandExecutorFunc(func(ctx context.Context, _ string, arguments ...string) ([]byte, error) {
			if len(arguments) > 1 && arguments[0] == "machine" && arguments[1] == "run" {
				<-ctx.Done()
				return nil, ctx.Err()
			}
			return []byte(`[{"id":"machine-1","name":"publisher-1","state":"stopped"}]`), nil
		})
		var output strings.Builder
		platform := flyPlatform{
			binary: "fly", region: "sjc", executor: executor, progress: newBenchmarkProgress(&output),
		}
		startedAt := time.Now()
		machine, err := platform.runMachine(t.Context(), machineSpec{
			App: "publisher-app", Name: "publisher-1", Image: "registry/image:tag", Command: "/tnlbench publisher",
			Size: "performance-2x", Restart: "no",
		})
		if err == nil || machine.ID != "machine-1" || time.Since(startedAt) != time.Minute {
			t.Fatalf("machine = %#v, elapsed = %s, error = %v", machine, time.Since(startedAt), err)
		}
		if !strings.Contains(output.String(), "machine publisher-1: waiting for Fly start (10s)") {
			t.Fatalf("progress = %q", &output)
		}
	})
}

func TestFlyWaitMachineReadyRetriesInternalProbe(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		executor := &executorStub{errs: []error{errors.New("not ready"), nil}}
		platform := flyPlatform{binary: "fly", executor: executor}
		if err := platform.waitMachineReady(t.Context(), "control-app", "machine-1", time.Minute); err != nil {
			t.Fatal(err)
		}
		want := []string{
			"ssh", "console", "--app", "control-app", "--machine", "machine-1",
			"--command", "/bin/sh -c 'wget -q --spider http://127.0.0.1:9090/ready'", "--pty=false",
		}
		if len(executor.calls) != 2 || !slices.Equal(executor.calls[0].args, want) {
			t.Fatalf("calls = %#v", executor.calls)
		}
	})
}

func TestBenchmarkShellCommandQuotesScripts(t *testing.T) {
	got := benchmarkShellCommand("printf 'ready'; cat /tmp/root.pem")
	want := `/bin/sh -c 'printf '"'"'ready'"'"'; cat /tmp/root.pem'`
	if got != want {
		t.Fatalf("shell command = %q, want %q", got, want)
	}
}

func TestFlyEphemeralMachineUsesUnambiguousAutostopFlag(t *testing.T) {
	executor := &executorStub{}
	platform := flyPlatform{binary: "fly", region: "sjc", executor: executor}
	if err := platform.runEphemeral(t.Context(), machineSpec{
		App: "control-app", Name: "migrate", Image: "registry/image:tag", Command: "/tnld migrate",
		Size: "shared-cpu-1x",
	}); err != nil {
		t.Fatal(err)
	}
	arguments := executor.calls[0].args
	if !slices.Contains(arguments, "--rm") || !slices.Contains(arguments, "--autostop=off") || slices.Contains(arguments, "off") {
		t.Fatalf("machine arguments = %v", arguments)
	}
}

func TestFlyMachineDiagnosticsIncludeStatusAndLogs(t *testing.T) {
	executor := &executorStub{responses: [][]byte{[]byte("started"), []byte("certificate failed")}}
	platform := flyPlatform{binary: "fly", executor: executor}
	diagnostics := platform.machineDiagnostics(t.Context(), "control-app", []flyMachine{{ID: "machine-1", Name: "control-1"}})
	if diagnostics != "[control-1 status]\nstarted\n\n[control-1 logs]\ncertificate failed\n" {
		t.Fatalf("diagnostics = %q", diagnostics)
	}
}

func TestFlyMachineRunAcceptsExplicitServiceConfig(t *testing.T) {
	executor := &executorStub{responses: [][]byte{nil, []byte(`[{"id":"machine-1","name":"ingress-1","state":"started"}]`)}}
	platform := flyPlatform{binary: "fly", region: "sjc", executor: executor}
	config := `{"services":[{"protocol":"tcp","internal_port":8443}]}`
	if _, err := platform.runMachine(t.Context(), machineSpec{
		App: "ingress-app", Name: "ingress-1", Image: "registry/image:tag", Command: "/tnld serve",
		Size: "performance-1x", Restart: "always", MachineConfig: config,
	}); err != nil {
		t.Fatal(err)
	}
	arguments := executor.calls[0].args
	index := slices.Index(arguments, "--machine-config")
	if index < 0 || index+1 == len(arguments) || arguments[index+1] != config || slices.Contains(arguments, "--port") {
		t.Fatalf("machine arguments = %v", arguments)
	}
}

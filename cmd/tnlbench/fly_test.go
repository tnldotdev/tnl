package main

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
)

type executorCall struct {
	name string
	args []string
}

type executorStub struct {
	calls     []executorCall
	responses [][]byte
	err       error
}

func (e *executorStub) Run(_ context.Context, name string, arguments ...string) ([]byte, error) {
	e.calls = append(e.calls, executorCall{name: name, args: append([]string(nil), arguments...)})
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

func TestFlyMachineRunUsesOneControlledCommand(t *testing.T) {
	executor := &executorStub{responses: [][]byte{nil, []byte(`[{"id":"machine-1","name":"relay-a-1","state":"started"}]`)}}
	platform := flyPlatform{binary: "fly", region: "sjc", executor: executor}
	machine, err := platform.runMachine(t.Context(), machineSpec{
		App: "relay-app", Name: "relay-a-1", Image: "registry/image:tag", Command: "/tnld serve",
		Size: "performance-1x", Restart: "always", Env: map[string]string{"TNLD_MODE": "relay"},
		Ports: []string{"443:443/tcp", "443:443/udp"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if machine.ID != "machine-1" || len(executor.calls) != 2 || executor.calls[0].args[3] != "/tnld serve" {
		t.Fatalf("machine = %#v, calls = %#v", machine, executor.calls)
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

package main

import (
	"bytes"
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/config"
)

func TestComposeServiceSelectsNamedOwnerWithoutFlatTarget(t *testing.T) {
	project, _, _ := testAppRuntime(t)
	configuration := project.project
	name, file, service, port := "my_worktree", "compose.yaml", "cache", 6379
	configuration.Config.Services = config.Services{"cache": {Protocol: new("redis"), Target: &config.ServiceTarget{
		Type: "compose", Project: &name, File: &file, Service: &service, Port: &port,
	}}}
	configuration.RelativeServiceDirectories["cache"] = "."
	flags := publishCommand{Target: "cache"}
	if err := configuration.applyPublish(&flags); err != nil {
		t.Fatal(err)
	}
	if flags.Service != "cache" || flags.Target != "" || flags.Protocol != "redis" {
		t.Fatalf("Compose named selection = %+v", flags)
	}
	entries := configuredRuntimeServices(configuration)
	if len(entries) != 1 || entries[0].ServiceProtocol != "redis" {
		t.Fatalf("named runtime services = %+v", entries)
	}
}

func TestWaitChecksReplacementComposeBindingInsteadOfStartupPort(t *testing.T) {
	a, stateDir, started := testAppRuntime(t)
	first, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	second, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	project := a.project
	project.Config.Services["cache"] = config.Service{Protocol: new("redis"), Target: &config.ServiceTarget{Type: "compose", Project: new("my_worktree"), File: new("compose.yaml"), Service: new("cache"), Port: new(6379)}}
	project.RelativeServiceDirectories["cache"] = "."
	if err := os.WriteFile(filepath.Join(project.Root, "compose.yaml"), []byte("services: {}\n"), 0600); err != nil {
		t.Fatal(err)
	}
	bin := t.TempDir()
	if err := os.WriteFile(filepath.Join(bin, "docker"), []byte("#!/bin/sh\nprintf '%s\\n' \"$COMPOSE_BINDING\"\n"), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	if err := a.manager.Configure(configuredRuntimeServices(project)); err != nil {
		t.Fatal(err)
	}
	id, err := a.manager.Reserve("cache", "cli-owner", os.Getpid(), "cache.example:16379")
	if err != nil {
		t.Fatal(err)
	}
	if err := a.manager.RegisterNamed(id, "cli-owner", first.Addr().String()); err != nil {
		t.Fatal(err)
	}
	<-started
	first.Close()
	t.Setenv("COMPOSE_BINDING", second.Addr().String())
	var output bytes.Buffer
	if err := runAppWaitWithProbe(t.Context(), project, stateDir, waitCommand{Service: []string{"cache"}, Timeout: 2 * time.Second, Output: "json"}, &output, nil); err != nil {
		t.Fatalf("replacement binding was not ready: %v: %s", err, output.String())
	}
	t.Setenv("COMPOSE_BINDING", "")
	output.Reset()
	if err := runAppWaitWithProbe(t.Context(), project, stateDir, waitCommand{Service: []string{"cache"}, Timeout: 300 * time.Millisecond, Output: "json"}, &output, nil); err == nil {
		t.Fatalf("missing binding passed wait: %s", output.String())
	}
	if err := a.manager.Unregister(id, "cli-owner"); err != nil {
		t.Fatal(err)
	}
}

func TestComposeReadinessFollowsCurrentBindingWithoutReplacingLease(t *testing.T) {
	a, _, started := testAppRuntime(t)
	first, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	second, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	project := a.project
	project.Config.Services["cache"] = config.Service{Protocol: new("redis"), Target: &config.ServiceTarget{Type: "compose", Project: new("my_worktree"), File: new("compose.yaml"), Service: new("cache"), Port: new(6379)}}
	project.RelativeServiceDirectories["cache"] = "."
	if err := a.manager.Configure(configuredRuntimeServices(project)); err != nil {
		t.Fatal(err)
	}
	id, err := a.manager.Reserve("cache", "cli-owner", os.Getpid(), "cache.example:16379")
	if err != nil {
		t.Fatal(err)
	}
	if err := a.manager.RegisterNamed(id, "cli-owner", first.Addr().String()); err != nil {
		t.Fatal(err)
	}
	run := <-started
	service := a.manager.Snapshot().Services[0]
	for _, candidate := range a.manager.Snapshot().Services {
		if candidate.Name == "cache" {
			service = candidate
		}
	}
	var mu sync.Mutex
	current := first.Addr().String()
	resolve := func(context.Context) (string, error) {
		mu.Lock()
		defer mu.Unlock()
		if current == "" {
			return "", errors.New("binding unavailable")
		}
		return current, nil
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan struct{})
	go func() { defer close(done); a.checkCompose(ctx, service, resolve) }()
	wait := func(ready bool) {
		t.Helper()
		deadline := time.After(6 * time.Second)
		for {
			for _, item := range a.manager.Snapshot().Services {
				if item.Name == "cache" && item.Observation != nil && item.Ready == ready {
					if item.RegistrationID != id || item.PublishRunNumber != run || item.Target != first.Addr().String() {
						t.Fatalf("readiness changed the lease or run: %+v", item)
					}
					return
				}
			}
			select {
			case <-deadline:
				t.Fatalf("readiness never changed to %t", ready)
			case <-time.After(50 * time.Millisecond):
			}
		}
	}
	wait(true)
	mu.Lock()
	current = ""
	mu.Unlock()
	wait(false)
	mu.Lock()
	current = second.Addr().String()
	mu.Unlock()
	wait(true)
	cancel()
	<-done
	if err := a.manager.Unregister(id, "cli-owner"); err != nil {
		t.Fatal(err)
	}
}

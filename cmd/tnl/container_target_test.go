package main

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/config"
)

func TestDockerContainerTargetSelectsNamedOwner(t *testing.T) {
	a, _, _ := testAppRuntime(t)
	project := a.project
	project.Worktree.Label.FullLabel = "shop-first-k7n2p9"
	project.Config.Services = config.Services{"cache": {Protocol: new("redis"), Target: &config.ServiceTarget{
		Type: "docker", Container: new("db-dev"), Port: new(6379),
	}}}
	project.RelativeServiceDirectories["cache"] = "."
	flags := publishCommand{Target: "cache"}
	if err := project.applyPublish(&flags); err != nil {
		t.Fatal(err)
	}
	if flags.Service != "cache" || flags.Target != "" || flags.Protocol != "redis" {
		t.Fatalf("named container selection = %+v", flags)
	}
	entries := configuredRuntimeServices(project)
	if len(entries) != 1 || entries[0].ServiceProtocol != "redis" {
		t.Fatalf("named container runtime services = %+v", entries)
	}
	bin := t.TempDir()
	if err := os.WriteFile(filepath.Join(bin, "docker"), []byte("#!/bin/sh\nprintf '%s\\n' \"$DOCKER_INSPECT\"\n"), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("DOCKER_INSPECT", dockerTargetFixture("shop-first-k7n2p9", "db-dev", "49153"))
	resolve := namedDynamicTarget(project.Project, project.Config.Services["cache"].Target, "http")
	if target, err := resolve(context.Background()); err != nil || target != "http://127.0.0.1:49153" {
		t.Fatalf("HTTP target = %q, %v", target, err)
	}
	project.Worktree.Label.FullLabel = "shop-second-m4q8s2"
	if _, err := namedDynamicTarget(project.Project, project.Config.Services["cache"].Target, "http")(t.Context()); err == nil {
		t.Fatal("HTTP resolver selected container from another worktree")
	}
}

func TestWaitFollowsCurrentDockerContainerBinding(t *testing.T) {
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
	_, oldPort, _ := net.SplitHostPort(first.Addr().String())
	_, newPort, _ := net.SplitHostPort(second.Addr().String())
	project := a.project
	project.Worktree.Label.FullLabel = "shop-first-k7n2p9"
	project.Config.Services["cache"] = config.Service{Protocol: new("redis"), Target: &config.ServiceTarget{Type: "docker", Container: new("db-dev"), Port: new(6379)}}
	project.RelativeServiceDirectories["cache"] = "."
	bin := t.TempDir()
	if err := os.WriteFile(filepath.Join(bin, "docker"), []byte("#!/bin/sh\nprintf '%s\\n' \"$DOCKER_INSPECT\"\n"), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("DOCKER_INSPECT", dockerTargetFixture("shop-first-k7n2p9", "db-dev", oldPort))
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
	t.Setenv("DOCKER_INSPECT", dockerTargetFixture("shop-first-k7n2p9", "db-dev", newPort))
	var output bytes.Buffer
	if err := runAppWaitWithProbe(t.Context(), project, stateDir, waitCommand{Service: []string{"cache"}, Timeout: 2 * time.Second, Output: "json"}, &output, nil); err != nil {
		t.Fatalf("replacement Docker binding was not ready: %v: %s", err, output.String())
	}
	t.Setenv("DOCKER_INSPECT", dockerTargetFixture("another-worktree", "db-dev", newPort))
	output.Reset()
	if err := runAppWaitWithProbe(t.Context(), project, stateDir, waitCommand{Service: []string{"cache"}, Timeout: 300 * time.Millisecond, Output: "json"}, &output, nil); err == nil {
		t.Fatalf("foreign container passed readiness: %s", output.String())
	}
	if err := a.manager.Unregister(id, "cli-owner"); err != nil {
		t.Fatal(err)
	}
}

func dockerTargetFixture(worktree, container, port string) string {
	return fmt.Sprintf(`[{"Id":%q,"Name":%q,"State":{"Running":true},"Config":{"Labels":{"tnl.worktree":%q}},"NetworkSettings":{"Ports":{"6379/tcp":[{"HostIp":"127.0.0.1","HostPort":%q}]}}}]`, strings.Repeat("a", 64), "/"+container, worktree, port)
}

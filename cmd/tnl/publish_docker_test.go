package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/projectconfig"
)

func TestDockerPublisherFollowsReboundPortAndRejectsMissingService(t *testing.T) {
	privatePort := 5432
	selected := dockerPublishTarget{selection: config.DockerSelection{Compose: &config.ComposeSelection{File: "compose.yaml", Project: "shop-perf-k7n2p9", Service: "database"}, ContainerPort: &privatePort}, projectLabel: "shop-perf-k7n2p9"}
	resolver := newDockerPublishResolver(t.Context(), t.TempDir(), selected, false)
	port := "127.0.0.1:49153"
	var lookups int
	resolver.lookup = func(_ context.Context, root, project string, selector config.DockerSelection) (string, error) {
		lookups++
		if root != resolver.root || project != selected.projectLabel || selector.Compose.Service != selected.selection.Compose.Service || *selector.ContainerPort != *selected.selection.ContainerPort {
			t.Fatalf("discovery changed the selected worktree or private port")
		}
		if port == "" {
			return "", errors.New("container stopped")
		}
		return port, nil
	}
	if initial, err := resolver.initial(); err != nil || initial != port || resolver.target() != port || lookups != 1 {
		t.Fatalf("initial target = %q, %v; lookups = %d", initial, err, lookups)
	}
	port = ""
	resolver.mu.Lock()
	resolver.checked = time.Time{}
	resolver.mu.Unlock()
	if current := resolver.target(); current != "" {
		t.Fatalf("stopped container retained stale host port %q", current)
	}
	port = "127.0.0.1:49154"
	resolver.mu.Lock()
	resolver.checked = time.Time{}
	resolver.mu.Unlock()
	if current := resolver.target(); current != port || lookups != 3 {
		t.Fatalf("replacement target = %q; lookups = %d", current, lookups)
	}
	httpResolver := newDockerPublishResolver(t.Context(), resolver.root, selected, true)
	httpResolver.lookup = resolver.lookup
	if target, err := httpResolver.initial(); err != nil || target != "http://"+port {
		t.Fatalf("HTTP target = %q, %v", target, err)
	}
	port = ""
	failed := newDockerPublishResolver(t.Context(), resolver.root, selected, false)
	failed.lookup = resolver.lookup
	if _, err := failed.initial(); err == nil || !strings.Contains(err.Error(), "selected Docker container has no reachable published port") {
		t.Fatalf("missing service diagnostic = %v", err)
	}
}

func TestProjectSnapshotFollowsTheCurrentDockerBinding(t *testing.T) {
	a, state, started := testAppRuntime(t)
	label := "shop-k7n2p9"
	a.project.Worktree = projectconfig.Worktree{Label: projectconfig.WorktreeLabel{FullLabel: label}}
	container := "shop-db"
	port := 5432
	protocol := "postgres"
	a.project.Config.Services["orders"] = config.Service{Protocol: &protocol, Target: &config.ServiceTarget{
		Type: "docker", DockerSelection: config.DockerSelection{Container: &container, ContainerPort: &port},
	}}
	if err := a.manager.Configure(configuredRuntimeServices(a.project)); err != nil {
		t.Fatal(err)
	}
	commands := t.TempDir()
	script := "#!/bin/sh\nif [ \"$1\" = inspect ]; then printf '[{\"Name\":\"/shop-db\",\"State\":{\"Running\":true},\"Config\":{\"Labels\":{\"tnl.worktree\":\"shop-k7n2p9\"}},\"NetworkSettings\":{\"Ports\":{\"5432/tcp\":[{\"HostIp\":\"127.0.0.1\",\"HostPort\":\"%s\"}]},\"Networks\":{}}}]\\n' \"$DOCKER_PORT\"; fi\n"
	if err := os.WriteFile(filepath.Join(commands, "docker"), []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", commands+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("DOCKER_PORT", "49153")
	id, err := a.manager.Reserve("orders", "owner", os.Getpid(), "orders.example:15432")
	if err != nil {
		t.Fatal(err)
	}
	if err := a.manager.RegisterNamed(id, "owner", "127.0.0.1:49153"); err != nil {
		t.Fatal(err)
	}
	<-started
	for _, binding := range []string{"49153", "49154"} {
		t.Setenv("DOCKER_PORT", binding)
		snapshot, err := readAppSnapshot(t.Context(), a.project, state)
		if err != nil {
			t.Fatal(err)
		}
		found := false
		for _, service := range snapshot.Services {
			if service.Name == "orders" {
				found = true
				if service.Target != "127.0.0.1:"+binding {
					t.Fatalf("private Docker mapping became stale after replacement: %+v", service)
				}
			}
		}
		if !found {
			t.Fatal("Docker service disappeared from project snapshot")
		}
	}
}

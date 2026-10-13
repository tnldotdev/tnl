package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/projectconfig"
)

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

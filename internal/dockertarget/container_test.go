package dockertarget

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestContainerPortChecksNameWorktreeAndPublishedPort(t *testing.T) {
	root, bin := t.TempDir(), t.TempDir()
	if err := os.WriteFile(filepath.Join(bin, "docker"), []byte("#!/bin/sh\nprintf '%s\\n' \"$*\" > \"$DOCKER_ARGS\"\nprintf '%s\\n' \"$DOCKER_INSPECT\"\n"), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	args := filepath.Join(root, "args")
	t.Setenv("DOCKER_ARGS", args)
	id := strings.Repeat("a", 64)
	inspect := func(name, label, running, bindings string) string {
		return fmt.Sprintf(`[{"Id":%q,"Name":%q,"State":{"Running":%s},"Config":{"Labels":{"tnl.worktree":%q}},"NetworkSettings":{"Ports":{"5432/tcp":%s}}}]`, id, "/"+name, running, label, bindings)
	}
	const one = `[{"HostIp":"0.0.0.0","HostPort":"49153"}]`
	t.Setenv("DOCKER_INSPECT", inspect("db-dev", "shop-first-k7n2p9", "true", one))
	address, err := ContainerPort(t.Context(), root, "shop-first-k7n2p9", "db-dev", 5432)
	if err != nil || address != "127.0.0.1:49153" {
		t.Fatalf("container binding = %q, %v", address, err)
	}
	data, err := os.ReadFile(args)
	if err != nil || string(data) != "container inspect db-dev\n" {
		t.Fatalf("Docker selection arguments = %q, %v", data, err)
	}
	if address, err = ContainerPort(t.Context(), root, "shop-first-k7n2p9", id[:12], 5432); err != nil || address != "127.0.0.1:49153" {
		t.Fatalf("selected exact container ID = %q, %v", address, err)
	}
	if _, err := ContainerPort(t.Context(), root, "shop-second-m4q8s2", "db-dev", 5432); err == nil {
		t.Fatal("selected a different worktree's container")
	}
	if _, err := ContainerPort(t.Context(), root, "shop-first-k7n2p9", "other-db", 5432); err == nil {
		t.Fatal("selected a different container name")
	}
	if _, err := ContainerPort(t.Context(), root, "shop-first-k7n2p9", strings.Repeat("b", 12), 5432); err == nil {
		t.Fatal("selected a different container ID")
	}
	for name, output := range map[string]string{
		"stopped":       inspect("db-dev", "shop-first-k7n2p9", "false", one),
		"foreign label": inspect("db-dev", "shop-second-m4q8s2", "true", one),
		"no binding":    inspect("db-dev", "shop-first-k7n2p9", "true", `null`),
		"ambiguous":     inspect("db-dev", "shop-first-k7n2p9", "true", `[{"HostIp":"127.0.0.1","HostPort":"49153"},{"HostIp":"::1","HostPort":"49154"}]`),
		"nonlocal":      inspect("db-dev", "shop-first-k7n2p9", "true", `[{"HostIp":"192.0.2.2","HostPort":"49153"}]`),
		"overflow":      strings.Repeat("x", maxInspectOutput+1),
	} {
		t.Run(name, func(t *testing.T) {
			t.Setenv("DOCKER_INSPECT", output)
			if _, err := ContainerPort(t.Context(), root, "shop-first-k7n2p9", "db-dev", 5432); err == nil {
				t.Fatal("accepted unavailable or untrusted binding")
			}
		})
	}
	if _, err := ContainerPort(t.Context(), root, "shop-first-k7n2p9", "--all", 5432); err == nil {
		t.Fatal("accepted Docker option as an identifier")
	}
}

package dockertarget

import (
	"context"
	"flag"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var dockerContainerIntegration = flag.Bool("tnl-docker-container-integration", false, "run disposable Docker container target integration")

func TestIntegrationDockerContainerPortFollowsNamedReplacement(t *testing.T) {
	if !*dockerContainerIntegration {
		t.Skip("requires -tnl-docker-container-integration")
	}
	root := t.TempDir()
	project := fmt.Sprintf("tnlcontainer%x", time.Now().UnixNano())
	file := filepath.Join(root, "compose.yaml")
	const image = "mirror.gcr.io/library/redis:7.4-alpine@sha256:858f009f9709ce576febc734aa78b8f6d624b82571f9ddb6bda4377c833b3499"
	if err := os.WriteFile(file, []byte("services:\n  db:\n    image: "+image+"\n    labels:\n      tnl.worktree: "+project+"\n    ports:\n      - '127.0.0.1::6379'\n"), 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()
	compose := func(args ...string) ([]byte, error) {
		command := exec.CommandContext(ctx, "docker", append([]string{"compose", "--project-directory", root, "--file", file, "--project-name", project}, args...)...)
		output, err := command.CombinedOutput()
		if err != nil {
			return nil, fmt.Errorf("docker compose %s: %w: %s", strings.Join(args, " "), err, output)
		}
		return output, nil
	}
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 30*time.Second)
		defer stop()
		command := exec.CommandContext(cleanup, "docker", "compose", "--project-directory", root, "--file", file, "--project-name", project, "down", "-v", "--remove-orphans")
		if output, err := command.CombinedOutput(); err != nil {
			t.Errorf("clean up disposable Docker project: %v: %s", err, output)
		}
	})
	if _, err := compose("up", "-d"); err != nil {
		t.Fatal(err)
	}
	idOutput, err := compose("ps", "-q", "db")
	if err != nil {
		t.Fatal(err)
	}
	id := strings.TrimSpace(string(idOutput))
	name := project + "-db-1"
	first, err := ContainerPort(ctx, root, project, id, 6379)
	if err != nil {
		t.Fatal(err)
	}
	if byName, err := ContainerPort(ctx, root, project, name, 6379); err != nil || byName != first {
		t.Fatalf("container name resolved %q rather than %q: %v", byName, first, err)
	}
	if _, err := ContainerPort(ctx, root, project+"-other", name, 6379); err == nil {
		t.Fatal("foreign worktree selected this container")
	}
	initial, err := net.DialTimeout("tcp", first, time.Second)
	if err != nil {
		t.Fatalf("initial binding %s is not reachable: %v", first, err)
	}
	initial.Close()
	if _, err := compose("stop"); err != nil {
		t.Fatal(err)
	}
	if _, err := ContainerPort(ctx, root, project, name, 6379); err == nil {
		t.Fatal("stopped container remained selected")
	}
	if _, err := compose("up", "-d", "--force-recreate"); err != nil {
		t.Fatal(err)
	}
	second, err := ContainerPort(ctx, root, project, name, 6379)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ContainerPort(ctx, root, project, id, 6379); err == nil {
		t.Fatal("old container ID selected replacement")
	}
	connection, err := net.DialTimeout("tcp", second, time.Second)
	if err != nil {
		t.Fatalf("replacement binding %s is not reachable: %v", second, err)
	}
	connection.Close()
	t.Logf("named container binding: %s -> %s", first, second)
}

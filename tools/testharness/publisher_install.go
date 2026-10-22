package main

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/testcontainers/testcontainers-go/modules/postgres"
)

// runPublisherInstall owns the privileged Ubuntu boundary. no systemctl, trust
// installation, or sudo invocation runs on the caller's host.
func runPublisherInstall(ctx context.Context, root string) error {
	id := fmt.Sprintf("tnl-publisher-install-%d", time.Now().UnixNano())
	command := func(args ...string) error {
		child := exec.CommandContext(ctx, "docker", args...)
		child.Stdout, child.Stderr = os.Stdout, os.Stderr
		return child.Run()
	}
	if err := command("build", "--file", filepath.Join(root, "tests/integration/fixtures/publisher-install/test.Dockerfile"), "--tag", id, root); err != nil {
		return err
	}
	defer exec.Command("docker", "image", "rm", id).Run()
	database, err := postgres.Run(ctx, postgresImage, postgres.BasicWaitStrategies(), loopbackPort("5432"))
	if err != nil {
		return err
	}
	defer terminate(database)
	address, err := database.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		return err
	}
	parsed, err := url.Parse(address)
	if err != nil {
		return err
	}
	parsed.Host = "127.0.0.1:5432"
	address = parsed.String()
	// the only bind mounts are read-only source and the Docker API used to own
	// disposable Compose fixtures. cgroups and systemd belong to this container.
	if err := command("run", "--detach", "--name", id, "--privileged", "--cgroupns=private", "--env", "GOMAXPROCS", "--env", "GOFLAGS", "--network=container:"+database.GetContainerID(), "--tmpfs", "/run", "--tmpfs", "/run/lock", "--tmpfs", "/tmp:exec", "--mount", "type=bind,src="+root+",dst=/src,readonly", "--mount", "type=bind,src=/var/run/docker.sock,dst=/var/run/docker.sock", id); err != nil {
		return err
	}
	defer exec.Command("docker", "rm", "--force", id).Run()
	for range 100 {
		status, _ := exec.CommandContext(ctx, "docker", "exec", id, "systemctl", "is-system-running").Output()
		if strings.TrimSpace(string(status)) == "running" || strings.TrimSpace(string(status)) == "degraded" {
			break
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
	}
	return command("exec", "--workdir", "/src", id, "go", "test", "-race", "-v", "./cmd/tnl", "-run=^TestIntegrationPublisherInstall", "-count=1", "-timeout=8m", "-args", "-tnl-test-tier=integration", "-tnl-test-postgres-url="+address, "-tnl-publisher-install-container", "-tnl-publisher-install-network="+database.GetContainerID(), "-tnl-publisher-install-image="+id)
}

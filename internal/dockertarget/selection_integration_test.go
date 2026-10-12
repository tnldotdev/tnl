package dockertarget

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/testutil"
)

func TestIntegrationIdenticalComposeFilesSeparateWorktreeDatabasePorts(t *testing.T) {
	testutil.RequireTestTier(t, testutil.TestTierIntegration)
	const content = `services:
  db:
    image: public.ecr.aws/docker/library/postgres:17.6-alpine@sha256:ef257d85f76e48da1c64832459b59fcaba1a4dac97bf5d7450c77753542eee94
    environment:
      POSTGRES_USER: shop
      POSTGRES_PASSWORD: devpassword
      POSTGRES_DB: shop
    ports:
      - "127.0.0.1::5432"
    volumes:
      - db-data:/var/lib/postgresql/data
volumes:
  db-data:
`
	port := 5432
	type instance struct {
		root, label, address string
		container            Container
	}
	var started []instance
	for _, label := range []string{"shop-first-k7n2p9", "shop-second-m4q8s2"} {
		root, err := filepath.EvalSymlinks(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, "compose.yaml"), []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
		cleanup := func() {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			command := exec.CommandContext(ctx, "docker", "compose", "--project-directory", root, "--file", filepath.Join(root, "compose.yaml"), "--project-name", label, "down", "--volumes", "--remove-orphans")
			command.Dir = root
			if output, err := command.CombinedOutput(); err != nil {
				t.Errorf("remove disposable Compose project: %v (%s)", err, output)
			}
		}
		t.Cleanup(cleanup)
		ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
		command := exec.CommandContext(ctx, "docker", "compose", "--project-directory", root, "--file", filepath.Join(root, "compose.yaml"), "--project-name", label, "up", "-d", "db")
		command.Dir = root
		output, err := command.CombinedOutput()
		cancel()
		if err != nil {
			t.Fatalf("start disposable Compose project: %v (%s)", err, output)
		}
		selection := config.DockerSelection{Compose: &config.ComposeSelection{File: "compose.yaml", Project: label, Service: "db"}, ContainerPort: &port}
		container, err := SelectContainer(t.Context(), root, label, selection)
		if err != nil {
			t.Fatal(err)
		}
		address, err := HostPort(container, port, false)
		if err != nil {
			t.Fatal(err)
		}
		started = append(started, instance{root: root, label: label, container: container, address: address})
	}
	if started[0].address == started[1].address || slices.Equal(started[0].container.Networks, started[1].container.Networks) {
		t.Fatalf("identical Compose files shared host port or Docker network: %+v", started)
	}
}

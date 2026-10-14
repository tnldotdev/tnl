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

var composeIntegration = flag.Bool("tnl-compose-integration", false, "run disposable Docker Compose host-port integration")

func TestIntegrationComposePortFollowsReplacement(t *testing.T) {
	if !*composeIntegration {
		t.Skip("requires -tnl-compose-integration")
	}
	root := t.TempDir()
	project := fmt.Sprintf("tnlcompose%x", time.Now().UnixNano())
	file := filepath.Join(root, "compose.yaml")
	const image = "mirror.gcr.io/library/redis:7.4-alpine@sha256:858f009f9709ce576febc734aa78b8f6d624b82571f9ddb6bda4377c833b3499"
	if err := os.WriteFile(file, []byte("services:\n  db:\n    image: "+image+"\n    ports:\n      - '127.0.0.1::6379'\n"), 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()
	compose := func(args ...string) error {
		command := exec.CommandContext(ctx, "docker", append([]string{"compose", "--project-directory", root, "--file", file, "--project-name", project}, args...)...)
		output, err := command.CombinedOutput()
		if err != nil {
			return fmt.Errorf("docker compose %s: %w: %s", strings.Join(args, " "), err, output)
		}
		return nil
	}
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 30*time.Second)
		defer stop()
		command := exec.CommandContext(cleanup, "docker", "compose", "--project-directory", root, "--file", file, "--project-name", project, "down", "-v", "--remove-orphans")
		if output, err := command.CombinedOutput(); err != nil {
			t.Errorf("clean up Compose project: %v: %s", err, output)
		}
	})
	if err := compose("up", "-d"); err != nil {
		t.Fatal(err)
	}
	first, err := ComposePort(ctx, root, "compose.yaml", project, "db", 6379)
	if err != nil {
		t.Fatal(err)
	}
	if conn, err := net.DialTimeout("tcp", first, time.Second); err != nil {
		t.Fatalf("first host binding %s: %v", first, err)
	} else {
		conn.Close()
	}
	if err := compose("stop"); err != nil {
		t.Fatal(err)
	}
	if _, err := ComposePort(ctx, root, "compose.yaml", project, "db", 6379); err == nil {
		t.Fatal("stopped container retained a live binding")
	}
	if err := compose("up", "-d", "--force-recreate"); err != nil {
		t.Fatal(err)
	}
	second, err := ComposePort(ctx, root, "compose.yaml", project, "db", 6379)
	if err != nil {
		t.Fatal(err)
	}
	if conn, err := net.DialTimeout("tcp", second, time.Second); err != nil {
		t.Fatalf("replacement host binding %s: %v", second, err)
	} else {
		conn.Close()
	}
	t.Logf("replaced Compose binding: %s -> %s", first, second)
}

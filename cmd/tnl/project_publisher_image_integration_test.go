package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/testutil"
)

func TestIntegrationPublisherDevImageLoadsTypeScript(t *testing.T) {
	testutil.RequireTestTier(t, testutil.TestTierIntegration)
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(root, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "tnl.config.ts"), []byte(`export default ({worktree}) => ({
  services: {web: {target: {type: "address", address: 3000}, tunnel: {name: "web-" + worktree.label.id}}}
});`), 0644); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	user := fmt.Sprintf("%d:%d", os.Getuid(), os.Getgid())
	state := fmt.Sprintf("/state:uid=%d,gid=%d,mode=0700", os.Getuid(), os.Getgid())
	command := exec.CommandContext(ctx, "docker", "run", "--rm", "--user", user, "--tmpfs", state,
		"--volume", root+":/fixture", "--entrypoint", "/usr/local/bin/tnl",
		"tnl:publisher-dev-integration", "--no-telemetry", "config", "check", "--config", "/fixture/tnl.config.ts", "--state-dir", "/state")
	output, err := command.CombinedOutput()
	if err != nil || !strings.Contains(string(output), "valid") {
		t.Fatalf("development publisher image did not load TypeScript config: %v (%s)", err, output)
	}
}

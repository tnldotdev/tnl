package init

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRunInitInstallPreservesCommandContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	go func() {
		time.Sleep(20 * time.Millisecond)
		cancel()
	}()
	err := runInitInstall(ctx, t.TempDir(), []string{"sh", "-c", "exec sleep 30"})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("install error = %v", err)
	}
}

func TestInitDoesNotChooseAPackageManagerWhenLockfilesConflict(t *testing.T) {
	root := copyInitFixture(t, "next")
	if err := os.WriteFile(filepath.Join(root, "package-lock.json"), []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	plan, err := planInit(t.Context(), root)
	if err != nil {
		t.Fatal(err)
	}
	if !plan.InstallBlocked || len(plan.Actions) == 0 || !strings.Contains(plan.Actions[0], "run tnl init again") {
		t.Fatalf("plan = %#v", plan)
	}
}

func TestInitDetectsPackageManagerFromWorkspaceAncestor(t *testing.T) {
	workspace := t.TempDir()
	root := filepath.Join(workspace, "apps", "web")
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	for path, data := range map[string]string{
		filepath.Join(workspace, "package.json"):   `{"packageManager":"pnpm@10","workspaces":["apps/*"]}`,
		filepath.Join(workspace, "pnpm-lock.yaml"): "lockfileVersion: '9.0'\n",
		filepath.Join(root, "package.json"):        `{"dependencies":{"vite":"8.2.2"}}`,
	} {
		if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	plan, err := planInit(t.Context(), root)
	if err != nil {
		t.Fatal(err)
	}
	if plan.PackageManager != "pnpm" || plan.Root != root {
		t.Fatalf("plan = %#v", plan)
	}
}

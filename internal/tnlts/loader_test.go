package tnlts

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLoadUsesImplicitVersionAndFactoryContext(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "tnl.ts")
	source := `export default async ({cwd, env, worktree}: any) => ({
  server: env.TNL_SERVER === undefined ? "https://control.example.com" : "leaked",
  tunnel: {subdomain: worktree.label},
  publish: {target: 3000},
  dev: {command: ["pnpm", "dev"], startupTimeout: "30s"},
});`
	if err := os.WriteFile(path, []byte(source), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TNL_SERVER", "secret")
	value, err := Load(t.Context(), path, directory)
	if err != nil {
		t.Fatal(err)
	}
	if value.Server == nil || *value.Server != "https://control.example.com" || value.Tunnel == nil || value.Tunnel.Subdomain == nil ||
		value.Publish == nil || value.Publish.Target == nil || string(*value.Publish.Target) != "3000" ||
		value.Dev == nil || value.Dev.StartupTimeout == nil || value.Dev.StartupTimeout.Value() != 30*time.Second {
		t.Fatalf("config = %#v", value)
	}
}

func TestLoadRejectsVersionedOrDaemonResult(t *testing.T) {
	for name, source := range map[string]string{
		"version": `export default {version: 1};`,
		"tnld":    `export default {tnld: {mode: "relay"}};`,
		"snake":   `export default {tunnel: {allow_ip: ["192.0.2.1"]}};`,
	} {
		path := filepath.Join(t.TempDir(), "tnl.ts")
		if err := os.WriteFile(path, []byte(source), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(t.Context(), path, filepath.Dir(path)); err == nil {
			t.Fatalf("%s result was accepted", name)
		}
	}
}

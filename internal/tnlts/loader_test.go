package tnlts

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLoadUsesImplicitVersionAndFactoryContext(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "tnl.config.ts")
	source := `export default async ({cwd, env, worktree}: any) => ({
  server: env.TNL_SERVER === undefined ? "https://control.example.com" : "leaked",
  tunnel: {subdomain: worktree.label},
  publish: {target: 3000},
  dev: {command: ["pnpm", "dev"], startupTimeout: "30s"},
  services: {api: {directory: "apps/api", dev: {startupTimeout: "45s"}}},
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
		value.Dev == nil || value.Dev.StartupTimeout == nil || value.Dev.StartupTimeout.Value() != 30*time.Second ||
		value.Services["api"].Directory == nil || *value.Services["api"].Directory != "apps/api" ||
		value.Services["api"].Dev == nil || value.Services["api"].Dev.StartupTimeout == nil ||
		value.Services["api"].Dev.StartupTimeout.Value() != 45*time.Second {
		t.Fatalf("config = %#v", value)
	}
}

func TestLoadRejectsVersionedOrDaemonResult(t *testing.T) {
	for name, source := range map[string]string{
		"version": `export default {version: 1};`,
		"tnld":    `export default {tnld: {mode: "relay"}};`,
		"snake":   `export default {tunnel: {allow_ip: ["192.0.2.1"]}};`,
	} {
		path := filepath.Join(t.TempDir(), "tnl.config.ts")
		if err := os.WriteFile(path, []byte(source), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(t.Context(), path, filepath.Dir(path)); err == nil {
			t.Fatalf("%s result was accepted", name)
		}
	}
}

func TestLoadAppliesStaticValidationToNestedServices(t *testing.T) {
	for name, source := range map[string]string{
		"duration":  `export default {services: {api: {dev: {startupTimeout: "+1s"}}}};`,
		"target":    `export default {services: {api: {publish: {target: "https://example.com"}}}};`,
		"ip":        `export default {services: {api: {tunnel: {allowIP: ["192.0.2.7/24"]}}}};`,
		"duplicate": `export default {services: {api: {tunnel: {allowIP: ["192.0.2.1", "192.0.2.1/32"]}}}};`,
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "tnl.config.ts")
			if err := os.WriteFile(path, []byte(source), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := Load(t.Context(), path, filepath.Dir(path)); err == nil {
				t.Fatal("invalid TypeScript service configuration was accepted")
			}
		})
	}
}

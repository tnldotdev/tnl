package projectconfig

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
	worktree := Worktree{Root: directory, Name: filepath.Base(directory), Label: "project-12345678"}
	value, err := loadTypeScript(t.Context(), path, directory, worktree)
	if err != nil {
		t.Fatal(err)
	}
	if value.Server == nil || *value.Server != "https://control.example.com" || value.Tunnel == nil || value.Tunnel.Subdomain == nil ||
		*value.Tunnel.Subdomain != worktree.Label ||
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
		if _, err := loadTypeScript(t.Context(), path, filepath.Dir(path), Worktree{}); err == nil {
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
			if _, err := loadTypeScript(t.Context(), path, filepath.Dir(path), Worktree{}); err == nil {
				t.Fatal("invalid TypeScript service configuration was accepted")
			}
		})
	}
}

func TestUnmarshalTypeScriptTNLRejectsStaticFieldNames(t *testing.T) {
	if _, err := unmarshalTypeScriptTNL([]byte(`{"tunnel":{"allow_ip":["192.0.2.1"]}}`)); err == nil {
		t.Fatal("static snake_case field was accepted as TypeScript configuration")
	}
}

func TestTypeScriptServicesUseCamelCaseFields(t *testing.T) {
	value, err := unmarshalTypeScriptTNL([]byte(`{
  "team":"Team One",
  "services":{"web":{"tunnel":{"allowIP":["192.0.2.1"],"ephemeral":true},"dev":{"startupTimeout":"30s"}}}
}`))
	if err != nil {
		t.Fatal(err)
	}
	service := value.Services["web"]
	if service.Tunnel == nil || len(service.Tunnel.AllowIP) != 1 || service.Tunnel.Ephemeral == nil || !*service.Tunnel.Ephemeral ||
		service.Dev == nil || service.Dev.StartupTimeout == nil || service.Dev.StartupTimeout.Value() != 30*time.Second {
		t.Fatalf("service = %#v", service)
	}
	if _, err := unmarshalTypeScriptTNL([]byte(`{"services":{"web":{"dev":{"startup_timeout":"30s"}}}}`)); err == nil {
		t.Fatal("static service field name was accepted in TypeScript")
	}
}

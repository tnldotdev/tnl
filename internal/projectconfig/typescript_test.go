package projectconfig

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLoadUsesImplicitVersionAndFactoryContext(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "tnl.config.ts")
	source := `export default async ({cwd, env, worktree}: any) => ({
  server: env.TNL_SERVER === undefined ? "https://control.example.com" : "leaked",
  tunnel: {subdomain: worktree.label, requestLimit: 750},
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
		value.Tunnel.RequestLimit == nil || *value.Tunnel.RequestLimit != 750 ||
		value.Publish == nil || value.Publish.Target == nil || string(*value.Publish.Target) != "3000" ||
		value.Dev == nil || value.Dev.StartupTimeout == nil || value.Dev.StartupTimeout.Value() != 30*time.Second ||
		value.Services["api"].Directory == nil || *value.Services["api"].Directory != "apps/api" ||
		value.Services["api"].Dev == nil || value.Services["api"].Dev.StartupTimeout == nil ||
		value.Services["api"].Dev.StartupTimeout.Value() != 45*time.Second {
		t.Fatalf("config = %#v", value)
	}
}

func TestLoadRejectsVersionedOrDaemonResult(t *testing.T) {
	for field, source := range map[string]string{
		"version":  `export default {version: 1};`,
		"tnld":     `export default {tnld: {mode: "relay"}};`,
		"allow_ip": `export default {tunnel: {allow_ip: ["192.0.2.1"]}};`,
	} {
		path := filepath.Join(t.TempDir(), "tnl.config.ts")
		if err := os.WriteFile(path, []byte(source), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := loadTypeScript(t.Context(), path, filepath.Dir(path), Worktree{}); err == nil || !strings.Contains(err.Error(), `unknown TypeScript configuration field "`+field+`"`) {
			t.Fatalf("%s result error = %v, want unknown-field rejection", field, err)
		}
	}
}

func TestLoadAppliesStaticValidationToNestedServices(t *testing.T) {
	for name, test := range map[string]struct{ source, category string }{
		"request limit": {`export default {services: {api: {tunnel: {requestLimit: 0}}}};`, "services.api: tunnel.request_limit must be greater than zero"},
		"duration":      {`export default {services: {api: {dev: {startupTimeout: "+1s"}}}};`, "invalid duration syntax"},
		"target":        {`export default {services: {api: {publish: {target: "https://example.com"}}}};`, "services.api: publish.target:"},
		"ip":            {`export default {services: {api: {tunnel: {allowIP: ["192.0.2.7/24"]}}}};`, "must be a canonical IP address or prefix"},
		"duplicate":     {`export default {services: {api: {tunnel: {allowIP: ["192.0.2.1", "192.0.2.1/32"]}}}};`, "is duplicated"},
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "tnl.config.ts")
			if err := os.WriteFile(path, []byte(test.source), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := loadTypeScript(t.Context(), path, filepath.Dir(path), Worktree{}); err == nil || !strings.Contains(err.Error(), test.category) {
				t.Fatalf("invalid TypeScript service error = %v, want %q", err, test.category)
			}
		})
	}
}

func TestLoadExitsWithActiveHandles(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "tnl.config.ts")
	if err := os.WriteFile(path, []byte(`setInterval(() => {}, 60_000); export default {};`), 0o600); err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	if _, err := loadTypeScript(t.Context(), path, directory, Worktree{}); err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(started); elapsed > 5*time.Second {
		t.Fatalf("configuration with active handle loaded in %s", elapsed)
	}
}

func TestLoadDoesNotExposeProjectOutputOrExceptions(t *testing.T) {
	const secret = "PROJECT_CONFIG_SECRET_SENTINEL"
	for name, test := range map[string]struct {
		source  string
		message string
	}{
		"import": {
			fmt.Sprintf(`console.log(%q); console.error(%q); throw new Error(%q);`, secret, secret, secret),
			"failed to import tnl.config.ts",
		},
		"evaluation": {
			fmt.Sprintf(`console.log(%q); export default () => { console.error(%q); throw new Error(%q); };`, secret, secret, secret),
			"failed to evaluate tnl.config.ts",
		},
		"cause": {
			fmt.Sprintf(`export default () => { throw new Error("outer", {cause: new Error(%q)}); };`, secret),
			"failed to evaluate tnl.config.ts",
		},
		"noncoercible": {
			fmt.Sprintf(`export default () => { throw {toString() { throw new Error(%q); }}; };`, secret),
			"failed to evaluate tnl.config.ts",
		},
	} {
		t.Run(name, func(t *testing.T) {
			directory := t.TempDir()
			path := filepath.Join(directory, "tnl.config.ts")
			if err := os.WriteFile(path, []byte(test.source), 0o600); err != nil {
				t.Fatal(err)
			}
			_, err := loadTypeScript(t.Context(), path, directory, Worktree{})
			if err == nil || !strings.Contains(err.Error(), test.message) {
				t.Fatalf("load error = %v, want %q", err, test.message)
			}
			if strings.Contains(err.Error(), secret) {
				t.Fatalf("load error exposed project secret: %v", err)
			}
		})
	}
}

func TestLoadSurfacesStableLoaderValidationErrors(t *testing.T) {
	for name, test := range map[string]struct {
		source  string
		message string
	}{
		"missing default export": {`export const config = {};`, "tnl.config.ts must have a default export"},
		"invalid export":         {`export default "not an object";`, "tnl.config.ts must export a configuration object or factory"},
	} {
		t.Run(name, func(t *testing.T) {
			directory := t.TempDir()
			path := filepath.Join(directory, "tnl.config.ts")
			if err := os.WriteFile(path, []byte(test.source), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := loadTypeScript(t.Context(), path, directory, Worktree{}); err == nil || !strings.Contains(err.Error(), test.message) {
				t.Fatalf("load error = %v, want %q", err, test.message)
			}
		})
	}
}

func TestLoadPreservesParentCancellation(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "tnl.config.ts")
	readyPath := filepath.Join(directory, "ready")
	source := fmt.Sprintf(`
import {writeFileSync} from "node:fs";
export default async () => {
  writeFileSync(%q, "ready");
  setInterval(() => {}, 60_000);
  await new Promise(() => {});
};`, readyPath)
	if err := os.WriteFile(path, []byte(source), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	errorChannel := make(chan error, 1)
	go func() {
		_, err := loadTypeScript(ctx, path, directory, Worktree{})
		errorChannel <- err
	}()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, err := os.Stat(readyPath); err == nil {
			break
		} else if !errors.Is(err, os.ErrNotExist) {
			t.Fatal(err)
		}
		if time.Now().After(deadline) {
			t.Fatal("TypeScript configuration did not begin evaluation")
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	select {
	case err := <-errorChannel:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("load error = %v, want context.Canceled", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("TypeScript configuration did not stop after cancellation")
	}
}

func TestLoadPreservesParentDeadline(t *testing.T) {
	ctx, cancel := context.WithDeadline(t.Context(), time.Now().Add(-time.Second))
	defer cancel()
	if _, err := loadTypeScript(ctx, "tnl.config.ts", ".", Worktree{}); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("load error = %v, want context.DeadlineExceeded", err)
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

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
	source := `export default async ({cwd, env, worktree, project}: any) => ({
  server: env.TNL_SERVER === undefined ? "https://control.example.com" : "leaked",
  feedback: true,
  requestInspection: "detailed",
  tunnel: {domain: "routes.example.test", requestLimit: 750},
  publish: {target: 3000},
  readiness: {path: "/health", status: 204},
  services: {
    api: {directory: "apps/api", requestInspection: "summary", tunnel: {name: worktree.label.fullLabel}, readiness: {path: "/status"}},
    site: {tunnel: {publicURL: "https://site.example.test", open: true}, paths: {"/api": "api", "/v1": {service: "api", stripPrefix: true}}},
  },
});`
	if err := os.WriteFile(path, []byte(source), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TNL_SERVER", "secret")
	worktree := Worktree{Root: directory, Name: filepath.Base(directory), Label: WorktreeLabel{Project: "project", ID: "12345678", FullLabel: "project-12345678"}}
	value, err := loadTypeScript(t.Context(), path, directory, worktree)
	if err != nil {
		t.Fatal(err)
	}
	if value.Server == nil || *value.Server != "https://control.example.com" || value.Feedback == nil || !*value.Feedback || value.Tunnel == nil || value.Tunnel.Domain == nil ||
		value.RequestInspection == nil || *value.RequestInspection != "detailed" ||
		value.Services["api"].RequestInspection == nil || *value.Services["api"].RequestInspection != "summary" ||
		*value.Tunnel.Domain != "routes.example.test" || value.Services["api"].Tunnel == nil ||
		value.Services["api"].Tunnel.Name == nil || *value.Services["api"].Tunnel.Name != worktree.Label.FullLabel ||
		value.Services["site"].Tunnel == nil || value.Services["site"].Tunnel.PublicURL == nil ||
		*value.Services["site"].Tunnel.PublicURL != "https://site.example.test" ||
		value.Services["site"].Tunnel.Open == nil || !*value.Services["site"].Tunnel.Open ||
		value.Services["site"].Paths["/api"].Service != "api" || !value.Services["site"].Paths["/v1"].StripPrefix ||
		value.Tunnel.RequestLimit == nil || *value.Tunnel.RequestLimit != 750 ||
		value.Publish == nil || value.Publish.Target == nil || string(*value.Publish.Target) != "3000" ||
		value.Readiness == nil || value.Readiness.Path != "/health" || value.Readiness.Status == nil || *value.Readiness.Status != 204 ||
		value.Services["api"].Directory == nil || *value.Services["api"].Directory != "apps/api" ||
		value.Services["api"].Readiness == nil || value.Services["api"].Readiness.Path != "/status" {
		t.Fatalf("config = %#v", value)
	}
}

func TestLoadResolvesProjectImportsAndTsconfigPaths(t *testing.T) {
	root := t.TempDir()
	api := filepath.Join(root, "apps", "api")
	for _, directory := range []string{
		filepath.Join(api, "src", "api"),
		filepath.Join(api, "node_modules", "nested-package"),
		filepath.Join(root, "node_modules", "example-package"),
	} {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for name, source := range map[string]string{
		filepath.Join(root, "tnl.config.ts"):                                 `import {server} from "./apps/api/settings.ts"; export default {server};`,
		filepath.Join(api, "settings.ts"):                                    `import {domain} from "@/api/errors"; import {origin} from "example-package"; import {subdomain} from "nested-package"; export const server: string = origin + subdomain + domain;`,
		filepath.Join(api, "src", "api", "errors.ts"):                        `export const domain = "example.com";`,
		filepath.Join(api, "node_modules", "nested-package", "package.json"): `{"name":"nested-package","version":"1.0.0","type":"module","exports":"./index.js"}`,
		filepath.Join(api, "node_modules", "nested-package", "index.js"):     `export const subdomain = "api.";`,
		filepath.Join(root, "tsconfig.json"):                                 `{"compilerOptions":{"strict":true}}`,
		filepath.Join(root, "tsconfig.base.json"): `{// paths are relative to this file
  "compilerOptions":{"baseUrl":".","paths":{"@/*":["./apps/api/src/*",],}},}`,
		filepath.Join(api, "tsconfig.json"):                                    `{"extends":"../../tsconfig.base.json"}`,
		filepath.Join(root, "node_modules", "example-package", "package.json"): `{"name":"example-package","version":"1.0.0","type":"module","exports":"./index.js"}`,
		filepath.Join(root, "node_modules", "example-package", "index.js"):     `export const origin = "https://";`,
	} {
		if err := os.WriteFile(name, []byte(source), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	value, err := loadTypeScript(t.Context(), filepath.Join(root, "tnl.config.ts"), root, Worktree{})
	if err != nil {
		t.Fatal(err)
	}
	if value.Server == nil || *value.Server != "https://api.example.com" {
		t.Fatalf("server = %v", value.Server)
	}
	if outputs, err := filepath.Glob(filepath.Join(root, ".tnl-config-*.mjs")); err != nil || len(outputs) != 0 {
		t.Fatalf("temporary bundles after loading: %v, %v", outputs, err)
	}
}

func TestLoadDoesNotExposeBuildErrors(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "tnl.config.ts")
	const secret = "PROJECT_CONFIG_SECRET_SENTINEL"
	if err := os.WriteFile(path, []byte(`import {value} from "./`+secret+`.ts"; export default {server: value};`), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := loadTypeScript(t.Context(), path, root, Worktree{})
	if err == nil || !strings.Contains(err.Error(), "failed to import tnl.config.ts") || strings.Contains(err.Error(), secret) {
		t.Fatalf("build error = %v", err)
	}
	if outputs, err := filepath.Glob(filepath.Join(root, ".tnl-config-*.mjs")); err != nil || len(outputs) != 0 {
		t.Fatalf("temporary bundles after build failure: %v, %v", outputs, err)
	}
}

func TestFactoryReceivesRelativeProjectDirectoryAndFrozenLabel(t *testing.T) {
	root := t.TempDir()
	canonical, err := filepath.EvalSymlinks(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, relative := range []string{".", "apps/api"} {
		project := filepath.Join(root, relative)
		if err := os.MkdirAll(project, 0o700); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(project, "tnl.config.ts")
		source := fmt.Sprintf(`export default ({worktree, project}) => {
  if (project.relativeDirectory !== %q || !Object.isFrozen(worktree.label) || "checkout" in worktree.label) throw new Error("context mismatch");
  return {publish: {target: 3000}};
};`, relative)
		if err := os.WriteFile(path, []byte(source), 0o600); err != nil {
			t.Fatal(err)
		}
		worktree := ApplyWorktreeHashSalt(Worktree{Root: canonical, Name: "shop"}, canonical, [32]byte{1})
		if _, err := loadTypeScript(t.Context(), path, project, worktree); err != nil {
			t.Fatalf("relative project %q: %v", relative, err)
		}
	}
}

func TestLoadAliasesValidatesComputedServiceReferences(t *testing.T) {
	for _, test := range []struct {
		service string
		valid   bool
	}{{"api", true}, {"missing", false}} {
		directory := t.TempDir()
		path := filepath.Join(directory, "tnl.config.ts")
		source := fmt.Sprintf(`export default () => ({ services: {api: {}}, aliases: {review: {service: [%q].join(""), name: "api.shop", allowAllIPs: true}} });`, test.service)
		if err := os.WriteFile(path, []byte(source), 0o600); err != nil {
			t.Fatal(err)
		}
		value, err := loadTypeScript(t.Context(), path, directory, Worktree{Root: directory})
		if (err == nil) != test.valid {
			t.Fatalf("computed alias service %q: %v", test.service, err)
		}
		if test.valid && (value.Aliases["review"].RelativeName("review") != "api.shop" || value.Aliases["review"].AllowAllIPs == nil || !*value.Aliases["review"].AllowAllIPs) {
			t.Fatal("TypeScript alias fields were not normalized")
		}
	}
}

func TestLoadRejectsVersionedOrDaemonResult(t *testing.T) {
	for field, source := range map[string]string{
		"version":         `export default {version: 1};`,
		"tnld":            `export default {tnld: {mode: "relay"}};`,
		"allow_ip":        `export default {tunnel: {allow_ip: ["192.0.2.1"]}};`,
		"allow_providers": `export default {tunnel: {allow_providers: ["github", "stripe"]}};`,
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
		"service server":     {`export default {services: {api: {server: "https://control.example"}}};`, `unknown TypeScript configuration field "server"`},
		"service team":       {`export default {services: {api: {team: "studio"}}};`, `unknown TypeScript configuration field "team"`},
		"request limit":      {`export default {services: {api: {tunnel: {requestLimit: 0}}}};`, "services.api: tunnel.request_limit must be greater than zero"},
		"request inspection": {`export default {services: {api: {requestInspection: "all"}}};`, "services.api.request_inspection: must be summary or detailed"},
		"retired dev":        {`export default {services: {api: {dev: {startupTimeout: "+1s"}}}};`, "dev"},
		"target":             {`export default {services: {api: {publish: {target: "https://example.com/path"}}}};`, "services.api: publish.target:"},
		"ip":                 {`export default {services: {api: {tunnel: {allowIP: ["192.0.2.7/24"]}}}};`, "must be a canonical IP address or prefix"},
		"duplicate":          {`export default {services: {api: {tunnel: {allowIP: ["192.0.2.1", "192.0.2.1/32"]}}}};`, "is duplicated"},
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
		"direct stdout": {
			fmt.Sprintf(`import {writeSync} from "node:fs"; writeSync(1, %q); throw new Error(%q);`, secret, secret),
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

func TestLoadRejectsProjectWritesToResponseChannel(t *testing.T) {
	for _, output := range []string{"project output", "RPROJECT_CONFIG_SECRET_SENTINEL"} {
		directory := t.TempDir()
		path := filepath.Join(directory, "tnl.config.ts")
		source := fmt.Sprintf(`import {writeSync} from "node:fs"; writeSync(1, %q); export default {};`, output)
		if err := os.WriteFile(path, []byte(source), 0o600); err != nil {
			t.Fatal(err)
		}
		_, err := loadTypeScript(t.Context(), path, directory, Worktree{})
		if err == nil || !strings.Contains(err.Error(), "invalid result from loader") || strings.Contains(err.Error(), output) {
			t.Fatalf("unexpected response channel result: %v", err)
		}
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
  "services":{"web":{"tunnel":{"allowIP":["192.0.2.1"],"ephemeral":true},"readiness":{"path":"/health","status":204}}}
}`))
	if err != nil {
		t.Fatal(err)
	}
	service := value.Services["web"]
	if service.Tunnel == nil || len(service.Tunnel.AllowIP) != 1 || service.Tunnel.Ephemeral == nil || !*service.Tunnel.Ephemeral ||
		service.Readiness == nil || service.Readiness.Path != "/health" || service.Readiness.Status == nil || *service.Readiness.Status != 204 {
		t.Fatalf("service = %#v", service)
	}
	if _, err := unmarshalTypeScriptTNL([]byte(`{"services":{"web":{"dev":{"startup_timeout":"30s"}}}}`)); err == nil {
		t.Fatal("static service field name was accepted in TypeScript")
	}
}

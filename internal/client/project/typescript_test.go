package project

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/config"
)

func TestLoadUsesImplicitVersionAndFactoryContext(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "tnl.config.ts")
	source := `export default async ({cwd, env, worktree, project}: any) => ({
  server: env.TNL_SERVER === undefined ? "https://control.example.com" : "leaked",
  feedback: true,
  inspection: {mode: "none"},
  services: {api: {}, site: {}},
  deployments: {local: {targets: {
    api: {domain: "routes.example.test", address: 3000, inspection: {mode: "summary"}, name: worktree.label.fullLabel, http: {requestBodyIdleTimeout: "45s", readiness: {path: "/status"}, limits: {total: 20, rate: {count: 5, per: "1m"}, concurrency: 750}}},
    site: {hostname: "site.example.test", http: {open: true, paths: {"/api": "api", "/v1": {service: "api", stripPrefix: true}}}},
  }}},
});`
	if err := os.WriteFile(path, []byte(source), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TNL_SERVER", "secret")
	worktree := Worktree{Root: directory, Name: filepath.Base(directory), Label: WorktreeLabel{Project: "project", ID: "12345678", FullLabel: "project-12345678"}}
	declaration, err := loadTypeScript(t.Context(), path, directory, worktree)
	if err != nil {
		t.Fatal(err)
	}
	value, err := config.ResolveDeployment(declaration, "local")
	if err != nil {
		t.Fatal(err)
	}
	if value.Server == nil || *value.Server != "https://control.example.com" || value.Feedback == nil || !*value.Feedback || value.Services["api"].Domain == nil ||
		value.Inspection == nil || value.Inspection.Mode == nil || *value.Inspection.Mode != "none" ||
		value.Services["api"].Inspection == nil || value.Services["api"].Inspection.Mode == nil || *value.Services["api"].Inspection.Mode != "summary" ||
		*value.Services["api"].Domain != "routes.example.test" ||
		value.Services["api"].Name == nil || *value.Services["api"].Name != worktree.Label.FullLabel ||
		value.Services["site"].Hostname == nil || *value.Services["site"].Hostname != "site.example.test" ||
		value.Services["site"].HTTP.Open == nil || !*value.Services["site"].HTTP.Open ||
		value.Services["site"].HTTP.Paths["/api"].Service != "api" || !value.Services["site"].HTTP.Paths["/v1"].StripPrefix ||
		value.Services["api"].HTTP.Limits == nil || value.Services["api"].HTTP.Limits.Concurrency == nil || *value.Services["api"].HTTP.Limits.Concurrency != 750 ||
		value.Services["api"].HTTP.Limits.Total == nil || *value.Services["api"].HTTP.Limits.Total != 20 ||
		value.Services["api"].HTTP.Limits.Rate == nil || value.Services["api"].HTTP.Limits.Rate.Count == nil || *value.Services["api"].HTTP.Limits.Rate.Count != 5 ||
		value.Services["api"].HTTP.Limits.Rate.Per == nil || value.Services["api"].HTTP.Limits.Rate.Per.Value() != time.Minute ||
		value.Services["api"].HTTP.RequestBodyIdleTimeout == nil || value.Services["api"].HTTP.RequestBodyIdleTimeout.Value() != 45*time.Second ||
		value.Services["api"].Target == nil || string(*value.Services["api"].Target.Address) != "3000" ||
		value.Services["api"].HTTP.Readiness == nil || value.Services["api"].HTTP.Readiness.Path != "/status" {
		t.Fatalf("config = %#v", value)
	}
}

func TestResolvePreservesTypeScriptExactDNSHostname(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "tnl.config.ts")
	if err := os.WriteFile(path, []byte(`export default {services: {api: {}}, deployments: {local: {targets: {api: {hostname: "api.example.test"}}}}, aliases: {review: {service: "api", hostname: "review.example.test"}}};`), 0o600); err != nil {
		t.Fatal(err)
	}
	project, err := Resolve(t.Context(), Selection{Path: path}, root, [32]byte{})
	if err != nil {
		t.Fatal(err)
	}
	if got := *project.Config.Services["api"].Hostname; got != "api.example.test" {
		t.Fatalf("service hostname = %q", got)
	}
	if got := *project.Config.Aliases["review"].Hostname; got != "review.example.test" {
		t.Fatalf("alias hostname = %q", got)
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
  return {services: {web: {}}, deployments: {local: {targets: {web: {address: 3000}}}}};
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
		source := fmt.Sprintf(`export default () => ({ services: {api: {}}, deployments: {local: {targets: {api: {}}}}, aliases: {review: {service: [%q].join(""), name: "api.shop", access: "anonymous"}} });`, test.service)
		if err := os.WriteFile(path, []byte(source), 0o600); err != nil {
			t.Fatal(err)
		}
		value, err := loadTypeScript(t.Context(), path, directory, Worktree{Root: directory})
		if (err == nil) != test.valid {
			t.Fatalf("computed alias service %q: %v", test.service, err)
		}
		if test.valid && (value.Aliases["review"].RelativeName("review") != "api.shop" || value.Aliases["review"].Access == nil || value.Aliases["review"].Access.VisitorMode() != "anonymous") {
			t.Fatal("TypeScript alias fields were not normalized")
		}
	}
}

func TestLoadRejectsVersionedOrDaemonResult(t *testing.T) {
	for field, source := range map[string]string{
		"version":         `export default {version: 1};`,
		"tnld":            `export default {tnld: {mode: "relay"}};`,
		"allow_ip":        `export default {allow_ip: ["192.0.2.1"]};`,
		"allow_providers": `export default {allow_providers: ["github", "stripe"]};`,
		"publicURL":       `export default {publicURL: {}};`,
		"public_url":      `export default {public_url: {}};`,
		"traffic":         `export default {traffic: {connections: 8}};`,
		"hostname":        `export default {hostname: "app.example"};`,
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
		"service server":    {`export default {services: {api: {server: "https://control.example"}}};`, `unknown TypeScript configuration field "server"`},
		"service team":      {`export default {services: {api: {team: "studio"}}};`, `unknown TypeScript configuration field "team"`},
		"concurrency":       {"export default " + typeScriptServiceCase("api", "http", `{http: {limits: {concurrency: 0}}}`), "positive safe integers"},
		"old request limit": {"export default " + typeScriptServiceCase("api", "http", `{http: {requestLimit: 2}}`), "unknown TypeScript configuration field"},
		"inspection":        {"export default " + typeScriptServiceCase("api", "http", `{inspection: {mode: "all"}}`), "services.api.inspection: mode must be none or summary"},
		"retired dev":       {`export default {services: {api: {dev: {startupTimeout: "+1s"}}}};`, "dev"},
		"target":            {"export default " + typeScriptServiceCase("api", "http", `{address: "https://example.com/path"}`), "services.api: target.address:"},
		"raw SSH":           {"export default " + typeScriptServiceCase("shell", "ssh", `{inspection: {mode: "none"}, address: "sshd:22"}`), "use tcp for an existing sshd"},
		"raw SSH TLS":       {`export default () => ({services: {shell: {protocol: ["s", "sh"].join("")}}, deployments: {local: {targets: {shell: {address: "sshd:22", tls: {hostname: "sshd", ca: "system"}}}}}});`, "use tcp for an existing sshd"},
		"invalid ip":        {"export default " + typeScriptServiceCase("api", "http", `{http: {access: {ip: ["invalid"]}}}`), "access.ip"},
		"wide mapped ip":    {"export default " + typeScriptServiceCase("api", "http", `{http: {access: {ip: ["::ffff:192.0.2.7/95"]}}}`), "access.ip"},
		"zoned ip":          {"export default " + typeScriptServiceCase("api", "http", `{http: {access: {ip: ["fe80::1%en0"]}}}`), "access.ip"},
		"empty ip":          {"export default " + typeScriptServiceCase("api", "http", `{http: {access: {ip: []}}}`), "access.ip"},
		"257 unique ips":    {"export default " + typeScriptServiceCase("api", "http", `{http: {access: {ip: Array.from({length: 257}, (_, i) => "2001:db8::" + i.toString(16))}}}`), "256 normalized"},
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

func TestLoadNormalizesIPAliasesInNestedServices(t *testing.T) {
	maximum := make([]string, 256)
	for index := range maximum {
		maximum[index] = fmt.Sprintf("192.0.2.%d/32", index)
	}
	slices.Sort(maximum)
	for _, test := range []struct {
		name, ip string
		want     []string
	}{
		{"masked prefix", `["192.0.2.7/24"]`, []string{"192.0.2.0/24"}},
		{"duplicate host", `["192.0.2.1", "192.0.2.1/32"]`, []string{"192.0.2.1/32"}},
		{"mapped aliases and overlap", `["::ffff:192.0.2.1", "192.0.2.1/32", "192.0.2.7/24", "::ffff:192.0.2.8/120"]`, []string{"192.0.2.0/24", "192.0.2.1/32"}},
		{"256 plus aliases", `[...Array.from({length: 256}, (_, i) => "192.0.2." + i), "::ffff:192.0.2.1", "192.0.2.1/32"]`, maximum},
	} {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "tnl.config.ts")
			source := "export default " + typeScriptServiceCase("api", "http", `{http: {access: {ip: `+test.ip+`}}}`)
			if err := os.WriteFile(path, []byte(source), 0o600); err != nil {
				t.Fatal(err)
			}
			value, err := loadTypeScript(t.Context(), path, filepath.Dir(path), Worktree{})
			if err != nil {
				t.Fatal(err)
			}
			access := value.Deployments["local"].Targets["api"].HTTP.Access
			if access == nil || !slices.Equal(access.IP, test.want) || access.VisitorMode() != "restricted" {
				t.Fatal("TypeScript aliases lost canonical prefixes or granted access", access)
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
    "services":{"web":{}}, "deployments":{"local":{"targets":{"web":{"ephemeral":true,"requirePostQuantum":true,"http":{"access":{"ip":["192.0.2.1"]},"readiness":{"path":"/health"}}}}}}
}`))
	if err != nil {
		t.Fatal(err)
	}
	service := value.Deployments["local"].Targets["web"]
	if service.RequirePostQuantum == nil || !*service.RequirePostQuantum {
		t.Fatal("TypeScript lost the public HTTPS requirement")
	}
	if service.HTTP == nil || service.HTTP.Access == nil || len(service.HTTP.Access.IP) != 1 || service.Ephemeral == nil || !*service.Ephemeral ||
		service.HTTP.Readiness == nil || service.HTTP.Readiness.Path != "/health" {
		t.Fatalf("service = %#v", service)
	}
	if _, err := unmarshalTypeScriptTNL([]byte(`{"services":{"web":{"dev":{"startup_timeout":"30s"}}}}`)); err == nil {
		t.Fatal("static service field name was accepted in TypeScript")
	}
}

func TestTypeScriptDatabaseTargetTLSIsPublisherSide(t *testing.T) {
	declared, err := unmarshalTypeScriptTNL([]byte(`{"services":{"web":{},"orders":{"protocol":"postgres"}},"deployments":{"local":{"targets":{"web":{"address":3000},"orders":{"address":"db.internal:5432","tls":{"hostname":"db.internal","ca":"system"}}}}}}`))
	if err != nil {
		t.Fatal(err)
	}
	value, err := config.ResolveDeployment(declared, "local")
	if err != nil {
		t.Fatal(err)
	}
	options := config.ServicePublish(value.Services["orders"])
	service := value.Services["orders"]
	if config.ServiceName("orders", service) != "orders" || service.Public != nil ||
		service.Target.TLS == nil || service.Target.TLS.Hostname == nil || *service.Target.TLS.Hostname != "db.internal" || service.Target.TLS.CA == nil || *service.Target.TLS.CA != "system" ||
		options == nil || options.Protocol == nil || *options.Protocol != "postgres" ||
		options.Target == nil || string(*options.Target) != "db.internal:5432" ||
		options.TargetTLS == nil || !*options.TargetTLS || options.TargetTLSName == nil || options.TargetCAFile != nil {
		t.Fatalf("database publication = %#v", options)
	}
	for _, field := range []string{"ca_file", "target_ca_file"} {
		if _, err := unmarshalTypeScriptTNL([]byte(`{"publish":{"` + field + `":"ca.pem"}}`)); err == nil {
			t.Fatalf("TypeScript accepted retired field %q", field)
		}
	}
	for _, field := range []string{"serverName", "caFile", "server_name", "ca_file"} {
		if _, err := unmarshalTypeScriptTNL([]byte(`{"services":{"db":{"protocol":"postgres"}},"deployments":{"local":{"targets":{"db":{"address":5432,"tls":{"` + field + `":"old"}}}}}}`)); err == nil {
			t.Fatalf("TypeScript accepted removed target TLS field %q", field)
		}
	}
}

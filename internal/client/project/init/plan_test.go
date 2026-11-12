package init

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	clientproject "github.com/tnldotdev/tnl/internal/client/project"
	"github.com/tnldotdev/tnl/internal/config"
)

func TestInitPlansNextProjectWithoutRewritingExistingFrameworkConfig(t *testing.T) {
	root := copyInitFixture(t, "next")
	path := filepath.Join(root, "next.config.ts")
	plan, err := planInit(t.Context(), root)
	if err != nil {
		t.Fatal(err)
	}
	if plan.PackageManager != "pnpm" || plan.Framework != "next" || !slices.Equal(plan.MissingPackages, []string{"@tnldotdev/tnl"}) || len(plan.NewFrameworkConfig) != 0 || !slices.Equal(plan.Actions, []string{frameworkConfigAction("next", path)}) {
		t.Fatalf("plan = %#v", plan)
	}
	for _, fragment := range []string{`app: { protocol: "http" }`, "environments:", "local:", "targets:", `app: { publicURL: {} }`, "defineConfig"} {
		if !strings.Contains(string(plan.NewConfiguration), fragment) {
			t.Fatalf("planned configuration missing %q: %s", fragment, plan.NewConfiguration)
		}
	}
	if strings.Contains(string(plan.NewConfiguration), "directory:") {
		t.Fatalf("planned a removed service directory: %s", plan.NewConfiguration)
	}
	if _, err := os.Stat(filepath.Join(root, "tnl.config.ts")); !os.IsNotExist(err) {
		t.Fatalf("planning wrote configuration: %v", err)
	}
}

func TestInitConfigurationResolvesSharedShapeAndLocalRegistration(t *testing.T) {
	root := t.TempDir()
	module := filepath.Join(root, "node_modules", "@tnldotdev", "tnl")
	if err := os.MkdirAll(module, 0o755); err != nil {
		t.Fatal(err)
	}
	for path, source := range map[string][]byte{
		filepath.Join(module, "package.json"): []byte(`{"name":"@tnldotdev/tnl","type":"module","exports":{"./config":"./config.ts"}}`),
		filepath.Join(module, "config.ts"):    []byte("export function defineConfig<const T>(value: T): T { return value; }\n"),
		filepath.Join(root, "tnl.config.ts"):  initConfigSource("app"),
	} {
		if err := os.WriteFile(path, source, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	project, err := clientproject.Resolve(t.Context(), clientproject.Selection{Path: filepath.Join(root, "tnl.config.ts")}, root, [32]byte{})
	if err != nil {
		t.Fatal("init produced a configuration rejected by project resolution", err)
	}
	if project.Declared == nil || len(project.Declared.Services) != 1 || len(project.Declared.Environments) != 1 || !project.HasLocalService("app") {
		t.Fatal("init did not declare one shared service and one worktree-local target")
	}
	shape := project.Declared.Services["app"]
	if config.Protocol(shape) != "http" || shape.Target != nil || shape.Tunnel != nil {
		t.Fatal("local target or preview policy entered the shared service shape")
	}
	local := project.Config.Services["app"]
	if config.TargetType(local) != "app" || local.Tunnel == nil {
		t.Fatal("init lost the app-owned listener or its local public URL")
	}
	if service, err := project.AppService(root, ""); err != nil || service != "app" {
		t.Fatal("init no longer selects its ordinary app registration", service, err)
	}
}

func TestPlanFrameworkConfigPreservesExistingConfig(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "next.config.ts")
	source := []byte("const config = {};\nexport default config;\n")
	if err := os.WriteFile(path, source, 0o600); err != nil {
		t.Fatal(err)
	}
	plan := Plan{Framework: "next"}
	if err := planFrameworkConfig(&plan, root); err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(after, source) || len(plan.NewFrameworkConfig) != 0 || !slices.Equal(plan.Actions, []string{frameworkConfigAction("next", path)}) {
		t.Fatalf("config = %q, plan = %#v", after, plan)
	}
}

func TestPlanFrameworkConfigPreservesMultipleConfigs(t *testing.T) {
	root := t.TempDir()
	source := []byte("export default { plugins: [] };\n")
	for _, name := range []string{"vite.config.ts", "vite.config.mts"} {
		if err := os.WriteFile(filepath.Join(root, name), source, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	plan := Plan{Framework: "vite"}
	if err := planFrameworkConfig(&plan, root); err != nil {
		t.Fatal(err)
	}
	want := "Configure @tnldotdev/tnl/vite in the intended framework config; multiple files were found."
	if plan.NewFrameworkConfig != nil || !slices.Equal(plan.Actions, []string{want}) {
		t.Fatalf("plan = %#v", plan)
	}
	for _, name := range []string{"vite.config.ts", "vite.config.mts"} {
		got, err := os.ReadFile(filepath.Join(root, name))
		if err != nil || !bytes.Equal(got, source) {
			t.Fatalf("%s changed: %q, %v", name, got, err)
		}
	}
}

func TestInitCreatesAbsentKnownNextConfig(t *testing.T) {
	root := copyInitFixture(t, "next")
	if err := os.Remove(filepath.Join(root, "next.config.ts")); err != nil {
		t.Fatal(err)
	}
	plan, err := planInit(t.Context(), root)
	if err != nil {
		t.Fatal(err)
	}
	if plan.FrameworkPath != filepath.Join(root, "next.config.ts") || !bytes.Equal(plan.NewFrameworkConfig, frameworkConfigSource("next")) {
		t.Fatalf("plan = %#v", plan)
	}
}

func TestInitPlansGenericAppIntegration(t *testing.T) {
	for _, test := range []struct {
		name, script, manager string
	}{
		{"dev script", "node server.js", "pnpm"},
		{"no dev script", "", "npm"},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := genericInitFixture(t, test.script, test.manager)
			plan, err := planInit(t.Context(), root)
			if err != nil {
				t.Fatal(err)
			}
			if plan.Framework != "" || !plan.NeedsAppRegistration || len(plan.Actions) != 1 || !strings.Contains(plan.Actions[0], "tnl.prepare") {
				t.Fatalf("plan = %#v", plan)
			}
			if strings.Contains(string(plan.NewConfiguration), "dev:") {
				t.Fatalf("planned an application command: %s", plan.NewConfiguration)
			}
			if strings.Contains(string(plan.NewConfiguration), "port:") {
				t.Fatalf("planned an unrequested port: %s", plan.NewConfiguration)
			}
		})
	}
}

func TestInitFrameworkWithoutDevScriptUsesAppStartup(t *testing.T) {
	for _, test := range []struct {
		framework, dependencies string
	}{
		{"next", `"next":"16.3.4"`},
		{"vite", `"vite":"6.0.9"`},
	} {
		t.Run(test.framework, func(t *testing.T) {
			root := copyInitFixture(t, test.framework)
			data := fmt.Sprintf(`{"devDependencies":{"@tnldotdev/tnl":"1.0.0",%s}}`, test.dependencies)
			if err := os.WriteFile(filepath.Join(root, "package.json"), []byte(data), 0o600); err != nil {
				t.Fatal(err)
			}
			plan, err := planInit(t.Context(), root)
			if err != nil {
				t.Fatal(err)
			}
			if plan.Framework != test.framework || plan.NeedsAppRegistration || strings.Contains(string(plan.NewConfiguration), "command:") || strings.Contains(string(plan.NewConfiguration), "port:") {
				t.Fatalf("plan = %#v, config = %s", plan, plan.NewConfiguration)
			}
		})
	}
}

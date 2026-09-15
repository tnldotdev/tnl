package main

import (
	"bytes"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/tnldotdev/tnl/internal/projectconfig"
)

func TestInitReportsManualActionForExistingNextConfig(t *testing.T) {
	root := copyInitFixture(t, "next")
	nextPath := filepath.Join(root, "next.config.ts")
	nextBefore, err := os.ReadFile(nextPath)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := planInit(t.Context(), root)
	if err != nil {
		t.Fatal(err)
	}
	if plan.manager != "pnpm" || plan.framework != "next" ||
		!slices.Equal(plan.packages, []string{"@tnldotdev/tnl"}) ||
		!strings.Contains(string(plan.configData), "app:") ||
		!strings.Contains(string(plan.configData), `directory: "."`) ||
		!strings.Contains(string(plan.configData), `["pnpm","dev"]`) ||
		!strings.Contains(string(plan.configData), "defineConfig") ||
		len(plan.frameworkAfter) != 0 ||
		!slices.Equal(plan.actions, []string{frameworkConfigAction("next", nextPath)}) {
		t.Fatalf("plan = %#v", plan)
	}

	t.Chdir(root)
	var stdout, stderr bytes.Buffer
	if err := runInit(t.Context(), initCommand{NoInstall: true}, &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	if stderr.Len() != 0 || !strings.Contains(stdout.String(), "pnpm add --save-dev") ||
		!strings.Contains(stdout.String(), "needs action") ||
		!strings.Contains(stdout.String(), "complete the actions above, then run tnl dev") {
		t.Fatalf("stdout = %q, stderr = %q", stdout.String(), stderr.String())
	}
	config, err := os.ReadFile(filepath.Join(root, "tnl.config.ts"))
	if err != nil {
		t.Fatal(err)
	}
	nextConfig, err := os.ReadFile(nextPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(config, plan.configData) || !bytes.Equal(nextConfig, nextBefore) {
		t.Fatalf("config = %q, next = %q", config, nextConfig)
	}
	gitignore, err := os.ReadFile(filepath.Join(root, ".gitignore"))
	if err != nil || string(gitignore) != ".tnl/\n" {
		t.Fatalf("gitignore = %q, %v", gitignore, err)
	}

	stdout.Reset()
	stderr.Reset()
	if err := runInit(t.Context(), initCommand{NoInstall: true}, &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(nextPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(nextBefore, after) || !strings.Contains(stdout.String(), "needs action") ||
		!strings.Contains(stdout.String(), "withTnl") {
		t.Fatalf("Next.js config = %q, stdout = %q", after, stdout.String())
	}
}

func TestInitInstallsMissingPackageWithDetectedManager(t *testing.T) {
	root := copyInitFixture(t, "next")
	bin := t.TempDir()
	marker := filepath.Join(t.TempDir(), "arguments")
	executable := filepath.Join(bin, "pnpm")
	script := "#!/bin/sh\nprintf '%s\\n' \"$*\" > \"$TNL_INIT_MARKER\"\n"
	if err := os.WriteFile(executable, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin)
	t.Setenv("TNL_INIT_MARKER", marker)
	t.Chdir(root)
	var stdout, stderr bytes.Buffer
	if err := runInit(t.Context(), initCommand{}, &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	arguments, err := os.ReadFile(marker)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(arguments), "add --save-dev") || !strings.Contains(string(arguments), "@tnldotdev/tnl") ||
		!strings.Contains(stdout.String(), "installed") || stderr.Len() != 0 {
		t.Fatalf("arguments = %q, stdout = %q, stderr = %q", arguments, stdout.String(), stderr.String())
	}
}

func TestInitReportsManualActionForExistingViteConfig(t *testing.T) {
	root := copyInitFixture(t, "vite")
	path := filepath.Join(root, "vite.config.ts")
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Chdir(root)
	var stdout, stderr bytes.Buffer
	if err := runInit(t.Context(), initCommand{NoInstall: true}, &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(after, before) {
		t.Fatalf("Vite config = %q, want unchanged %q", after, before)
	}
	if !strings.Contains(stdout.String(), "needs action") ||
		!strings.Contains(stdout.String(), "tnl() to plugins.") ||
		!strings.Contains(stdout.String(), "complete the actions above, then run tnl dev") || stderr.Len() != 0 {
		t.Fatalf("stdout = %q, stderr = %q", stdout.String(), stderr.String())
	}
	stdout.Reset()
	if err := runInit(t.Context(), initCommand{NoInstall: true}, &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	second, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, second) || !strings.Contains(stdout.String(), "needs action") ||
		!strings.Contains(stdout.String(), `.tnl/project.d.ts`) {
		t.Fatalf("second config = %q, stdout = %q", second, stdout.String())
	}
}

func TestInitReportsManualProjectTypeAction(t *testing.T) {
	root := copyInitFixture(t, "vite")
	path := filepath.Join(root, "tsconfig.json")
	source := []byte("{\n  \"include\": [\"src/**/*.ts\"]\n}\n")
	if err := os.WriteFile(path, source, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Chdir(root)
	var stdout bytes.Buffer
	if err := runInit(t.Context(), initCommand{NoInstall: true}, &stdout, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(after, source) || !strings.Contains(stdout.String(), "needs action") ||
		!strings.Contains(stdout.String(), `.tnl/project.d.ts`) {
		t.Fatalf("tsconfig = %q, err = %v, stdout = %q", after, err, stdout.String())
	}

	stdout.Reset()
	if err := runInit(t.Context(), initCommand{NoInstall: true}, &stdout, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout.String(), "needs action") || !strings.Contains(stdout.String(), `.tnl/project.d.ts`) {
		t.Fatalf("second stdout = %q", stdout.String())
	}
}

func TestInitRepeatsManualProjectTypeAction(t *testing.T) {
	root := copyInitFixture(t, "vite")
	path := filepath.Join(root, "tsconfig.json")
	source := []byte("{\n  // preserve JSONC\n  \"include\": [\"src/**/*.ts\"]\n}\n")
	if err := os.WriteFile(path, source, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Chdir(root)
	for run := 1; run <= 2; run++ {
		var stdout bytes.Buffer
		if err := runInit(t.Context(), initCommand{NoInstall: true}, &stdout, &bytes.Buffer{}); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(stdout.String(), "needs action") || !strings.Contains(stdout.String(), `.tnl/project.d.ts`) {
			t.Fatalf("run %d stdout = %q", run, stdout.String())
		}
		after, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(after, source) {
			t.Fatalf("run %d tsconfig = %q, err = %v", run, after, err)
		}
	}
}

func TestInitDevCommandPrefersPackageScript(t *testing.T) {
	tests := []struct {
		name, framework, manager string
		scripts                  map[string]string
		want                     []string
	}{
		{name: "pnpm next", framework: "next", manager: "pnpm", scripts: map[string]string{"dev": "next dev --turbo"}, want: []string{"pnpm", "dev"}},
		{name: "yarn vite", framework: "vite", manager: "yarn", scripts: map[string]string{"dev": "vite --host"}, want: []string{"yarn", "dev"}},
		{name: "npm next", framework: "next", manager: "npm", scripts: map[string]string{"dev": "next dev"}, want: []string{"npm", "run", "dev"}},
		{name: "bun vite", framework: "vite", manager: "bun", scripts: map[string]string{"dev": "vite"}, want: []string{"bun", "run", "dev"}},
		{name: "unknown manager", framework: "next", scripts: map[string]string{"dev": "next dev"}, want: []string{"npm", "run", "dev"}},
		{name: "next fallback", framework: "next", want: []string{"next", "dev"}},
		{name: "vite fallback", framework: "vite", want: []string{"vite"}},
		{name: "no framework or script", manager: "pnpm"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := initDevCommand(test.framework, test.manager, test.scripts); !slices.Equal(got, test.want) {
				t.Fatalf("initDevCommand() = %v, want %v", got, test.want)
			}
		})
	}
}

func TestPlanFrameworkConfigPreservesExistingConfig(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "next.config.ts")
	source := []byte("const config = {};\nexport default config;\n")
	if err := os.WriteFile(path, source, 0o600); err != nil {
		t.Fatal(err)
	}
	plan := initPlan{framework: "next"}
	if err := planFrameworkConfig(&plan, root); err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(after, source) || len(plan.frameworkAfter) != 0 ||
		!slices.Equal(plan.actions, []string{frameworkConfigAction("next", path)}) {
		t.Fatalf("config = %q, plan = %#v", after, plan)
	}
}

func TestPlanFrameworkConfigPreservesMultipleConfigs(t *testing.T) {
	root := t.TempDir()
	for _, name := range []string{"vite.config.ts", "vite.config.mts"} {
		if err := os.WriteFile(filepath.Join(root, name), []byte("export default { plugins: [] };\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	plan := initPlan{framework: "vite"}
	if err := planFrameworkConfig(&plan, root); err != nil {
		t.Fatal(err)
	}
	want := "Configure @tnldotdev/tnl/vite in the intended framework config; multiple files were found."
	if plan.frameworkAfter != nil || !slices.Equal(plan.actions, []string{want}) {
		t.Fatalf("plan = %#v", plan)
	}
}

func TestInitAmbiguousFrameworkOutputNeedsAction(t *testing.T) {
	root := copyInitFixture(t, "vite")
	path := filepath.Join(root, "vite.config.ts")
	source := []byte("import { defineConfig } from \"vite\";\nexport default defineConfig({ ...base, plugins: [] });\n")
	if err := os.WriteFile(path, source, 0o600); err != nil {
		t.Fatal(err)
	}
	plan, err := planInit(t.Context(), root)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(plan.actions, []string{frameworkConfigAction("vite", path)}) {
		t.Fatalf("actions = %v", plan.actions)
	}
	t.Chdir(root)
	var stdout, stderr bytes.Buffer
	if err := runInit(t.Context(), initCommand{NoInstall: true}, &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(after, source) || !strings.Contains(stdout.String(), "needs action") ||
		strings.Contains(stdout.String(), "already configured") ||
		!strings.Contains(stdout.String(), "complete the actions above, then run tnl dev") || stderr.Len() != 0 {
		t.Fatalf("config = %q, stdout = %q, stderr = %q", after, stdout.String(), stderr.String())
	}
}

func TestInitPreservesExistingStaticConfiguration(t *testing.T) {
	root := copyInitFixture(t, "next")
	staticPath := filepath.Join(root, "tnl.yml")
	static := []byte("version: 1\ntnl:\n  team: Existing Team\n")
	if err := os.WriteFile(staticPath, static, 0o600); err != nil {
		t.Fatal(err)
	}
	plan, err := planInit(t.Context(), root)
	if err != nil {
		t.Fatal(err)
	}
	if plan.configPath != staticPath || plan.configData != nil {
		t.Fatalf("plan = %#v", plan)
	}
	got, err := os.ReadFile(staticPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, static) {
		t.Fatalf("existing config changed: %q", got)
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
	if !plan.installBlocked || len(plan.actions) == 0 || !strings.Contains(plan.actions[0], "run tnl init again") {
		t.Fatalf("plan = %#v", plan)
	}
}

func TestInitDetectsPackageManagerFromWorkspaceAncestor(t *testing.T) {
	workspace := t.TempDir()
	root := filepath.Join(workspace, "apps", "web")
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(workspace, "package.json"), []byte(`{"packageManager":"pnpm@10","workspaces":["apps/*"]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(workspace, "pnpm-lock.yaml"), []byte("lockfileVersion: '9.0'\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "package.json"), []byte(`{"dependencies":{"vite":"8.2.2"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	plan, err := planInit(t.Context(), root)
	if err != nil {
		t.Fatal(err)
	}
	if plan.manager != "pnpm" || plan.root != root {
		t.Fatalf("plan = %#v", plan)
	}
}

func TestProjectTypeIncludeActionsPreserveConfiguration(t *testing.T) {
	root := t.TempDir()
	service := filepath.Join(root, "apps", "api")
	if err := os.MkdirAll(service, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(service, "tsconfig.json")
	if err := os.WriteFile(path, []byte("{\n  \"include\": [\"src/**/*.ts\"]\n}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	project := projectConfiguration{Project: projectconfig.Project{
		Root: root, ServiceDirectories: map[string]string{"api": service},
	}}
	actions, err := projectTypeIncludeActions(project)
	if err != nil {
		t.Fatal(err)
	}
	if len(actions) != 1 || !strings.Contains(actions[0], "../../.tnl/project.d.ts") {
		t.Fatalf("actions = %v", actions)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "{\n  \"include\": [\"src/**/*.ts\"]\n}\n" {
		t.Fatalf("tsconfig changed: %s", data)
	}
	integrated := []byte("{\n  \"include\": [\"src/**/*.ts\", \"../../.tnl/project.d.ts\"]\n}\n")
	if err := os.WriteFile(path, integrated, 0o600); err != nil {
		t.Fatal(err)
	}
	actions, err = projectTypeIncludeActions(project)
	if err != nil || len(actions) != 0 {
		t.Fatalf("integrated actions = %v, err = %v", actions, err)
	}

	ambiguous := []byte("{\n  // preserve this JSONC file\n  \"include\": [\"src\"]\n}\n")
	if err := os.WriteFile(path, ambiguous, 0o600); err != nil {
		t.Fatal(err)
	}
	actions, err = projectTypeIncludeActions(project)
	if err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(actions) != 1 || !bytes.Equal(after, ambiguous) || !strings.Contains(actions[0], "../../.tnl/project.d.ts") {
		t.Fatalf("actions = %v, tsconfig = %s", actions, after)
	}

	ambiguous = []byte("{\n  \"include\": [\"src\"],\n  \"include\": [\"generated\"]\n}\n")
	if err := os.WriteFile(path, ambiguous, 0o600); err != nil {
		t.Fatal(err)
	}
	actions, err = projectTypeIncludeActions(project)
	if err != nil {
		t.Fatal(err)
	}
	after, err = os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(actions) != 1 || !bytes.Equal(after, ambiguous) {
		t.Fatalf("duplicate-key actions = %v, tsconfig = %s", actions, after)
	}
}

func TestProjectTypeIncludeActionUsesRootWithoutNamedServices(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "tsconfig.json")
	if err := os.WriteFile(path, []byte("{\n  \"include\": [\"src/**/*.ts\"]\n}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	actions, err := projectTypeIncludeActions(projectConfiguration{Project: projectconfig.Project{Root: root}})
	if err != nil {
		t.Fatal(err)
	}
	if len(actions) != 1 || !strings.Contains(actions[0], `".tnl/project.d.ts"`) {
		t.Fatalf("actions = %v", actions)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "{\n  \"include\": [\"src/**/*.ts\"]\n}\n" {
		t.Fatalf("tsconfig changed: %s", data)
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
	if plan.frameworkPath != filepath.Join(root, "next.config.ts") ||
		!bytes.Equal(plan.frameworkAfter, frameworkConfigSource("next")) {
		t.Fatalf("plan = %#v", plan)
	}
}

func copyInitFixture(t *testing.T, name string) string {
	t.Helper()
	root := t.TempDir()
	entries, err := os.ReadDir(filepath.Join("testdata", "init", name))
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		data, err := os.ReadFile(filepath.Join("testdata", "init", name, entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, entry.Name()), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

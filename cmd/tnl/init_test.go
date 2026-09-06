package main

import (
	"bytes"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestInitConfiguresRecognizedNextFixture(t *testing.T) {
	root := copyInitFixture(t, "next")
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
		!strings.Contains(string(plan.frameworkAfter), "export default withTnl(config)") ||
		len(plan.frameworkBefore) == 0 || len(plan.actions) != 0 {
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
	nextConfig, err := os.ReadFile(filepath.Join(root, "next.config.ts"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(config, plan.configData) || !bytes.Equal(nextConfig, plan.frameworkAfter) {
		t.Fatalf("config = %q, next = %q", config, nextConfig)
	}
	gitignore, err := os.ReadFile(filepath.Join(root, ".gitignore"))
	if err != nil || string(gitignore) != ".tnl/\n" {
		t.Fatalf("gitignore = %q, %v", gitignore, err)
	}

	before := slices.Clone(nextConfig)
	stdout.Reset()
	stderr.Reset()
	if err := runInit(t.Context(), initCommand{NoInstall: true}, &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(filepath.Join(root, "next.config.ts"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatalf("idempotent init changed Next.js config:\n%s", after)
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

func TestInitConfiguresRecognizedViteFactoryFixture(t *testing.T) {
	root := copyInitFixture(t, "vite")
	path := filepath.Join(root, "vite.config.ts")
	t.Chdir(root)
	var stdout, stderr bytes.Buffer
	if err := runInit(t.Context(), initCommand{NoInstall: true}, &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	want := "import tnl from \"@tnldotdev/tnl/vite\";\nimport { defineConfig } from \"vite\";\n\nexport default defineConfig(() => ({ plugins: [tnl()] }));\n"
	if string(after) != want {
		t.Fatalf("Vite config = %q, want %q", after, want)
	}
	if !strings.Contains(stdout.String(), "needs action") ||
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
	if !bytes.Equal(after, second) || !strings.Contains(stdout.String(), "needs action") ||
		!strings.Contains(stdout.String(), `.tnl/project.d.ts`) {
		t.Fatalf("second config = %q, stdout = %q", second, stdout.String())
	}
}

func TestInitReportsUpdatedProjectTypeConfig(t *testing.T) {
	root := copyInitFixture(t, "vite")
	path := filepath.Join(root, "tsconfig.json")
	if err := os.WriteFile(path, []byte("{\n  \"include\": [\"src/**/*.ts\"]\n}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Chdir(root)
	var stdout bytes.Buffer
	if err := runInit(t.Context(), initCommand{NoInstall: true}, &stdout, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if strings.Count(stdout.String(), "updated") != 3 {
		t.Fatalf("stdout = %q", stdout.String())
	}

	stdout.Reset()
	if err := runInit(t.Context(), initCommand{NoInstall: true}, &stdout, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(stdout.String(), "updated") || !strings.Contains(stdout.String(), "already configured") {
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

func TestUpdateNextConfigRecognizesOnlyIdentifierDefaultExport(t *testing.T) {
	recognized := []struct {
		name, source, want string
	}{
		{
			name:   "one line",
			source: "const config = { reactStrictMode: true }; export default config;\n",
			want:   "import { withTnl } from \"@tnldotdev/tnl/next\";\nconst config = { reactStrictMode: true }; export default withTnl(config);\n",
		},
		{
			name:   "multiline with misleading comment and string",
			source: "// export default fake;\nconst note = \"export default fake\";\nconst config = { reactStrictMode: true };\n\nexport default config;\n",
			want:   "import { withTnl } from \"@tnldotdev/tnl/next\";\n// export default fake;\nconst note = \"export default fake\";\nconst config = { reactStrictMode: true };\n\nexport default withTnl(config);\n",
		},
	}
	for _, test := range recognized {
		t.Run(test.name, func(t *testing.T) {
			updated := updateNextConfig([]byte(test.source))
			if string(updated) != test.want {
				t.Fatalf("updated = %q, want %q", updated, test.want)
			}
			if second := updateNextConfig(updated); !bytes.Equal(second, updated) {
				t.Fatalf("second update = %q", second)
			}
		})
	}

	ambiguous := []struct {
		name, source string
	}{
		{name: "object export", source: "export default {};\n"},
		{name: "call export", source: "const config = {}; export default defineConfig(config);\n"},
		{name: "multiple default exports", source: "const a = {}; export default a; export default a;\n"},
		{name: "commonjs", source: "const config = {}; module.exports = config; export default config;\n"},
		{name: "binding collision", source: "const withTnl = value; const config = {}; export default config;\n"},
	}
	for _, test := range ambiguous {
		t.Run(test.name, func(t *testing.T) {
			if updated := updateNextConfig([]byte(test.source)); updated != nil {
				t.Fatalf("ambiguous source was updated: %q", updated)
			}
		})
	}
}

func TestUpdateViteConfigRecognizedShapes(t *testing.T) {
	tests := []struct {
		name, source, want string
	}{
		{
			name:   "one-line static",
			source: "import { defineConfig } from \"vite\";\nexport default defineConfig({ plugins: [react()] });\n",
			want:   "import tnl from \"@tnldotdev/tnl/vite\";\nimport { defineConfig } from \"vite\";\nexport default defineConfig({ plugins: [tnl(), react()] });\n",
		},
		{
			name:   "direct object",
			source: "export default { plugins: [] };\n",
			want:   "import tnl from \"@tnldotdev/tnl/vite\";\nexport default { plugins: [tnl()] };\n",
		},
		{
			name:   "aliased defineConfig",
			source: "import { defineConfig as config } from \"vite\";\nexport default config({ plugins: [] });\n",
			want:   "import tnl from \"@tnldotdev/tnl/vite\";\nimport { defineConfig as config } from \"vite\";\nexport default config({ plugins: [tnl()] });\n",
		},
		{
			name:   "multiline static preserves settings",
			source: "import { defineConfig } from \"vite\";\n\nexport default defineConfig({\n  resolve: { alias: { \"@\": \"/src\" } },\n  plugins: [\n    react(),\n  ],\n  server: { port: 4173 },\n});\n",
			want:   "import tnl from \"@tnldotdev/tnl/vite\";\nimport { defineConfig } from \"vite\";\n\nexport default defineConfig({\n  resolve: { alias: { \"@\": \"/src\" } },\n  plugins: [\n    tnl(),\n    react(),\n  ],\n  server: { port: 4173 },\n});\n",
		},
		{
			name:   "expression factory",
			source: "import { defineConfig } from \"vite\";\nexport default defineConfig(() => ({ plugins: [] }));\n",
			want:   "import tnl from \"@tnldotdev/tnl/vite\";\nimport { defineConfig } from \"vite\";\nexport default defineConfig(() => ({ plugins: [tnl()] }));\n",
		},
		{
			name:   "return-object factory",
			source: "import { defineConfig } from \"vite\";\nexport default defineConfig((env) => { return { plugins: [] }; });\n",
			want:   "import tnl from \"@tnldotdev/tnl/vite\";\nimport { defineConfig } from \"vite\";\nexport default defineConfig((env) => { return { plugins: [tnl()] }; });\n",
		},
		{
			name:   "comments and strings do not add properties",
			source: "import { defineConfig } from \"vite\";\n// plugins: []\nconst label = \"plugins: []\";\nexport default defineConfig({ plugins: [] });\n",
			want:   "import tnl from \"@tnldotdev/tnl/vite\";\nimport { defineConfig } from \"vite\";\n// plugins: []\nconst label = \"plugins: []\";\nexport default defineConfig({ plugins: [tnl()] });\n",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := updateViteConfig([]byte(test.source)); string(got) != test.want {
				t.Fatalf("updated = %q, want %q", got, test.want)
			}
		})
	}
}

func TestUpdateViteConfigPreservesIntegratedAndAmbiguousSource(t *testing.T) {
	integrated := []byte("import tunnel from \"@tnldotdev/tnl/vite\";\nimport { defineConfig } from \"vite\";\nexport default defineConfig({ plugins: [react(), tunnel()] });\n")
	if got := updateViteConfig(integrated); !bytes.Equal(got, integrated) {
		t.Fatalf("integrated config changed: %q", got)
	}

	ambiguous := []struct {
		name, source string
	}{
		{name: "missing plugins", source: "import { defineConfig } from \"vite\"; export default defineConfig({});"},
		{name: "non-array plugins", source: "import { defineConfig } from \"vite\"; export default defineConfig({ plugins });"},
		{name: "multiple plugin properties", source: "import { defineConfig } from \"vite\"; export default defineConfig({ plugins: [], nested: { plugins: [] } });"},
		{name: "computed plugins", source: "import { defineConfig } from \"vite\"; export default defineConfig({ [\"plugins\"]: [] });"},
		{name: "spread config", source: "import { defineConfig } from \"vite\"; export default defineConfig({ ...base, plugins: [] });"},
		{name: "spread plugins", source: "import { defineConfig } from \"vite\"; export default defineConfig({ plugins: [...base] });"},
		{name: "binding collision", source: "import { defineConfig } from \"vite\"; const tnl = other; export default defineConfig({ plugins: [] });"},
		{name: "commonjs", source: "const { defineConfig } = require(\"vite\"); module.exports = defineConfig({ plugins: [] });"},
	}
	for _, test := range ambiguous {
		t.Run(test.name, func(t *testing.T) {
			if got := updateViteConfig([]byte(test.source)); got != nil {
				t.Fatalf("ambiguous source was updated: %q", got)
			}
		})
	}
}

func TestPlanFrameworkConfigUsesPackageTypeAndPreservesAmbiguity(t *testing.T) {
	for _, extension := range []string{".ts", ".mts", ".mjs"} {
		t.Run(extension, func(t *testing.T) {
			root := t.TempDir()
			path := filepath.Join(root, "next.config"+extension)
			source := []byte("const config = {};\nexport default config;\n")
			if err := os.WriteFile(path, source, 0o600); err != nil {
				t.Fatal(err)
			}
			plan := initPlan{framework: "next"}
			if err := planFrameworkConfig(&plan, root, ""); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(plan.frameworkBefore, source) || len(plan.frameworkAfter) == 0 || len(plan.actions) != 0 {
				t.Fatalf("plan = %#v", plan)
			}
		})
	}

	root := t.TempDir()
	path := filepath.Join(root, "next.config.js")
	source := []byte("const config = {};\nexport default config;\n")
	if err := os.WriteFile(path, source, 0o600); err != nil {
		t.Fatal(err)
	}
	packagePath := filepath.Join(root, "package.json")
	if err := os.WriteFile(packagePath, []byte(`{"dependencies":{"next":"1","@tnldotdev/tnl":"1"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	plan, err := planInit(t.Context(), root)
	if err != nil {
		t.Fatal(err)
	}
	if plan.frameworkAfter != nil || !slices.Equal(plan.actions, []string{frameworkConfigAction("next", path)}) {
		t.Fatalf("non-module plan = %#v", plan)
	}
	if err := os.WriteFile(packagePath, []byte(`{"type":"module","dependencies":{"next":"1","@tnldotdev/tnl":"1"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	modulePlan, err := planInit(t.Context(), root)
	if err != nil {
		t.Fatal(err)
	}
	if len(modulePlan.frameworkAfter) == 0 || len(modulePlan.actions) != 0 {
		t.Fatalf("module plan = %#v", modulePlan)
	}

	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	cjsPath := filepath.Join(root, "next.config.cjs")
	if err := os.WriteFile(cjsPath, []byte("module.exports = {};\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cjsPlan := initPlan{framework: "next"}
	if err := planFrameworkConfig(&cjsPlan, root, "module"); err != nil {
		t.Fatal(err)
	}
	if cjsPlan.frameworkAfter != nil || !slices.Equal(cjsPlan.actions, []string{frameworkConfigAction("next", cjsPath)}) {
		t.Fatalf("CommonJS plan = %#v", cjsPlan)
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
	if err := planFrameworkConfig(&plan, root, "module"); err != nil {
		t.Fatal(err)
	}
	want := "Configure @tnldotdev/tnl/vite in the intended framework config; multiple files were found."
	if plan.frameworkAfter != nil || !slices.Equal(plan.actions, []string{want}) {
		t.Fatalf("plan = %#v", plan)
	}
}

func TestInitFrameworkConfigRefusesChangedPlannedFile(t *testing.T) {
	root := copyInitFixture(t, "next")
	plan, err := planInit(t.Context(), root)
	if err != nil {
		t.Fatal(err)
	}
	changed := []byte("const config = { changed: true };\nexport default config;\n")
	if err := os.WriteFile(plan.frameworkPath, changed, 0o600); err != nil {
		t.Fatal(err)
	}
	err = replaceRecognizedInitFile(plan.frameworkPath, plan.frameworkBefore, plan.frameworkAfter)
	after, readErr := os.ReadFile(plan.frameworkPath)
	if err == nil || !strings.Contains(err.Error(), "changed during initialization") || readErr != nil || !bytes.Equal(after, changed) {
		t.Fatalf("err = %v, readErr = %v, config = %q", err, readErr, after)
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

func TestProjectTypeIncludeIsUpdatedOnlyForStrictJSON(t *testing.T) {
	root := t.TempDir()
	service := filepath.Join(root, "apps", "api")
	if err := os.MkdirAll(service, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(service, "tsconfig.json")
	if err := os.WriteFile(path, []byte("{\n  \"include\": [\"src/**/*.ts\"]\n}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	project := projectConfiguration{root: root, directories: map[string]string{"api": service}}
	actions, updated, err := ensureProjectTypeIncludes(project)
	if err != nil {
		t.Fatal(err)
	}
	if len(actions) != 0 || !slices.Equal(updated, []string{path}) {
		t.Fatalf("actions = %v, updated = %v", actions, updated)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"../../.tnl/project.d.ts"`) {
		t.Fatalf("tsconfig = %s", data)
	}

	ambiguous := []byte("{\n  // preserve this JSONC file\n  \"include\": [\"src\"]\n}\n")
	if err := os.WriteFile(path, ambiguous, 0o600); err != nil {
		t.Fatal(err)
	}
	actions, updated, err = ensureProjectTypeIncludes(project)
	if err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(actions) != 1 || len(updated) != 0 || !bytes.Equal(after, ambiguous) || !strings.Contains(actions[0], "../../.tnl/project.d.ts") {
		t.Fatalf("actions = %v, updated = %v, tsconfig = %s", actions, updated, after)
	}

	ambiguous = []byte("{\n  \"include\": [\"src\"],\n  \"include\": [\"generated\"]\n}\n")
	if err := os.WriteFile(path, ambiguous, 0o600); err != nil {
		t.Fatal(err)
	}
	actions, updated, err = ensureProjectTypeIncludes(project)
	if err != nil {
		t.Fatal(err)
	}
	after, err = os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(actions) != 1 || len(updated) != 0 || !bytes.Equal(after, ambiguous) {
		t.Fatalf("duplicate-key actions = %v, updated = %v, tsconfig = %s", actions, updated, after)
	}
}

func TestProjectTypeIncludeUsesRootWithoutNamedServices(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "tsconfig.json")
	if err := os.WriteFile(path, []byte("{\n  \"include\": [\"src/**/*.ts\"]\n}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	actions, updated, err := ensureProjectTypeIncludes(projectConfiguration{root: root})
	if err != nil {
		t.Fatal(err)
	}
	if len(actions) != 0 || !slices.Equal(updated, []string{path}) {
		t.Fatalf("actions = %v, updated = %v", actions, updated)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `".tnl/project.d.ts"`) {
		t.Fatalf("tsconfig = %s", data)
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
		string(plan.frameworkAfter) != "import { withTnl } from \"@tnldotdev/tnl/next\";\n\nexport default withTnl({});\n" {
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

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInitReportsManualActionForExistingFrameworkConfig(t *testing.T) {
	for _, test := range []struct{ framework, action string }{{"next", "withTnl"}, {"vite", "tnl() to plugins."}} {
		t.Run(test.framework, func(t *testing.T) {
			root := copyInitFixture(t, test.framework)
			path := filepath.Join(root, test.framework+".config.ts")
			before, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			plan, err := planInit(t.Context(), root)
			if err != nil {
				t.Fatal(err)
			}
			t.Chdir(root)
			for run := 1; run <= 2; run++ {
				var stdout, stderr bytes.Buffer
				if err := runInit(t.Context(), initCommand{NoInstall: true}, &stdout, &stderr); err != nil {
					t.Fatal(err)
				}
				for _, fragment := range []string{"needs action", test.action, "complete the actions above, then run tnl dev"} {
					if !strings.Contains(stdout.String(), fragment) {
						t.Fatalf("run %d missing %q: %q", run, fragment, stdout.String())
					}
				}
				if stderr.Len() != 0 {
					t.Fatalf("stderr = %q", stderr.String())
				}
				after, err := os.ReadFile(path)
				if err != nil || !bytes.Equal(before, after) {
					t.Fatalf("framework config changed: %q, %v", after, err)
				}
				config, err := os.ReadFile(filepath.Join(root, "tnl.config.ts"))
				if err != nil || !bytes.Equal(config, plan.configData) {
					t.Fatalf("config = %q, %v", config, err)
				}
				gitignore, err := os.ReadFile(filepath.Join(root, ".gitignore"))
				if err != nil || string(gitignore) != "# tnl\n.tnl/\n" {
					t.Fatalf("gitignore = %q, %v", gitignore, err)
				}
				if test.framework == "next" && !strings.Contains(stdout.String(), "pnpm add --save-dev") {
					t.Fatalf("missing installation action: %q", stdout.String())
				}
			}
		})
	}
}

func TestInitRepeatsManualProjectTypeAction(t *testing.T) {
	for name, source := range map[string]string{"json": "{\n  \"include\": [\"src/**/*.ts\"]\n}\n", "jsonc": "{\n  // preserve JSONC\n  \"include\": [\"src/**/*.ts\"]\n}\n"} {
		t.Run(name, func(t *testing.T) {
			root := copyInitFixture(t, "vite")
			path := filepath.Join(root, "tsconfig.json")
			if err := os.WriteFile(path, []byte(source), 0o600); err != nil {
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
				if err != nil || string(after) != source {
					t.Fatalf("run %d tsconfig = %q, %v", run, after, err)
				}
			}
		})
	}
}

func TestInitAmbiguousFrameworkOutputNeedsAction(t *testing.T) {
	root := copyInitFixture(t, "vite")
	path := filepath.Join(root, "vite.config.ts")
	source := []byte("import { defineConfig } from \"vite\";\nexport default defineConfig({ ...base, plugins: [] });\n")
	if err := os.WriteFile(path, source, 0o600); err != nil {
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
	if !bytes.Equal(after, source) || !strings.Contains(stdout.String(), "needs action") || strings.Contains(stdout.String(), "already configured") || !strings.Contains(stdout.String(), "complete the actions above, then run tnl dev") || stderr.Len() != 0 {
		t.Fatalf("config = %q, stdout = %q, stderr = %q", after, stdout.String(), stderr.String())
	}
}

func TestInitGenericMissingSettingsRepeatUntilAnswered(t *testing.T) {
	for _, test := range []struct {
		name, script, action, command string
	}{
		{"script", "node server.js", "services.app.dev.port", `["node","server.js"]`},
		{"no script", "", "services.app.dev.command and services.app.dev.port", ""},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := genericInitFixture(t, test.script, "npm")
			t.Chdir(root)
			path := filepath.Join(root, "tnl.config.ts")
			for run := 1; run <= 2; run++ {
				var stdout, stderr bytes.Buffer
				if err := runInitWithInput(t.Context(), initCommand{}, strings.NewReader("7777\n"), false, &stdout, &stderr); err != nil {
					t.Fatal(err)
				}
				for _, text := range []string{"[ tnl init ]-- needs action", test.action, "complete the actions above, then run tnl dev"} {
					if !strings.Contains(stdout.String(), text) {
						t.Fatalf("run %d missing %q: %s", run, text, stdout.String())
					}
				}
				if stderr.Len() != 0 {
					t.Fatalf("run %d stderr = %q", run, stderr.String())
				}
				config, err := os.ReadFile(path)
				if err != nil || strings.Contains(string(config), "port:") || strings.Contains(string(config), "7777") || (test.command != "" && !strings.Contains(string(config), test.command)) || (test.command == "" && strings.Contains(string(config), "dev:")) {
					t.Fatalf("run %d config = %s, %v", run, config, err)
				}
			}
		})
	}
}

func TestInitFrameworkIntegrationDoesNotPromptForPort(t *testing.T) {
	for _, framework := range []string{"next", "vite"} {
		t.Run(framework, func(t *testing.T) {
			root := copyInitFixture(t, framework)
			t.Chdir(root)
			var stdout, stderr bytes.Buffer
			if err := runInitWithInput(t.Context(), initCommand{NoInstall: true}, strings.NewReader("4321\n"), true, &stdout, &stderr); err != nil {
				t.Fatal(err)
			}
			config, err := os.ReadFile(filepath.Join(root, "tnl.config.ts"))
			if err != nil || strings.Contains(string(config), "port:") || strings.Contains(stdout.String(), "services.app.dev.port") || stderr.Len() != 0 {
				t.Fatalf("config = %q, stdout = %q, stderr = %q, err = %v", config, stdout.String(), stderr.String(), err)
			}
		})
	}
}

func TestInitGenericPromptsSaveAnswers(t *testing.T) {
	for _, test := range []struct {
		name, script, answers, command string
	}{
		{"script", "node server.js", "4321\n", `["node","server.js"]`},
		{"no script", "", "node 'server file.js' --name \"two words\"\n4321\n", `["node","server file.js","--name","two words"]`},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := genericInitFixture(t, test.script, "yarn")
			t.Chdir(root)
			var stdout, stderr bytes.Buffer
			if err := runInitWithInput(t.Context(), initCommand{}, strings.NewReader(test.answers), true, &stdout, &stderr); err != nil {
				t.Fatal(err)
			}
			config, err := os.ReadFile(filepath.Join(root, "tnl.config.ts"))
			if err != nil || !strings.Contains(string(config), test.command) || !strings.Contains(string(config), "port: 4321") {
				t.Fatalf("config = %s, %v", config, err)
			}
			if !strings.Contains(stdout.String(), "[ tnl init ]-- configured") || !strings.Contains(stdout.String(), "+-- run tnl dev") || strings.Contains(stdout.String(), "needs action") || !strings.Contains(stderr.String(), "[ tnl init ]-- needs input") || !strings.Contains(stderr.String(), "dev port") {
				t.Fatalf("stdout = %q, stderr = %q", stdout.String(), stderr.String())
			}
			stderr.Reset()
			stdout.Reset()
			if err := runInitWithInput(t.Context(), initCommand{}, strings.NewReader(""), true, &stdout, &stderr); err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(stdout.String(), "[ tnl init ]-- already configured") || strings.Contains(stdout.String(), "needs action") || stderr.Len() != 0 {
				t.Fatalf("rerun stdout = %q, stderr = %q", stdout.String(), stderr.String())
			}
		})
	}
}

func TestInitGenericPartialAnswersAreRetained(t *testing.T) {
	root := genericInitFixture(t, "", "npm")
	t.Chdir(root)
	path := filepath.Join(root, "tnl.config.ts")
	var stdout, stderr bytes.Buffer
	if err := runInitWithInput(t.Context(), initCommand{}, strings.NewReader("\n0\n65536\nnot-a-port\n8123\n"), true, &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	config, err := os.ReadFile(path)
	if err != nil || !strings.Contains(string(config), "dev: { port: 8123 }") {
		t.Fatalf("config = %q, %v", config, err)
	}
	if !strings.Contains(stdout.String(), "set services.app.dev.command") || !strings.Contains(stdout.String(), "needs action") || strings.Count(stderr.String(), "invalid input") != 3 {
		t.Fatalf("stdout = %q, stderr = %q", stdout.String(), stderr.String())
	}
	stdout.Reset()
	stderr.Reset()
	if err := runInitWithInput(t.Context(), initCommand{}, strings.NewReader("node server.js\n"), true, &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	config, err = os.ReadFile(path)
	if err != nil || !strings.Contains(string(config), `dev: { command: ["node","server.js"], port: 8123 }`) || !strings.Contains(stdout.String(), "[ tnl init ]-- configured") || strings.Contains(stdout.String(), "needs action") || strings.Contains(stderr.String(), "dev port") {
		t.Fatalf("config = %q, stdout = %q, stderr = %q, err = %v", config, stdout.String(), stderr.String(), err)
	}
}

func TestInitGenericRerunUpdatesUntouchedConfigWithPort(t *testing.T) {
	root := genericInitFixture(t, "node server.js", "bun")
	t.Chdir(root)
	path := filepath.Join(root, "tnl.config.ts")
	if err := runInitWithInput(t.Context(), initCommand{}, strings.NewReader(""), false, &bytes.Buffer{}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if err := runInitWithInput(t.Context(), initCommand{}, strings.NewReader("5174\n"), true, &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	config, err := os.ReadFile(path)
	if err != nil || !strings.Contains(string(config), `dev: { command: ["node","server.js"], port: 5174 }`) || !strings.Contains(stdout.String(), "[ tnl init ]-- configured") || !strings.Contains(stdout.String(), "updated") || strings.Contains(stdout.String(), "needs action") || !strings.Contains(stderr.String(), "dev port") {
		t.Fatalf("config = %q, stdout = %q, stderr = %q, err = %v", config, stdout.String(), stderr.String(), err)
	}
}

func TestInitPreservesCustomizedGenericService(t *testing.T) {
	for _, test := range []struct{ name, script string }{{"script", "node server.js"}, {"no script", ""}} {
		t.Run(test.name, func(t *testing.T) {
			root := genericInitFixture(t, test.script, "npm")
			t.Chdir(root)
			if err := runInitWithInput(t.Context(), initCommand{}, strings.NewReader(""), false, &bytes.Buffer{}, &bytes.Buffer{}); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(root, "tnl.config.ts")
			custom := bytes.Replace(initConfigSourceWithPort("app", []string{"node", "server.js"}, 4173), []byte("  services:"), []byte("  // configured by the developer\n  services:"), 1)
			if err := os.WriteFile(path, custom, 0o600); err != nil {
				t.Fatal(err)
			}
			var stdout, stderr bytes.Buffer
			if err := runInitWithInput(t.Context(), initCommand{}, strings.NewReader(""), true, &stdout, &stderr); err != nil {
				t.Fatal(err)
			}
			after, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(after, custom) || !strings.Contains(stdout.String(), "[ tnl init ]-- already configured") || strings.Contains(stdout.String(), "services.app.dev.port") || stderr.Len() != 0 {
				t.Fatalf("config = %q, stdout = %q, stderr = %q, err = %v", after, stdout.String(), stderr.String(), err)
			}
		})
	}
}

func TestInitMigratesGeneratedFrameworkCommandBeforeChangingDevScript(t *testing.T) {
	root := copyInitFixture(t, "next")
	path := filepath.Join(root, "tnl.config.ts")
	if err := os.WriteFile(path, initConfigSource("app", []string{"pnpm", "dev"}), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Chdir(root)
	var output bytes.Buffer
	if err := runInitWithInput(t.Context(), initCommand{NoInstall: true}, strings.NewReader(""), false, &output, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(data, initConfigSource("app", []string{"next", "dev"})) || !strings.Contains(output.String(), "scripts.dev to") || !strings.Contains(output.String(), `"tnl dev"`) {
		t.Fatalf("migrated config = %s, output = %s, err = %v", data, output.String(), err)
	}
	packagePath := filepath.Join(root, "package.json")
	packageJSON, err := os.ReadFile(packagePath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(packagePath, bytes.Replace(packageJSON, []byte("next dev"), []byte("tnl dev"), 1), 0o600); err != nil {
		t.Fatal(err)
	}
	output.Reset()
	if err := runInitWithInput(t.Context(), initCommand{NoInstall: true}, strings.NewReader(""), false, &output, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	data, err = os.ReadFile(path)
	if err != nil || !bytes.Equal(data, initConfigSource("app", []string{"next", "dev"})) || strings.Contains(output.String(), "scripts.dev to") {
		t.Fatalf("repeat config = %s, output = %s, err = %v", data, output.String(), err)
	}
}

func TestInitCannotReuseGenericScriptOnceItStartsTnl(t *testing.T) {
	root := genericInitFixture(t, "tnl dev", "pnpm")
	path := filepath.Join(root, "tnl.config.ts")
	if err := os.WriteFile(path, initConfigSourceWithPort("app", []string{"pnpm", "dev"}, 4242), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Chdir(root)
	var output bytes.Buffer
	if err := runInitWithInput(t.Context(), initCommand{NoInstall: true}, strings.NewReader(""), false, &output, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(data, initConfigSourceWithPort("app", nil, 4242)) || !strings.Contains(output.String(), "set services.app.dev.command") {
		t.Fatalf("generic config = %s, output = %s, err = %v", data, output.String(), err)
	}
}

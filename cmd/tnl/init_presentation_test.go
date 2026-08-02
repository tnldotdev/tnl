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
				if err != nil || string(gitignore) != ".tnl/\n" {
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

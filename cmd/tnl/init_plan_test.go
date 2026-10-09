package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestInitPlansNextProjectWithoutRewritingExistingFrameworkConfig(t *testing.T) {
	root := copyInitFixture(t, "next")
	path := filepath.Join(root, "next.config.ts")
	plan, err := planInit(t.Context(), root)
	if err != nil {
		t.Fatal(err)
	}
	if plan.manager != "pnpm" || plan.framework != "next" || !slices.Equal(plan.packages, []string{"@tnldotdev/tnl"}) || len(plan.frameworkAfter) != 0 || !slices.Equal(plan.actions, []string{frameworkConfigAction("next", path)}) {
		t.Fatalf("plan = %#v", plan)
	}
	for _, fragment := range []string{"app:", `directory: "."`, "defineConfig"} {
		if !strings.Contains(string(plan.configData), fragment) {
			t.Fatalf("planned configuration missing %q: %s", fragment, plan.configData)
		}
	}
	if _, err := os.Stat(filepath.Join(root, "tnl.config.ts")); !os.IsNotExist(err) {
		t.Fatalf("planning wrote configuration: %v", err)
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
	if !bytes.Equal(after, source) || len(plan.frameworkAfter) != 0 || !slices.Equal(plan.actions, []string{frameworkConfigAction("next", path)}) {
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
	plan := initPlan{framework: "vite"}
	if err := planFrameworkConfig(&plan, root); err != nil {
		t.Fatal(err)
	}
	want := "Configure @tnldotdev/tnl/vite in the intended framework config; multiple files were found."
	if plan.frameworkAfter != nil || !slices.Equal(plan.actions, []string{want}) {
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
	if plan.frameworkPath != filepath.Join(root, "next.config.ts") || !bytes.Equal(plan.frameworkAfter, frameworkConfigSource("next")) {
		t.Fatalf("plan = %#v", plan)
	}
}

func TestInitPlansGenericDevSettings(t *testing.T) {
	for _, test := range []struct {
		name, script, manager, command, action string
	}{
		{"dev script", "node server.js", "pnpm", `["node","server.js"]`, "set services.app.dev.port in tnl.config.ts to your app's listening port."},
		{"no dev script", "", "npm", "", "set services.app.dev.command and services.app.dev.port in tnl.config.ts."},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := genericInitFixture(t, test.script, test.manager)
			plan, err := planInit(t.Context(), root)
			if err != nil {
				t.Fatal(err)
			}
			if plan.framework != "" || !plan.genericDev || len(plan.actions) != 1 || !strings.Contains(plan.actions[0], "tnl.prepare") {
				t.Fatalf("plan = %#v", plan)
			}
			if strings.Contains(string(plan.configData), "dev:") {
				t.Fatalf("planned an application command: %s", plan.configData)
			}
			if strings.Contains(string(plan.configData), "port:") {
				t.Fatalf("planned an unrequested port: %s", plan.configData)
			}
		})
	}
}

func TestInitFrameworkWithoutDevScriptUsesDefaultCommand(t *testing.T) {
	for _, test := range []struct {
		framework, dependencies, command string
	}{
		{"next", `"next":"16.3.4"`, `["next","dev"]`},
		{"vite", `"vite":"6.0.9"`, `["vite"]`},
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
			if plan.framework != test.framework || plan.genericDev || strings.Contains(string(plan.configData), "command:") || strings.Contains(string(plan.configData), "port:") {
				t.Fatalf("plan = %#v, config = %s", plan, plan.configData)
			}
		})
	}
}

func genericInitFixture(t *testing.T, script, manager string) string {
	t.Helper()
	root := t.TempDir()
	scripts := ""
	if script != "" {
		scripts = fmt.Sprintf(`"scripts":{"dev":%q},`, script)
	}
	data := fmt.Sprintf(`{"packageManager":%q,%s"devDependencies":{"@tnldotdev/tnl":"1.0.0"}}`, manager+"@1", scripts)
	if err := os.WriteFile(filepath.Join(root, "package.json"), []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "tsconfig.json"), []byte(`{"include":[".tnl/project.d.ts"]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	return root
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

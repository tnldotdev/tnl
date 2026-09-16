package main

import (
	"bytes"
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
	for _, fragment := range []string{"app:", `directory: "."`, `["pnpm","dev"]`, "defineConfig"} {
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

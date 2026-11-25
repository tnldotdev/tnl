package main

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

type initReceipt struct {
	SchemaVersion int    `json:"schema_version"`
	Project       string `json:"project"`
	DryRun        bool   `json:"dry_run"`
	NoInstall     bool   `json:"no_install"`
	Files         []struct{ Path, Status string }
	Steps         []struct {
		Kind, Status, Path, Message string
		Argv                        []string
	}
}

func (r initReceipt) file(path string) string {
	for _, file := range r.Files {
		if file.Path == path {
			return file.Status
		}
	}
	return ""
}

func (r initReceipt) step(kind string) (string, []string) {
	for _, step := range r.Steps {
		if step.Kind == kind {
			return step.Status, step.Argv
		}
	}
	return "", nil
}

func runInitJSON(t *testing.T, args ...string) initReceipt {
	t.Helper()
	var stdout, stderr bytes.Buffer
	err := run(t.Context(), append([]string{"--no-telemetry", "init", "--output", "json"}, args...), &stdout, &stderr)
	if err != nil || stderr.Len() != 0 {
		t.Fatalf("init: %v; stderr %q", err, &stderr)
	}
	var result initReceipt
	decoder := json.NewDecoder(&stdout)
	if err := decoder.Decode(&result); err != nil || decoder.Decode(new(any)) != io.EOF || result.SchemaVersion != 1 ||
		!filepath.IsAbs(result.Project) || result.Files == nil || result.Steps == nil {
		t.Fatalf("invalid receipt: %+v; %v", result, err)
	}
	return result
}

func putInitFile(t *testing.T, root, name, content string, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(root, name), []byte(content), mode); err != nil {
		t.Fatal(err)
	}
}

func TestInitJSONDryRunDoesNotEvaluateOrWrite(t *testing.T) {
	root, bin := t.TempDir(), t.TempDir()
	t.Chdir(root)
	t.Setenv("TNL_STATE_DIR", filepath.Join(root, "state"))
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("INIT_MARKER", filepath.Join(root, "called"))
	for _, program := range []string{"node", "pnpm", "uv"} {
		putInitFile(t, bin, program, "#!/bin/sh\n: > \"$INIT_MARKER\"\nexit 1\n", 0o700)
	}
	putInitFile(t, root, "package.json", `{"packageManager":"pnpm@11","devDependencies":{"vite":"6"}}`, 0o600)
	putInitFile(t, root, "tnl.config.ts", "throw new Error('dry run must not evaluate this')\n", 0o600)
	putInitFile(t, root, "tsconfig.json", `{"include":["src"]}`, 0o600)
	putInitFile(t, root, "pyproject.toml", "[project]\nname = 'example'\n", 0o600)

	plan := runInitJSON(t, "--dry-run")
	if !plan.DryRun || plan.NoInstall || plan.file("tnl.config.ts") != "unchanged" || plan.file("vite.config.ts") != "create" ||
		plan.file(".gitignore") != "create" || plan.file("tsconfig.json") != "update" || plan.file(".tnl/generated/project.d.ts") != "" {
		t.Fatalf("preview files = %+v", plan)
	}
	if status, argv := plan.step("install_node"); status != "planned" || !slices.Equal(argv, []string{"pnpm", "add", "--save-dev", "--reporter=silent", "@tnldotdev/tnl"}) {
		t.Fatalf("planned install = %s %v", status, argv)
	}
	if status, _ := plan.step("generate"); status != "conditional" {
		t.Fatalf("planned generation = %q", status)
	}
	manual := runInitJSON(t, "--dry-run", "--no-install")
	if status, argv := manual.step("install_node"); !manual.NoInstall || status != "outstanding" || !slices.Equal(argv, []string{"pnpm", "add", "--save-dev", "@tnldotdev/tnl"}) {
		t.Fatalf("manual install = %s %v", status, argv)
	}
	entries, err := os.ReadDir(root)
	if err != nil || len(entries) != 4 {
		t.Fatalf("preview wrote files: %v; %v", entries, err)
	}
	if data, err := os.ReadFile(filepath.Join(root, "tsconfig.json")); err != nil || string(data) != `{"include":["src"]}` {
		t.Fatalf("preview edited tsconfig: %q; %v", data, err)
	}
}

func TestInitJSONNoInstallReportsActualChangesAndPreservesEdits(t *testing.T) {
	root, bin := t.TempDir(), t.TempDir()
	t.Chdir(root)
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("GIT_CONFIG_GLOBAL", os.DevNull)
	t.Setenv("GIT_CONFIG_NOSYSTEM", "1")
	for _, program := range []string{"pnpm", "uv"} {
		putInitFile(t, bin, program, "#!/bin/sh\nexit 71\n", 0o700)
	}
	putInitFile(t, root, "package.json", `{"packageManager":"pnpm@11","devDependencies":{"vite":"6"}}`, 0o600)
	putInitFile(t, root, "pyproject.toml", "[project]\nname = 'example'\n", 0o600)
	putInitFile(t, root, "tnl.yml", "version: 1\ntnl:\n  services: {}\n", 0o600)
	putInitFile(t, root, "tsconfig.json", `{"include":["src"]}`, 0o600)

	first := runInitJSON(t, "--no-install")
	if first.DryRun || !first.NoInstall || first.file("tnl.yml") != "unchanged" || first.file("vite.config.ts") != "created" ||
		first.file(".gitignore") != "created" || first.file("tsconfig.json") != "updated" ||
		first.file(".tnl/generated/project.d.ts") != "created" || first.file(".tnl/local/completion.json") != "created" {
		t.Fatalf("first receipt = %+v", first)
	}
	for _, kind := range []string{"install_node", "install_python"} {
		if status, argv := first.step(kind); status != "outstanding" || len(argv) == 0 {
			t.Fatalf("%s = %q %v", kind, status, argv)
		}
	}
	if status, _ := first.step("generate"); status != "executed" {
		t.Fatalf("generation = %q", status)
	}

	const customized = "// Keep my custom Vite plugin.\nexport default { plugins: [] }\n"
	putInitFile(t, root, "vite.config.ts", customized, 0o600)
	putInitFile(t, root, ".tnl/generated/services.ts", "// stale artifact\n", 0o600)
	repeat := runInitJSON(t, "--no-install")
	if repeat.file("vite.config.ts") != "unchanged" || repeat.file("tsconfig.json") != "unchanged" ||
		repeat.file(".tnl/generated/project.d.ts") != "unchanged" || repeat.file(".tnl/generated/services.ts") != "updated" ||
		repeat.file(".tnl/local/completion.json") != "unchanged" {
		t.Fatalf("repeat receipt = %+v", repeat)
	}
	if data, err := os.ReadFile(filepath.Join(root, "vite.config.ts")); err != nil || string(data) != customized {
		t.Fatalf("custom Vite config overwritten: %q; %v", data, err)
	}
}

func TestInitUsesSelectedCheckoutForFilesAndWait(t *testing.T) {
	launch := t.TempDir()
	root := filepath.Join(t.TempDir(), "selected checkout")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Chdir(launch)
	t.Setenv("GIT_CONFIG_GLOBAL", os.DevNull)
	t.Setenv("GIT_CONFIG_NOSYSTEM", "1")
	putInitFile(t, root, "tnl.yml", "version: 1\ntnl:\n  services: {}\n", 0o600)
	var stdout, stderr bytes.Buffer
	if err := run(t.Context(), []string{"--no-telemetry", "--cwd", root, "init", "--no-install", "--output", "human"}, &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	canonical, err := filepath.EvalSymlinks(root)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(stdout.String(), "\ntnl --cwd "+shellWord(canonical)+" wait\n") || stderr.Len() != 0 {
		t.Fatalf("init output = %q, stderr = %q", &stdout, &stderr)
	}
	if _, err := os.Stat(filepath.Join(root, ".tnl", "generated", "project.d.ts")); err != nil {
		t.Fatal("generated files are missing in the selected checkout:", err)
	}
	if entries, err := os.ReadDir(launch); err != nil || len(entries) != 0 {
		t.Fatalf("init wrote to the launch directory: %v (%v)", entries, err)
	}
}

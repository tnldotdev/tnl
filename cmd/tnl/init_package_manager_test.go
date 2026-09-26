package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestInitInstallsMissingPackageWithDetectedManager(t *testing.T) {
	root := copyInitFixture(t, "next")
	bin := t.TempDir()
	marker := filepath.Join(t.TempDir(), "arguments")
	// One argv element per line proves the actual invocation, including cwd.
	script := "#!/bin/sh\nprintf '%s\\n' \"$PWD\" \"$@\" > \"$TNL_INIT_MARKER\"\n"
	if err := os.WriteFile(filepath.Join(bin, "pnpm"), []byte(script), 0o700); err != nil {
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
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	want := []string{cwd, "add", "--save-dev", "--reporter=silent", "@tnldotdev/tnl"}
	if !slices.Equal(strings.Split(strings.TrimSuffix(string(arguments), "\n"), "\n"), want) || !strings.Contains(stdout.String(), "installed") || stderr.Len() != 0 {
		t.Fatalf("arguments = %q, want %v; stdout = %q, stderr = %q", arguments, want, stdout.String(), stderr.String())
	}
}

func TestRunInitInstallPreservesCommandContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	go func() {
		time.Sleep(20 * time.Millisecond)
		cancel()
	}()
	err := runInitInstall(ctx, t.TempDir(), []string{"sh", "-c", "exec sleep 30"})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("install error = %v", err)
	}
	if code, render := terminalResult(err); code != 0 || render != nil {
		t.Fatalf("terminal result = %d, %v", code, render)
	}
}

func TestInitDevCommandPrefersPackageScript(t *testing.T) {
	for _, test := range []struct {
		name, framework, manager string
		scripts                  map[string]string
		want                     []string
	}{
		{"pnpm next", "next", "pnpm", map[string]string{"dev": "next dev --turbo"}, []string{"pnpm", "dev"}},
		{"yarn vite", "vite", "yarn", map[string]string{"dev": "vite --host"}, []string{"yarn", "dev"}},
		{"npm next", "next", "npm", map[string]string{"dev": "next dev"}, []string{"npm", "run", "dev"}},
		{"bun vite", "vite", "bun", map[string]string{"dev": "vite"}, []string{"bun", "run", "dev"}},
		{"unknown manager", "next", "", map[string]string{"dev": "next dev"}, []string{"npm", "run", "dev"}},
		{"pnpm generic", "", "pnpm", map[string]string{"dev": "node server.js"}, []string{"pnpm", "dev"}},
		{"yarn generic", "", "yarn", map[string]string{"dev": "node server.js"}, []string{"yarn", "dev"}},
		{"bun generic", "", "bun", map[string]string{"dev": "node server.js"}, []string{"bun", "run", "dev"}},
		{"npm generic", "", "npm", map[string]string{"dev": "node server.js"}, []string{"npm", "run", "dev"}},
		{"next fallback", "next", "", nil, []string{"next", "dev"}},
		{"vite fallback", "vite", "", nil, []string{"vite"}},
		{"no framework or script", "", "pnpm", nil, nil},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := initDevCommand(test.framework, test.manager, test.scripts); !slices.Equal(got, test.want) {
				t.Fatalf("initDevCommand() = %v, want %v", got, test.want)
			}
		})
	}
}

func TestParseInitCommandKeepsQuotedArguments(t *testing.T) {
	for _, test := range []struct {
		input string
		want  []string
	}{
		{`node server.js --name "two words"`, []string{"node", "server.js", "--name", "two words"}},
		{`node 'server file.js' escaped\ space`, []string{"node", "server file.js", "escaped space"}},
		{`node "unclosed`, nil},
		{`node ""`, nil},
	} {
		got, err := parseInitCommand(test.input)
		if (err != nil) != (test.want == nil) || !slices.Equal(got, test.want) {
			t.Fatalf("parseInitCommand(%q) = %v, %v; want %v", test.input, got, err, test.want)
		}
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
	for path, data := range map[string]string{
		filepath.Join(workspace, "package.json"):   `{"packageManager":"pnpm@10","workspaces":["apps/*"]}`,
		filepath.Join(workspace, "pnpm-lock.yaml"): "lockfileVersion: '9.0'\n",
		filepath.Join(root, "package.json"):        `{"dependencies":{"vite":"8.2.2"}}`,
	} {
		if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	plan, err := planInit(t.Context(), root)
	if err != nil {
		t.Fatal(err)
	}
	if plan.manager != "pnpm" || plan.root != root {
		t.Fatalf("plan = %#v", plan)
	}
}

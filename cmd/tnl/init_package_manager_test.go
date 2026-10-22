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

	projectinit "github.com/tnldotdev/tnl/internal/client/project/init"
)

func TestInitInstallsMissingPackageWithDetectedManager(t *testing.T) {
	root := copyInitFixture(t, "next")
	bin := t.TempDir()
	marker := filepath.Join(t.TempDir(), "arguments")
	// one argv element per line proves the actual invocation, including cwd.
	script := "#!/bin/sh\nprintf '%s\\n' \"$PWD\" \"$@\" > \"$TNL_INIT_MARKER\"\n"
	if err := os.WriteFile(filepath.Join(bin, "pnpm"), []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
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

func TestRunInitInstallCancellationHasSuccessfulTerminalResult(t *testing.T) {
	root := copyInitFixture(t, "next")
	plan, err := planInit(t.Context(), root)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	_, err = plan.Apply(ctx, projectinit.Options{Generate: func(context.Context, string, string) error {
		t.Fatal("generated after canceled installation")
		return nil
	}})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("install error = %v", err)
	}
	if code, render := terminalResult(err); code != 0 || render != nil {
		t.Fatalf("terminal result = %d, %v", code, render)
	}
}

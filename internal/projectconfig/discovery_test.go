package projectconfig

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func TestSelectProjectConfigExplicitAndNonGitSelection(t *testing.T) {
	root := t.TempDir()
	nested := filepath.Join(root, "a", "b")
	if err := os.MkdirAll(nested, 0o700); err != nil {
		t.Fatal(err)
	}
	rootConfig := filepath.Join(root, "tnl.yml")
	nearConfig := filepath.Join(root, "a", "tnl.json")
	for _, path := range []string{rootConfig, nearConfig} {
		if err := os.WriteFile(path, []byte("{}"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	selection, err := SelectProjectConfig(t.Context(), nested, nearConfig, "", false)
	if err != nil || selection.Path != nearConfig || !selection.Explicit {
		t.Fatalf("explicit selection = %#v, %v", selection, err)
	}

	// discovery outside a Git worktree inspects cwd only.
	selection, err = SelectProjectConfig(t.Context(), filepath.Join(root, "a"), "", "", false)
	if err != nil || selection.Path != nearConfig || selection.Explicit {
		t.Fatalf("discovered selection = %#v, %v", selection, err)
	}
	selection, err = SelectProjectConfig(t.Context(), nested, "", "", false)
	if err != nil || selection.Path != "" {
		t.Fatalf("non-Git discovery escaped cwd: %#v, %v", selection, err)
	}
}

func TestSelectProjectConfigWalksAncestorsAndStopsAtRepositoryBoundary(t *testing.T) {
	outside := t.TempDir()
	var err error
	outside, err = filepath.EvalSymlinks(outside)
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(outside, "repo")
	nested := filepath.Join(root, "apps", "web", "src")
	if err := os.MkdirAll(nested, 0o700); err != nil {
		t.Fatal(err)
	}
	command := exec.CommandContext(t.Context(), "git", "init", "--initial-branch=0xcadams/test", root)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("git init: %v\n%s", err, output)
	}
	outerConfig, rootConfig, nearConfig := filepath.Join(outside, "tnl.yml"), filepath.Join(root, "tnl.json"), filepath.Join(root, "apps", "tnl.yaml")
	for _, path := range []string{outerConfig, rootConfig, nearConfig} {
		if err := os.WriteFile(path, []byte("{}"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for _, want := range []string{nearConfig, rootConfig, ""} {
		selection, err := SelectProjectConfig(t.Context(), nested, "", "", false)
		if err != nil || selection.Path != want || selection.Explicit {
			t.Fatalf("discovery = %#v, %v; want %q", selection, err, want)
		}
		if want != "" {
			if err := os.Remove(want); err != nil {
				t.Fatal(err)
			}
		}
	}
	// explicit selection may cross the boundary and flags take precedence over env.
	selection, err := SelectProjectConfig(t.Context(), nested, outerConfig, "missing.yml", false)
	if err != nil || selection.Path != outerConfig || !selection.Explicit {
		t.Fatalf("explicit outside selection = %#v, %v", selection, err)
	}
}

func TestSelectProjectConfigRejectsAmbiguity(t *testing.T) {
	directory := t.TempDir()
	for _, name := range []string{"tnl.yml", "tnl.config.ts"} {
		if err := os.WriteFile(filepath.Join(directory, name), []byte(""), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := SelectProjectConfig(t.Context(), directory, "", "", false); err == nil {
		t.Fatal("ambiguous configuration was accepted")
	}
	if selection, err := SelectProjectConfig(t.Context(), directory, "", "ignored", true); err != nil || selection.Path != "" {
		t.Fatalf("disabled selection = %#v, %v", selection, err)
	}
}

func TestSelectProjectConfigRejectsOtherTypeScriptNames(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "project.ts")
	if err := os.WriteFile(path, []byte("export default {};"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := SelectProjectConfig(t.Context(), directory, path, "", false); err == nil {
		t.Fatal("noncanonical TypeScript configuration name was accepted")
	}
}

func TestSelectProjectConfigCancelsGitDiscovery(t *testing.T) {
	bin := t.TempDir()
	if err := os.WriteFile(filepath.Join(bin, "git"), []byte("#!/bin/sh\nexec sleep 60\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer cancel()
	if _, err := SelectProjectConfig(ctx, t.TempDir(), "", "", false); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("discovery error = %v, want deadline exceeded", err)
	}
}

func TestConfigNamesReturnsIndependentSlice(t *testing.T) {
	names := ConfigNames()
	names[0] = "other.yml"
	if got := ConfigNames()[0]; got != "tnl.yml" {
		t.Fatalf("first configuration filename = %q", got)
	}
}

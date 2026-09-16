package projectconfig

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
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
	selection, err := SelectProjectConfig(nested, nearConfig, "", false)
	if err != nil || selection.Path != nearConfig || !selection.Explicit {
		t.Fatalf("explicit selection = %#v, %v", selection, err)
	}

	// Discovery outside a Git worktree intentionally inspects cwd only.
	selection, err = SelectProjectConfig(filepath.Join(root, "a"), "", "", false)
	if err != nil || selection.Path != nearConfig || selection.Explicit {
		t.Fatalf("discovered selection = %#v, %v", selection, err)
	}
	selection, err = SelectProjectConfig(nested, "", "", false)
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
		selection, err := SelectProjectConfig(nested, "", "", false)
		if err != nil || selection.Path != want || selection.Explicit {
			t.Fatalf("discovery = %#v, %v; want %q", selection, err, want)
		}
		if want != "" {
			if err := os.Remove(want); err != nil {
				t.Fatal(err)
			}
		}
	}
	// Explicit selection is allowed to cross the boundary and flags beat env.
	selection, err := SelectProjectConfig(nested, outerConfig, "missing.yml", false)
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
	if _, err := SelectProjectConfig(directory, "", "", false); err == nil {
		t.Fatal("ambiguous configuration was accepted")
	}
	if selection, err := SelectProjectConfig(directory, "", "ignored", true); err != nil || selection.Path != "" {
		t.Fatalf("disabled selection = %#v, %v", selection, err)
	}
}

func TestSelectProjectConfigRejectsOtherTypeScriptNames(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "project.ts")
	if err := os.WriteFile(path, []byte("export default {};"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := SelectProjectConfig(directory, path, "", false); err == nil {
		t.Fatal("noncanonical TypeScript configuration name was accepted")
	}
}

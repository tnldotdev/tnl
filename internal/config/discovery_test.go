package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSelectProjectConfigUsesNearestFile(t *testing.T) {
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

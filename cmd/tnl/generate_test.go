package main

import (
	"bytes"
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/publisherdeployment"
)

func generationGit(t *testing.T, directory string, args ...string) []byte {
	t.Helper()
	command := exec.CommandContext(t.Context(), "git", args...)
	command.Dir = directory
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, output)
	}
	return output
}

func TestGenerateTypesWithoutGitOriginOrRuntimeValues(t *testing.T) {
	for _, name := range []string{"tnl.yml", "tnl.config.ts"} {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			source := "version: 1\ntnl:\n  services:\n    api: {}\n"
			if name == "tnl.config.ts" {
				source = `import { defineConfig } from "@tnldotdev/tnl/config"; export default defineConfig({ services: { api: {} } });`
			}
			if err := os.WriteFile(filepath.Join(root, name), []byte(source), 0600); err != nil {
				t.Fatal(err)
			}
			t.Chdir(root)
			t.Setenv("TNL_PROJECT_RUNTIME", "invalid-runtime-must-not-be-read")
			t.Setenv("TNL_STATE_DIR", filepath.Join(root, "unused-state"))
			for _, args := range [][]string{{"check"}, {"generate"}, {"generate", "--check"}} {
				if err := run(t.Context(), args, &bytes.Buffer{}, &bytes.Buffer{}, func(string) telemetryReporter { t.Fatal("offline command opened telemetry"); return nil }); err != nil {
					t.Fatal(args, err)
				}
			}
			if _, err := os.Stat(filepath.Join(root, ".tnl/local")); !os.IsNotExist(err) {
				t.Fatal("generation wrote runtime values")
			}
			if _, err := os.Stat(filepath.Join(root, "unused-state")); !os.IsNotExist(err) {
				t.Fatal("offline command opened client state")
			}
			if err := run(t.Context(), []string{"config", "generate"}, &bytes.Buffer{}, &bytes.Buffer{}); err == nil {
				t.Fatal("retired command still accepted")
			}
		})
	}
}

func TestGenerateOfflineAcrossWorktreesAndReadOnlyCheck(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	first, second := filepath.Join(root, "first"), filepath.Join(root, "second")
	if err := os.Mkdir(first, 0755); err != nil {
		t.Fatal(err)
	}
	generationGit(t, first, "init", "-b", "main")
	generationGit(t, first, "remote", "add", "origin", "https://user:git-credential@example.test/company/project.git")
	generationGit(t, first, "worktree", "add", "--orphan", "-b", "other", second)
	state := filepath.Join(root, "unused-client-state")
	t.Setenv("TNL_STATE_DIR", state)
	t.Setenv("TNL_ACCESS_TOKEN", "do-not-serialize-session")
	t.Setenv("TNL_SERVER", "https://do-not-contact.invalid")
	configSource := `export default { publishers: { production: { aws: { replicas: 2 } } } };`
	var expected map[string][]byte
	for _, directory := range []string{first, second} {
		if err := os.WriteFile(filepath.Join(directory, "tnl.config.ts"), []byte(configSource), 0644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(directory, ".gitignore"), []byte("/.tnl/local/\n"), 0644); err != nil {
			t.Fatal(err)
		}
		t.Chdir(directory)
		var stdout, stderr bytes.Buffer
		runCommand := func(args ...string) error {
			return run(t.Context(), args, &stdout, &stderr, func(string) telemetryReporter { t.Fatal("generation opened telemetry"); return nil })
		}
		if err := runCommand("generate", "--check"); err == nil {
			t.Fatal("check accepted missing artifacts")
		} else {
			reason, _ := failure.ReasonOf(err)
			if reason != failure.PublisherDeploymentInvalid || !errors.Is(err, fs.ErrNotExist) {
				t.Fatal("generation error lost classification or cause", err)
			}
			var rendered bytes.Buffer
			writeCommandError(&rendered, err)
			if !strings.Contains(rendered.String(), "tnl generate") || strings.Contains(rendered.String(), directory) {
				t.Fatal("generation error leaked the filesystem cause or lost the command")
			}
		}
		if _, err := os.Stat(filepath.Join(directory, ".tnl")); !os.IsNotExist(err) {
			t.Fatal("check created .tnl")
		}
		if err := runCommand("generate"); err != nil {
			t.Fatal(err)
		}
		before := generationSnapshot(t, directory)
		if err := runCommand("generate", "--check"); err != nil {
			t.Fatal(err)
		}
		if after := generationSnapshot(t, directory); !reflect.DeepEqual(before, after) {
			t.Fatal("check changed tracked/generated files")
		}
		manifest, err := publisherdeployment.Read(filepath.Join(directory, publisherdeployment.DefaultOutputDir))
		if err != nil {
			t.Fatal(err)
		}
		files := map[string][]byte{}
		for _, name := range []string{"manifest.json", "project.d.ts", "python/pyproject.toml", "python/tnl_project/__init__.py", "python/tnl_project/py.typed", manifest.DocumentationPath, manifest.Publishers[0].TemplatePath, manifest.Publishers[0].ParametersExamplePath, manifest.Publishers[0].StoragePolicyPath} {
			data, err := os.ReadFile(filepath.Join(directory, publisherdeployment.DefaultOutputDir, name))
			if err != nil {
				t.Fatal(err)
			}
			for _, forbidden := range []string{root, "do-not-serialize-session", "git-credential", "do-not-contact.invalid"} {
				if bytes.Contains(data, []byte(forbidden)) {
					t.Fatal("generation leaked local or secret input")
				}
			}
			files[name] = data
		}
		if expected == nil {
			expected = files
		} else if !reflect.DeepEqual(expected, files) {
			t.Fatal("equivalent linked worktrees generated different artifacts")
		}
		ignored := generationGit(t, directory, "check-ignore", "--no-index", ".tnl/local/project.json")
		if strings.TrimSpace(string(ignored)) != ".tnl/local/project.json" {
			t.Fatal("local metadata not ignored")
		}
		tracked := generationGit(t, directory, "ls-files", "--others", "--exclude-standard", ".tnl/generated")
		if len(strings.Fields(string(tracked))) != len(files) {
			t.Fatalf("generated outputs are not trackable: %s", tracked)
		}
		if err := runCommand("generate", "--output-dir", "infrastructure/generated"); err != nil {
			t.Fatal(err)
		}
		if err := runCommand("generate", "--check", "--output-dir", "infrastructure/generated"); err != nil {
			t.Fatal(err)
		}
		if stderr.Len() != 0 {
			t.Fatalf("unexpected diagnostics: %s", stderr.String())
		}
	}
	if _, err := os.Stat(state); !os.IsNotExist(err) {
		t.Fatal("offline generation opened client state")
	}
}

type generationFile struct {
	Data     string
	Mode     fs.FileMode
	Modified time.Time
}

func generationSnapshot(t *testing.T, root string) map[string]generationFile {
	t.Helper()
	result := map[string]generationFile{}
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.Name() == ".git" {
			if entry.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if entry.IsDir() {
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		result[relative] = generationFile{string(data), info.Mode(), info.ModTime()}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return result
}

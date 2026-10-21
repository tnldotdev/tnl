package main

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tnldotdev/tnl/internal/projectmeta"
	"github.com/tnldotdev/tnl/internal/sourcestate"
)

func initIgnoreGit(t *testing.T, root string, args ...string) string {
	t.Helper()
	cmd := exec.CommandContext(t.Context(), "git", args...)
	cmd.Dir = root
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v: %s", args, err, output)
	}
	return string(output)
}

func initIgnoreRepository(t *testing.T, root string) {
	t.Helper()
	t.Setenv("GIT_CONFIG_GLOBAL", os.DevNull)
	t.Setenv("GIT_CONFIG_NOSYSTEM", "1")
	initIgnoreGit(t, root, "init", "--quiet", "--template=")
}

func assertInitIgnored(t *testing.T, root, path string, ignored bool) {
	t.Helper()
	cmd := exec.CommandContext(t.Context(), "git", "check-ignore", "--no-index", "--quiet", "--", path)
	cmd.Dir = root
	err := cmd.Run()
	var exit *exec.ExitError
	if err != nil && (!errors.As(err, &exit) || exit.ExitCode() != 1) {
		t.Fatal(err)
	}
	if (err == nil) != ignored {
		t.Fatalf("git check-ignore %s: ignored = %t, want %t", path, err == nil, ignored)
	}
}

func writeInitIgnoreFixture(t *testing.T, root, name, contents string) {
	t.Helper()
	path := filepath.Join(root, name)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestInitGitignoreActualGitAndSourceState(t *testing.T) {
	for _, before := range []string{"", "# keep\r\nnode_modules/\r\n# tnl\r\n.tnl/\r\n"} {
		t.Run(before, func(t *testing.T) {
			root := genericInitFixture(t, "node server.js", "npm")
			initIgnoreRepository(t, root)
			writeInitIgnoreFixture(t, root, ".gitignore", before)
			t.Chdir(root)
			var previous []byte
			for run := range 2 {
				var output bytes.Buffer
				if err := runInit(t.Context(), initCommand{NoInstall: true}, &output, &bytes.Buffer{}); err != nil {
					t.Fatal(err)
				}
				if !strings.Contains(output.String(), tnlLocalIgnoreRule) || strings.Contains(output.String(), "Narrow custom") {
					t.Fatal(output.String())
				}
				after, err := os.ReadFile(filepath.Join(root, ".gitignore"))
				if err != nil || run > 0 && !bytes.Equal(previous, after) {
					t.Fatalf("init changed ignore rules on repeat: %q, %v", after, err)
				}
				previous = after
			}
			// source capture needs a HEAD in this isolated repository, whose
			// Git configuration does not inherit the user's keys.
			initIgnoreGit(t, root, "add", ".")
			initIgnoreGit(t, root, "-c", "user.name=Test", "-c", "user.email=test@example.test", "commit", "--quiet", "-m", "fixture")
			if err := projectmeta.Write(t.Context(), root, projectmeta.Metadata{Version: projectmeta.Version, Services: map[string]projectmeta.Service{}}); err != nil {
				t.Fatal(err)
			}
			for _, path := range []string{".tnl/local/project.json", ".tnl/local/project.lock", ".tnl/local/.project-interrupted"} {
				assertInitIgnored(t, root, path, true)
			}
			for _, path := range []string{".tnl/generated/example.ts", ".tnl/config.json", "apps/other/.tnl/local/project.json"} {
				writeInitIgnoreFixture(t, root, path, "intentional source\n")
				assertInitIgnored(t, root, path, false)
			}
			writeInitIgnoreFixture(t, root, ".tnl/local/.project-interrupted", "local temporary output\n")
			state, err := sourcestate.Capture(t.Context(), root)
			if err != nil || !state.Complete || len(state.ChangedFiles) != 3 {
				t.Fatalf("source state = %+v, %v", state, err)
			}
			for _, file := range state.ChangedFiles {
				if strings.HasPrefix(file.Path, ".tnl/local/") {
					t.Fatalf("local output captured: %+v", file)
				}
			}
			initIgnoreGit(t, root, "add", ".tnl/generated/example.ts", ".tnl/config.json")
			if files := initIgnoreGit(t, root, "ls-files", "--", ".tnl"); files != ".tnl/config.json\n.tnl/generated/example.ts\n.tnl/generated/manifest.json\n.tnl/generated/project.d.ts\n.tnl/generated/python/pyproject.toml\n.tnl/generated/python/tnl_project/__init__.py\n.tnl/generated/python/tnl_project/py.typed\n.tnl/generated/readme.md\n" {
				t.Fatalf("trackable files = %q", files)
			}
		})
	}
}

func TestInitGitignoreCustomRulesAreDiagnosedAndPreserved(t *testing.T) {
	for _, pattern := range []string{".tnl", ".tnl/", "/.tnl/", ".tnl/*", "**/.tnl/**", ".*/", "*.ts"} {
		t.Run(pattern, func(t *testing.T) {
			root := genericInitFixture(t, "", "npm")
			initIgnoreRepository(t, root)
			before := "# custom rule\r\n" + pattern + "\r\n# keep this comment\r\n"
			writeInitIgnoreFixture(t, root, ".gitignore", before)
			t.Chdir(root)
			for range 2 {
				var output bytes.Buffer
				if err := runInit(t.Context(), initCommand{NoInstall: true}, &output, &bytes.Buffer{}); err != nil {
					t.Fatal(err)
				}
				if !strings.Contains(output.String(), "needs action") || !strings.Contains(output.String(), ".gitignore:2") || !strings.Contains(output.String(), "Narrow custom") {
					t.Fatalf("missing custom rule action: %s", output.String())
				}
				after, err := os.ReadFile(filepath.Join(root, ".gitignore"))
				if err != nil || string(after) != before+"# tnl\r\n/.tnl/local/\r\n" {
					t.Fatalf("custom rules changed: %q, %v", after, err)
				}
			}
		})
	}
}

func TestInitGitignoreNestedProjectRoot(t *testing.T) {
	root := t.TempDir()
	initIgnoreRepository(t, root)
	project := filepath.Join(root, "apps", "web")
	writeInitIgnoreFixture(t, root, "package.json", `{"workspaces":["apps/*"]}`)
	writeInitIgnoreFixture(t, project, "package.json", `{"packageManager":"npm@1","devDependencies":{"@tnldotdev/tnl":"1.0.0"}}`)
	writeInitIgnoreFixture(t, project, "src/app.ts", "")
	t.Chdir(filepath.Join(project, "src"))
	if err := runInit(t.Context(), initCommand{NoInstall: true}, &bytes.Buffer{}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, ".gitignore")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("init edited the repository root: %v", err)
	}
	assertInitIgnored(t, root, "apps/web/.tnl/local/project.json", true)
	for _, path := range []string{".tnl/local/project.json", "apps/api/.tnl/local/project.json", "apps/web/src/.tnl/local/project.json", "apps/web/.tnl/generated/example.ts", "apps/web/.tnl/config.json"} {
		assertInitIgnored(t, root, path, false)
	}
	// an ancestor's custom broad rule still wins over the nested rule.
	writeInitIgnoreFixture(t, root, ".gitignore", "**/.tnl/\n")
	actions := projectGitignoreActions(t.Context(), project)
	if len(actions) == 0 || !strings.Contains(strings.Join(actions, "\n"), ".gitignore:1") {
		t.Fatalf("ancestor conflict not diagnosed: %v", actions)
	}
}

func TestInitGitignoreWithoutRepositoryAndWithNegations(t *testing.T) {
	root := t.TempDir()
	t.Setenv("GIT_CONFIG_GLOBAL", os.DevNull)
	t.Setenv("GIT_CONFIG_NOSYSTEM", "1")
	writeInitIgnoreFixture(t, root, ".gitignore", ".tnl/*\n!.tnl/*\n")
	if _, err := ensureTnlGitignore(root); err != nil {
		t.Fatal(err)
	}
	if actions := projectGitignoreActions(t.Context(), root); len(actions) != 0 {
		t.Fatalf("trackable files diagnosed as ignored: %v", actions)
	}
	if _, err := os.Stat(filepath.Join(root, ".git")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("created project Git state: %v", err)
	}
	writeInitIgnoreFixture(t, root, ".gitignore", "/.tnl/local/\n!/.tnl/local/\n")
	if actions := projectGitignoreActions(t.Context(), root); len(actions) == 0 || !strings.Contains(actions[0], "not ignored") {
		t.Fatalf("local negation not diagnosed: %v", actions)
	}
}

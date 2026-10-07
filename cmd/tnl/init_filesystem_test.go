package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tnldotdev/tnl/internal/projectconfig"
)

func TestInitPreservesExistingStaticConfiguration(t *testing.T) {
	root := copyInitFixture(t, "next")
	path := filepath.Join(root, "tnl.yml")
	static := []byte("version: 1\ntnl:\n  team: Existing Team\n")
	if err := os.WriteFile(path, static, 0o600); err != nil {
		t.Fatal(err)
	}
	plan, err := planInit(t.Context(), root)
	if err != nil {
		t.Fatal(err)
	}
	if plan.configPath != path || plan.configData != nil {
		t.Fatalf("plan = %#v", plan)
	}
	t.Chdir(root)
	if err := runInit(t.Context(), initCommand{NoInstall: true}, &bytes.Buffer{}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(got, static) {
		t.Fatalf("existing config changed: %q, %v", got, err)
	}
	if _, err := os.Stat(filepath.Join(root, "tnl.config.ts")); !os.IsNotExist(err) {
		t.Fatalf("created conflicting TypeScript config: %v", err)
	}
}

func TestProjectTypeIncludeActionsPreserveConfiguration(t *testing.T) {
	root := t.TempDir()
	service := filepath.Join(root, "apps", "api")
	if err := os.MkdirAll(service, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(service, "tsconfig.json")
	project := projectConfiguration{Project: projectconfig.Project{Root: root, ServiceDirectories: map[string]string{"api": service}}}
	for _, test := range []struct {
		name, source string
		wantAction   bool
	}{
		{"missing_include", "{\n  \"include\": [\"src/**/*.ts\"]\n}\n", true},
		{"included", "{\n  \"include\": [\"src/**/*.ts\", \"../../.tnl/project.d.ts\"]\n}\n", false},
		{"jsonc", "{\n  // preserve this JSONC file\n  \"include\": [\"src\"]\n}\n", true},
		{"duplicate_keys", "{\n  \"include\": [\"src\"],\n  \"include\": [\"generated\"]\n}\n", true},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := os.WriteFile(path, []byte(test.source), 0o600); err != nil {
				t.Fatal(err)
			}
			actions, err := projectTypeIncludeActions(project)
			if err != nil {
				t.Fatal(err)
			}
			if test.wantAction && (len(actions) != 1 || !strings.Contains(actions[0], "../../.tnl/project.d.ts")) || !test.wantAction && len(actions) != 0 {
				t.Fatalf("actions = %v", actions)
			}
			after, err := os.ReadFile(path)
			if err != nil || string(after) != test.source {
				t.Fatalf("tsconfig changed: %s, %v", after, err)
			}
		})
	}
}

func TestProjectTypeIncludeActionUsesRootWithoutNamedServices(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "tsconfig.json")
	source := []byte("{\n  \"include\": [\"src/**/*.ts\"]\n}\n")
	if err := os.WriteFile(path, source, 0o600); err != nil {
		t.Fatal(err)
	}
	actions, err := projectTypeIncludeActions(projectConfiguration{Project: projectconfig.Project{Root: root}})
	if err != nil {
		t.Fatal(err)
	}
	if len(actions) != 1 || !strings.Contains(actions[0], `".tnl/project.d.ts"`) {
		t.Fatalf("actions = %v", actions)
	}
	data, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(data, source) {
		t.Fatalf("tsconfig changed: %s, %v", data, err)
	}
}

func TestInitGitignoreGroupsNewRuleAndPreservesExistingRules(t *testing.T) {
	for _, test := range []struct {
		name, before, want string
		updated            bool
	}{
		{"new", "", "# tnl\n.tnl/\n", true},
		{"existing", "node_modules/", "node_modules/\n# tnl\n.tnl/\n", true},
		{"already ignored", "node_modules/\n.tnl/\n", "node_modules/\n.tnl/\n", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			path := filepath.Join(root, ".gitignore")
			if test.name != "new" {
				if err := os.WriteFile(path, []byte(test.before), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			for run := 0; run < 2; run++ {
				updated, err := ensureTnlGitignore(root)
				if err != nil || updated != (run == 0 && test.updated) {
					t.Fatalf("run %d: updated = %t, err = %v", run, updated, err)
				}
				got, err := os.ReadFile(path)
				if err != nil || string(got) != test.want {
					t.Fatalf("run %d: gitignore = %q, err = %v", run, got, err)
				}
			}
		})
	}
}

func TestInitReportsTypeIncludeForExistingProjectConfig(t *testing.T) {
	root := copyInitFixture(t, "next")
	if err := os.WriteFile(filepath.Join(root, "tnl.yml"), []byte("version: 1\ntnl: {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "tsconfig.json")
	source := []byte("{\n  \"include\": [\"app/**/*.tsx\"]\n}\n")
	if err := os.WriteFile(path, source, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Chdir(root)
	var output bytes.Buffer
	if err := runInitWithInput(t.Context(), initCommand{NoInstall: true}, strings.NewReader(""), false, &output, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(got, source) || !strings.Contains(output.String(), `.tnl/project.d.ts`) || !strings.Contains(output.String(), "ignored") {
		t.Fatalf("tsconfig = %s, output = %s, err = %v", got, output.String(), err)
	}
}

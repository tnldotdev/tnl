package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tnldotdev/tnl/internal/config"
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
	nested := filepath.Join(root, "apps", "api")
	if err := os.MkdirAll(nested, 0o700); err != nil {
		t.Fatal(err)
	}
	nestedPath := filepath.Join(nested, "tsconfig.json")
	nestedSource := []byte(`{"include":["src"]}`)
	if err := os.WriteFile(nestedPath, nestedSource, 0o600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "tsconfig.json")
	project := projectConfiguration{Project: projectconfig.Project{Root: root, Config: config.TNL{Services: config.Services{"api": {}, "web": {}}}}}
	for _, test := range []struct {
		name, source string
		wantAction   bool
	}{
		{"missing_include", "{\n  \"include\": [\"src/**/*.ts\"]\n}\n", true},
		{"included", "{\n  \"include\": [\"src/**/*.ts\", \".tnl/local/project.d.ts\"]\n}\n", false},
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
			if test.wantAction && (len(actions) != 1 || !strings.Contains(actions[0], `".tnl/local/project.d.ts"`) || !strings.Contains(actions[0], path)) || !test.wantAction && len(actions) != 0 {
				t.Fatalf("actions = %v", actions)
			}
			after, err := os.ReadFile(path)
			if err != nil || string(after) != test.source {
				t.Fatalf("tsconfig changed: %s, %v", after, err)
			}
			if got, err := os.ReadFile(nestedPath); err != nil || !bytes.Equal(got, nestedSource) {
				t.Fatalf("nested tsconfig changed: %s, %v", got, err)
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
	if len(actions) != 1 || !strings.Contains(actions[0], `".tnl/local/project.d.ts"`) {
		t.Fatalf("actions = %v", actions)
	}
	data, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(data, source) {
		t.Fatalf("tsconfig changed: %s, %v", data, err)
	}
}

func TestProjectTypeIncludeActionDoesNotInferNestedServiceDirectory(t *testing.T) {
	root := t.TempDir()
	nested := filepath.Join(root, "apps", "web")
	if err := os.MkdirAll(nested, 0o700); err != nil {
		t.Fatal(err)
	}
	nestedPath := filepath.Join(nested, "tsconfig.json")
	source := []byte(`{"include":["src"]}`)
	if err := os.WriteFile(nestedPath, source, 0o600); err != nil {
		t.Fatal(err)
	}
	project := projectConfiguration{Project: projectconfig.Project{Root: root, Config: config.TNL{Services: config.Services{"web": {}}}}}
	actions, err := projectTypeIncludeActions(project)
	if err != nil {
		t.Fatal(err)
	}
	if len(actions) != 1 || !strings.Contains(actions[0], filepath.Join(root, "tsconfig.json")) || !strings.Contains(actions[0], `".tnl/local/project.d.ts"`) || strings.Contains(actions[0], nestedPath) {
		t.Fatalf("actions = %v", actions)
	}
	if got, err := os.ReadFile(nestedPath); err != nil || !bytes.Equal(got, source) {
		t.Fatalf("nested tsconfig changed: %s, %v", got, err)
	}
}

func TestInitGitignoreGroupsNewRuleAndPreservesExistingRules(t *testing.T) {
	for _, test := range []struct {
		name, before, want string
		updated            bool
	}{
		{"new", "", "# tnl\n/.tnl/local/\n", true},
		{"existing", "node_modules/", "node_modules/\n# tnl\n/.tnl/local/\n", true},
		{"already ignored", "node_modules/\n/.tnl/local/\n", "node_modules/\n/.tnl/local/\n", false},
		{"generated broad", "# tnl\n.tnl/\n", "# tnl\n/.tnl/local/\n", true},
		{"generated anchored", "# tnl\n/.tnl/\n", "# tnl\n/.tnl/local/\n", true},
		{"custom broad", "# custom\n.tnl/\n", "# custom\n.tnl/\n# tnl\n/.tnl/local/\n", true},
		{"custom block", "# tnl\n# custom\n.tnl/\n", "# tnl\n# custom\n.tnl/\n# tnl\n/.tnl/local/\n", true},
		{"crlf", "# keep\r\nnode_modules/\r\n# tnl\r\n.tnl/\r\n# end\r\n", "# keep\r\nnode_modules/\r\n# tnl\r\n/.tnl/local/\r\n# end\r\n", true},
		{"append crlf", "# keep\r\nnode_modules/", "# keep\r\nnode_modules/\r\n# tnl\r\n/.tnl/local/\r\n", true},
		{"no final newline", "# tnl\n.tnl/", "# tnl\n/.tnl/local/", true},
		{"mixed endings", "# keep\r\n# tnl\n.tnl/\r\n# end", "# keep\r\n# tnl\n/.tnl/local/\r\n# end", true},
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
	if err != nil || !bytes.Equal(got, source) || !strings.Contains(output.String(), `.tnl/local/project.d.ts`) || !strings.Contains(output.String(), "ignore") {
		t.Fatalf("tsconfig = %s, output = %s, err = %v", got, output.String(), err)
	}
}

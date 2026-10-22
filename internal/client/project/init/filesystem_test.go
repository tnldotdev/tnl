package projectinit

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInitFileCreationDoesNotOverwriteExistingFilesOrSymlinks(t *testing.T) {
	for _, symlink := range []bool{false, true} {
		t.Run(map[bool]string{false: "regular", true: "symlink"}[symlink], func(t *testing.T) {
			root := t.TempDir()
			path := filepath.Join(root, "tnl.config.ts")
			original := []byte("developer configuration\n")
			target := path
			if symlink {
				target = filepath.Join(t.TempDir(), "configuration")
				if err := os.Symlink(target, path); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.WriteFile(target, original, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := createInitFile(path, []byte("replacement")); !errors.Is(err, os.ErrExist) {
				t.Fatalf("create existing path = %v", err)
			}
			if data, err := os.ReadFile(target); err != nil || !bytes.Equal(data, original) {
				t.Fatalf("existing target changed: %s, %v", data, err)
			}
			entries, err := os.ReadDir(root)
			if err != nil || len(entries) != 1 || entries[0].Name() != filepath.Base(path) {
				t.Fatalf("temporary files leaked: %v, %v", entries, err)
			}
		})
	}
}

func TestInitFileReplacementRejectsSymlinksAndPreservesMode(t *testing.T) {
	root := t.TempDir()
	path, link := filepath.Join(root, "source"), filepath.Join(root, "symlink")
	before, after := []byte("original"), []byte("replacement")
	if err := os.WriteFile(path, before, 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if err := replaceRecognizedInitFile(link, before, after); err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Fatalf("replace symlink = %v", err)
	}
	if data, err := os.ReadFile(path); err != nil || !bytes.Equal(data, before) {
		t.Fatalf("symlink target changed: %s, %v", data, err)
	}
	if err := replaceRecognizedInitFile(path, before, after); err != nil {
		t.Fatal(err)
	}
	if info, err := os.Stat(path); err != nil || info.Mode().Perm() != 0o640 {
		t.Fatalf("replacement mode = %v, %v", info, err)
	}
	if data, err := os.ReadFile(path); err != nil || !bytes.Equal(data, after) {
		t.Fatalf("replacement = %s, %v", data, err)
	}
}

func TestInitFileReadsAreBounded(t *testing.T) {
	path := filepath.Join(t.TempDir(), "package.json")
	if err := os.WriteFile(path, bytes.Repeat([]byte(" "), initReadLimit+1), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readInitFile(path); err == nil || !strings.Contains(err.Error(), "file exceeds 1048576 bytes") {
		t.Fatalf("unbounded read = %v", err)
	}
}

func TestProjectTypeIncludesUseReferencedProjectDirectories(t *testing.T) {
	root := t.TempDir()
	nested := filepath.Join(root, "apps/web")
	if err := os.MkdirAll(nested, 0700); err != nil {
		t.Fatal(err)
	}
	rootSource := []byte("{\n// preserve references\n\"files\": [], \"references\": [{\"path\": \"apps/web\"}],\n}\n")
	nestedSource := []byte(`{"include":["src"]}`)
	if err := os.WriteFile(filepath.Join(root, "tsconfig.json"), rootSource, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(nested, "tsconfig.json"), nestedSource, 0600); err != nil {
		t.Fatal(err)
	}
	result, err := wireProjectTypeIncludes(root)
	if err != nil || len(result.actions) != 0 || len(result.updated) != 1 || result.updated[0] != filepath.Join(nested, "tsconfig.json") {
		t.Fatalf("referenced include = %v %v", result, err)
	}
	if after, err := os.ReadFile(filepath.Join(root, "tsconfig.json")); err != nil || !bytes.Equal(rootSource, after) {
		t.Fatal("solution references changed", err)
	}
	if after, err := os.ReadFile(filepath.Join(nested, "tsconfig.json")); err != nil || !bytes.Contains(after, []byte("../../.tnl/generated/project.d.ts")) || !bytes.Contains(after, []byte(`"src"`)) {
		t.Fatalf("referenced include = %s %v", after, err)
	}
}

func TestProjectTypeIncludesPreserveConfiguration(t *testing.T) {
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
	for _, test := range []struct {
		name, source string
		wantAction   bool
		wantUpdate   bool
	}{
		{"missing_include", "{\n  \"include\": [\"src/**/*.ts\"]\n}\n", false, true},
		{"included", "{\n  \"include\": [\"src/**/*.ts\", \".tnl/generated/project.d.ts\"]\n}\n", false, false},
		{"jsonc", "{\n  // preserve this JSONC file\n  \"include\": [\"src\"]\n}\n", false, true},
		{"jsonc_included", "{\n  // preserve comments and trailing commas\n  \"include\": [\"src\", \".tnl/generated/project.d.ts\",],\n}\n", false, false},
		{"duplicate_keys", "{\n  \"include\": [\"src\"],\n  \"include\": [\"generated\"]\n}\n", true, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := os.WriteFile(path, []byte(test.source), 0o600); err != nil {
				t.Fatal(err)
			}
			result, err := wireProjectTypeIncludes(root)
			if err != nil {
				t.Fatal(err)
			}
			if test.wantAction && (len(result.actions) != 1 || !strings.Contains(result.actions[0], `".tnl/generated/project.d.ts"`) || !strings.Contains(result.actions[0], path)) || !test.wantAction && len(result.actions) != 0 || (len(result.updated) != 0) != test.wantUpdate {
				t.Fatalf("include result = %v", result)
			}
			after, err := os.ReadFile(path)
			if err != nil || !test.wantUpdate && string(after) != test.source || test.wantUpdate && !bytes.Contains(after, []byte(".tnl/generated/project.d.ts")) {
				t.Fatalf("tsconfig changed: %s, %v", after, err)
			}
			if got, err := os.ReadFile(nestedPath); err != nil || !bytes.Equal(got, nestedSource) {
				t.Fatalf("nested tsconfig changed: %s, %v", got, err)
			}
		})
	}
}

func TestProjectTypeIncludeWiresRootWithoutNamedServices(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "tsconfig.json")
	source := []byte("{\n  \"include\": [\"src/**/*.ts\"]\n}\n")
	if err := os.WriteFile(path, source, 0o600); err != nil {
		t.Fatal(err)
	}
	result, err := wireProjectTypeIncludes(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.actions) != 0 || len(result.updated) != 1 || result.updated[0] != path {
		t.Fatalf("include result = %v", result)
	}
	data, err := os.ReadFile(path)
	if err != nil || !bytes.Contains(data, []byte(".tnl/generated/project.d.ts")) || !bytes.Contains(data, []byte("src/**/*.ts")) {
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
	result, err := wireProjectTypeIncludes(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.actions) != 1 || !strings.Contains(result.actions[0], filepath.Join(root, "tsconfig.json")) || !strings.Contains(result.actions[0], `".tnl/generated/project.d.ts"`) || strings.Contains(result.actions[0], nestedPath) {
		t.Fatalf("actions = %v", result.actions)
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

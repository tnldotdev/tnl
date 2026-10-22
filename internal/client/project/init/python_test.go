package init

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func TestInitPythonWithoutUvRecommendsProjectLocalDependency(t *testing.T) {
	root := t.TempDir()
	before := []byte("[project]\nname = 'example'\n")
	path := filepath.Join(root, "pyproject.toml")
	if err := os.WriteFile(path, before, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", t.TempDir())
	updated, actions, err := wirePythonProject(t.Context(), root, false)
	if err != nil || updated || !slices.Equal(actions, []string{"run in the Python project: uv add --editable ./.tnl/generated/python"}) {
		t.Fatalf("Python result = %t, %v, %v", updated, actions, err)
	}
	if data, err := os.ReadFile(path); err != nil || string(data) != string(before) {
		t.Fatalf("Python project changed: %s, %v", data, err)
	}
}

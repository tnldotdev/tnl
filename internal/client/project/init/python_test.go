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
	install, err := (Plan{Root: root}).PythonInstall(false)
	var report Report
	if err != nil {
		t.Fatal(err)
	}
	if err := report.install(t.Context(), root, "install_python", install, false); err != nil {
		t.Fatal(err)
	}
	if !install.Manual || install.Command != "uv add --editable ./.tnl/generated/python" || len(report.Steps) != 1 ||
		report.Steps[0].Status != "outstanding" || !slices.Equal(report.Steps[0].Argv, []string{"uv", "add", "--editable", "./.tnl/generated/python"}) {
		t.Fatalf("Python install = %+v, steps = %+v", install, report.Steps)
	}
	if data, err := os.ReadFile(path); err != nil || string(data) != string(before) {
		t.Fatalf("Python project changed: %s, %v", data, err)
	}
}

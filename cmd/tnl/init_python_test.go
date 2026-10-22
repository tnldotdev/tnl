package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInitPythonFacadeIsProjectLocalAndNoInstallPreservesProject(t *testing.T) {
	root := t.TempDir()
	initIgnoreRepository(t, root)
	project := filepath.Join(root, "apps", "api")
	writeInitIgnoreFixture(t, root, "package.json", `{"workspaces":["apps/*"]}`)
	pyproject := "[project]\nname = \"example-api\"\nversion = \"0.0.0\"\nrequires-python = \">=3.12\"\n"
	writeInitIgnoreFixture(t, project, "pyproject.toml", pyproject)
	writeInitIgnoreFixture(t, project, "tnl.yml", "version: 1\ntnl:\n  services:\n    database:\n      protocol: postgres\n      target: {type: address, address: 'database:5432'}\n")
	working := filepath.Join(project, "src")
	if err := os.Mkdir(working, 0755); err != nil {
		t.Fatal(err)
	}
	t.Chdir(working)
	for range 2 {
		var output bytes.Buffer
		if err := runInit(t.Context(), initCommand{NoInstall: true}, &output, &bytes.Buffer{}); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(output.String(), "uv add --editable") || !strings.Contains(output.String(), "./.tnl/generated/python") {
			t.Fatal("missing local Python import/type wiring action", output.String())
		}
		if data, err := os.ReadFile(filepath.Join(project, "pyproject.toml")); err != nil || string(data) != pyproject {
			t.Fatal("no-install edited the Python project", err)
		}
		if data, err := os.ReadFile(filepath.Join(project, ".tnl/generated/python/tnl_project/__init__.py")); err != nil || !bytes.Contains(data, []byte(`Literal["database"]`)) {
			t.Fatal("exact project facade missing", err)
		}
	}
	if _, err := os.Stat(filepath.Join(root, ".tnl")); !os.IsNotExist(err) {
		t.Fatal("Python initialization modified the enclosing workspace")
	}
}

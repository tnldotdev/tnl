package publisher_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// build and install the Python distribution with the real native executable.
// psycopg is an isolated test consumer, not a tnl or application dependency.
func runInstalledPsycopg(t *testing.T, root, binary, handle string) {
	t.Helper()
	stage := filepath.Join(root, "python-package")
	if err := os.MkdirAll(filepath.Join(stage, "src"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.CopyFS(filepath.Join(stage, "src", "tnl"), os.DirFS("../../packages/py/src/tnl")); err != nil {
		t.Fatal(err)
	}
	for name, source := range map[string]string{"pyproject.toml": "../../packages/py/pyproject.toml", "readme.md": "../../packages/py/readme.md", "src/tnl/bin/tnl": binary} {
		data, err := os.ReadFile(source)
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(stage, name)
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, data, 0700); err != nil {
			t.Fatal(err)
		}
	}
	wheels := filepath.Join(root, "wheels")
	build := exec.CommandContext(t.Context(), "uv", "build", "--python", "3.13.9", "--wheel", "--out-dir", wheels, stage)
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build installed Python driver fixture: %v\n%s", err, output)
	}
	files, err := os.ReadDir(wheels)
	if err != nil {
		t.Fatal(err)
	}
	var wheel string
	for _, file := range files {
		if strings.HasSuffix(file.Name(), ".whl") {
			if wheel != "" {
				t.Fatal("expected only one Python fixture wheel")
			}
			wheel = filepath.Join(wheels, file.Name())
		}
	}
	if wheel == "" {
		t.Fatal("expected one Python fixture wheel", err)
	}
	fixture, err := filepath.Abs("../../packages/py/fixtures/database_drivers.py")
	if err != nil {
		t.Fatal(err)
	}
	command := exec.CommandContext(t.Context(), "uv", "run", "--python", "3.13.9", "--isolated", "--no-project", "--with", wheel, "--with", "psycopg[binary]==3.2.10", "python", fixture)
	command.Dir = root
	for _, value := range os.Environ() {
		if !strings.HasPrefix(value, "TNL_") && !strings.HasPrefix(value, "PYTHONPATH=") {
			command.Env = append(command.Env, value)
		}
	}
	command.Env = append(command.Env, "TNL_CONNECTION_HANDLE="+handle)
	command.WaitDelay = time.Second
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("installed psycopg verification: %v\n%s", err, output)
	}
	t.Log(strings.TrimSpace(string(output)))
}

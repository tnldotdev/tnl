package meta

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/tnldotdev/tnl/internal/config"
)

func TestPythonFacadePortableSourceShapeAndStrictMypy(t *testing.T) {
	repository, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	python := filepath.Join(repository, "packages/py/.venv/bin/python")
	if _, err := os.Stat(python); err != nil {
		t.Skip("run uv sync --frozen --project packages/py for generated facade type checks")
	}
	for _, scenario := range []string{"static", "single", "empty", "factory"} {
		t.Run(scenario, func(t *testing.T) {
			root, err := filepath.EvalSymlinks(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			postgres, tcp, mysql, kubernetes := "postgres", "tcp", "mysql", "kubernetes"
			configuration := config.TNL{Services: config.Services{"database": {Protocol: &postgres}, "web": {}, "stream": {Protocol: &tcp}, "mysql": {Protocol: &mysql}, "cluster": {Protocol: &kubernetes}}}
			path := "tnl.yml"
			usage := `from typing import Literal, assert_type
import tnl as native
from tnl_project import tnl

handle = tnl.connect("database")
assert_type(handle, native.PostgresConnectionHandle)
assert_type(handle.protocol, Literal["postgres"])
assert_type(handle.server_hostname, str)
assert_type(handle.snapshot().protocol, Literal["postgres"])
assert_type(tnl.connect("web").url, str)
assert_type(tnl.connect("web").snapshot().url, str)
assert_type(tnl.connect("stream").snapshot().protocol, Literal["tcp"])
tnl.connect("stream").snapshot().ssl  # type: ignore[attr-defined]
tnl.connect("stream").ssl  # type: ignore[misc]
assert_type(tnl.connect("mysql").snapshot().protocol, Literal["mysql"])
assert_type(tnl.connect("cluster").context, str)
assert_type(tnl.connect("cluster").snapshot().protocol, Literal["kubernetes"])
tnl.connect("missing")  # type: ignore[call-overload]
handle.url  # type: ignore[attr-defined]
handle.snapshot().url  # type: ignore[attr-defined]

async def use() -> None:
    result = await handle
    assert_type(result, native.PostgresConnection)
    assert_type(result.protocol, Literal["postgres"])
    await result  # type: ignore[misc]
`
			if scenario == "single" {
				configuration.Services = config.Services{"database": {Protocol: &postgres}}
				usage = `from typing import assert_type
import tnl as native
from tnl_project import tnl
assert_type(tnl.connect("database").snapshot(), native.PostgresConnection)
tnl.connect("missing")  # type: ignore[arg-type]
`
			}
			if scenario == "empty" {
				configuration.Services = config.Services{}
				usage = "from tnl_project import tnl\ntnl.connect(\"missing\")  # type: ignore[arg-type]\n"
			}
			if scenario == "factory" {
				path = "tnl.config.ts"
				usage = `from typing import assert_type
import tnl as native
from tnl_project import tnl
assert_type(tnl.connect("only-in-another-worktree").snapshot(), native.Connection)
`
			}
			files, err := PythonFacade(configuration, path)
			if err != nil {
				t.Fatal(err)
			}
			if err := WritePythonFacade(root, files, true); !os.IsNotExist(err) {
				t.Fatal("read-only check accepted absent output", err)
			}
			if _, err := os.Stat(filepath.Join(root, "python")); !os.IsNotExist(err) {
				t.Fatal("check created output")
			}
			if err := WritePythonFacade(root, files, false); err != nil {
				t.Fatal(err)
			}
			if err := WritePythonFacade(root, files, true); err != nil {
				t.Fatal(err)
			}
			if scenario == "factory" {
				other, err := PythonFacade(config.TNL{}, path)
				if err != nil || !reflect.DeepEqual(files, other) {
					t.Fatal("factory typing depended on one evaluated checkout", err)
				}
			}
			if err := os.WriteFile(filepath.Join(root, "usage.py"), []byte(usage), 0600); err != nil {
				t.Fatal(err)
			}
			command := exec.CommandContext(t.Context(), python, "-m", "mypy", "--strict", "--no-incremental", "--config-file", filepath.Join(repository, "packages/py/pyproject.toml"), filepath.Join(root, "usage.py"), filepath.Join(root, "python/tnl_project"))
			command.Dir = repository
			command.Env = append(os.Environ(), "MYPYPATH="+filepath.Join(root, "python")+string(os.PathListSeparator)+filepath.Join(repository, "packages/py/src"))
			if output, err := command.CombinedOutput(); err != nil {
				t.Fatalf("generated facade typecheck: %v\n%s\n%s", err, output, files["tnl_project/__init__.py"])
			}
		})
	}
}

func TestPythonFacadeRejectsSymlinksAndPreservesUnownedFiles(t *testing.T) {
	for _, scenario := range []string{"ancestor", "module", "file", "unowned"} {
		t.Run(scenario, func(t *testing.T) {
			root, _ := filepath.EvalSymlinks(t.TempDir())
			outside := t.TempDir()
			files, err := PythonFacade(config.TNL{}, "tnl.yml")
			if err != nil {
				t.Fatal(err)
			}
			if scenario == "ancestor" {
				err = os.Symlink(outside, filepath.Join(root, "python"))
			} else {
				if err := os.Mkdir(filepath.Join(root, "python"), 0755); err != nil {
					t.Fatal(err)
				}
				if scenario == "module" {
					err = os.Symlink(outside, filepath.Join(root, "python/tnl_project"))
				} else {
					if err := os.Mkdir(filepath.Join(root, "python/tnl_project"), 0755); err != nil {
						t.Fatal(err)
					}
					if scenario == "file" {
						err = os.Symlink(filepath.Join(outside, "untouched"), filepath.Join(root, "python/tnl_project/__init__.py"))
					} else {
						err = os.WriteFile(filepath.Join(root, "python/tnl_project/__init__.py"), []byte("# user code\n"), 0600)
					}
				}
			}
			if err != nil {
				t.Fatal(err)
			}
			if err := WritePythonFacade(root, files, false); err == nil {
				t.Fatal("unsafe output was accepted")
			}
			if entries, err := os.ReadDir(outside); err != nil || len(entries) != 0 {
				t.Fatal("wrote outside output directory", err)
			}
		})
	}
}

func TestPythonFacadeContainsNamesAndProtocolsOnly(t *testing.T) {
	protocol := "postgres"
	address := config.Target("secret-target:5432")
	configuration := config.TNL{Services: config.Services{"database": {Protocol: &protocol, Target: &config.ServiceTarget{Type: "address", Address: &address}}}}
	files, err := PythonFacade(configuration, "/private/checkout/tnl.yml")
	if err != nil {
		t.Fatal(err)
	}
	for _, data := range files {
		for _, forbidden := range []string{"secret-target", "/private/checkout", "5432", "credential"} {
			if bytes.Contains(data, []byte(forbidden)) {
				t.Fatal("portable facade contains local values")
			}
		}
	}
	if !strings.Contains(string(files["tnl_project/__init__.py"]), `Literal["database"]`) {
		t.Fatal("static service literal missing")
	}
}

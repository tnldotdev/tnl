package meta

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestPythonServiceFactsRuntimeAndStrictMypy(t *testing.T) {
	repository, err := filepath.Abs("../../../..")
	if err != nil {
		t.Fatal(err)
	}
	python := filepath.Join(repository, "packages/py/.venv/bin/python")
	if _, err := os.Stat(python); err != nil {
		t.Skip("run uv sync --frozen --project packages/py for generated type checks")
	}
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	files := pythonServices(serviceFacts{"api": "http", "database": "postgres", "mysql": "mysql", "raw": "tcp", "cluster": "kubernetes"})
	if err := writeArtifacts(root, files, false); err != nil {
		t.Fatal(err)
	}
	usage := `from typing import assert_type, TYPE_CHECKING
from datetime import UTC, datetime, timedelta
import tnl
from tnl import HTTPConnection, PostgresConnection, MySQLConnection, TCPConnection, KubernetesConnection
from tnl_project import services

assert services["database"]["protocol"] == "postgres"
assert services["api"]["protocol"] == "http"
assert list(services) == ["api", "cluster", "database", "mysql", "raw"]

async def assertion() -> tnl.OIDCAssertion:
    return tnl.OIDCAssertion("test.assertion", datetime.now(UTC) + timedelta(minutes=1))

if TYPE_CHECKING:
    async def check() -> None:
        async with tnl.client(services=services,
            environment=tnl.EnvironmentReference("https://control.example", "project", "env_" + "a" * 22),
            identity=tnl.IdentitySource("oidc", "mci_" + "a" * 22, assertion, permission_id="mwp_" + "a" * 22)) as client:
            assert_type(await client.connect("api"), HTTPConnection)
            assert_type(await client.connect("database"), PostgresConnection)
            assert_type(await client.connect("mysql"), MySQLConnection)
            assert_type(await client.connect("raw"), TCPConnection)
            assert_type(await client.connect("cluster"), KubernetesConnection)
            await client.connect("missing")  # type: ignore[call-overload]
            (await client.connect("database")).url  # type: ignore[attr-defined]
`
	if err := os.WriteFile(filepath.Join(root, "usage.py"), []byte(usage), 0600); err != nil {
		t.Fatal(err)
	}
	paths := filepath.Join(root, "python") + string(os.PathListSeparator) + filepath.Join(repository, "packages/py/src")
	for _, arguments := range [][]string{
		{"-m", "mypy", "--strict", "--no-incremental", "--config-file", filepath.Join(repository, "packages/py/pyproject.toml"), filepath.Join(root, "usage.py"), filepath.Join(root, "python/tnl_project")},
		{filepath.Join(root, "usage.py")},
		{"-m", "ruff", "format", "--check", "--diff", filepath.Join(root, "python/tnl_project/__init__.py")},
	} {
		command := exec.CommandContext(t.Context(), python, arguments...)
		command.Dir = repository
		command.Env = append(os.Environ(), "MYPYPATH="+paths, "PYTHONPATH="+paths)
		if output, err := command.CombinedOutput(); err != nil {
			t.Fatalf("generated Python facts check failed: %v\n%s", err, output)
		}
	}
	if strings.Contains(string(files["python/tnl_project/__init__.py"]), "tnl =") {
		t.Fatal("generated a second SDK object")
	}
}

func TestPythonServiceFactsRejectSymlinks(t *testing.T) {
	for _, scenario := range []string{"ancestor", "module", "file"} {
		t.Run(scenario, func(t *testing.T) {
			root, _ := filepath.EvalSymlinks(t.TempDir())
			outside := t.TempDir()
			files := pythonServices(serviceFacts{})
			if scenario == "ancestor" {
				if err := os.Symlink(outside, filepath.Join(root, "python")); err != nil {
					t.Fatal(err)
				}
			} else {
				if err := os.Mkdir(filepath.Join(root, "python"), 0755); err != nil {
					t.Fatal(err)
				}
				if scenario == "module" {
					if err := os.Symlink(outside, filepath.Join(root, "python/tnl_project")); err != nil {
						t.Fatal(err)
					}
				} else {
					if err := os.Mkdir(filepath.Join(root, "python/tnl_project"), 0755); err != nil {
						t.Fatal(err)
					}
					if err := os.Symlink(filepath.Join(outside, "untouched"), filepath.Join(root, "python/tnl_project/__init__.py")); err != nil {
						t.Fatal(err)
					}
				}
			}
			if err := writeArtifacts(root, files, false); err == nil {
				t.Fatal("unsafe output accepted")
			}
			if entries, err := os.ReadDir(outside); err != nil || len(entries) != 0 {
				t.Fatal("wrote outside output directory")
			}
		})
	}
}

func TestPythonServiceFactsTypingEdgeCases(t *testing.T) {
	repository, err := filepath.Abs("../../../..")
	if err != nil { t.Fatal(err) }
	python := filepath.Join(repository, "packages/py/.venv/bin/python")
	if _, err := os.Stat(python); err != nil { t.Skip("run the locked Python SDK sync for generated type checks") }
	for name, facts := range map[string]serviceFacts{"empty": {}, "single": {"db":"postgres"}, "long name": {strings.Repeat("a",63):"postgres"}} {
		t.Run(name,func(t *testing.T){
			root, err := filepath.EvalSymlinks(t.TempDir()); if err != nil {t.Fatal(err)}
			if err := writeArtifacts(root,pythonServices(facts),false); err != nil {t.Fatal(err)}
			paths := filepath.Join(root,"python") + string(os.PathListSeparator) + filepath.Join(repository,"packages/py/src")
			for _, args := range [][]string{
				{"-m","mypy","--strict","--no-incremental","--config-file",filepath.Join(repository,"packages/py/pyproject.toml"),filepath.Join(root,"python/tnl_project")},
				{"-m","ruff","format","--check","--diff",filepath.Join(root,"python/tnl_project/__init__.py")},
			} {
				command:=exec.CommandContext(t.Context(),python,args...);command.Dir=repository;command.Env=append(os.Environ(),"MYPYPATH="+paths,"PYTHONPATH="+paths)
				if output,err:=command.CombinedOutput();err!=nil{t.Fatalf("generated edge case failed: %v\n%s",err,output)}
			}
		})
	}
}

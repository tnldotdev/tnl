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
	repository, err := filepath.Abs("../../../..")
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
			configuration := config.Project{Services: map[string]config.ServiceDeclaration{"database": {Protocol: &postgres}, "web": {}, "stream": {Protocol: &tcp}, "mysql": {Protocol: &mysql}, "cluster": {Protocol: &kubernetes}}}
			path := "tnl.yml"
			usage := `from typing import Literal, assert_type
import tnl as native
from tnl_project import create_client, deployment, services

assert services["database"]["protocol"] == "postgres"
client = create_client(project="team/project")
assert_type(client, native.Client)
production = deployment(client, "production")

async def use() -> None:
    result = await production.connect("database")
    assert_type(result, native.PostgresConnection | native.LocalPostgresConnection)
    assert_type((await production.connect("web")).url, str)
    assert_type((await production.connect("stream")).protocol, Literal["tcp"])
    (await production.connect("stream")).ssl  # type: ignore[union-attr]
    assert_type((await production.connect("mysql")).protocol, Literal["mysql"])
    assert_type((await production.connect("cluster")).context, str)
    await production.connect("missing")  # type: ignore[call-overload]
    result.url  # type: ignore[union-attr]
    await result  # type: ignore[misc]
    await production.aclose()
`
			if scenario == "single" {
				configuration.Services = map[string]config.ServiceDeclaration{"database": {Protocol: &postgres}}
				usage = `from typing import assert_type
import tnl as native
from tnl_project import create_client, deployment, services
assert services["database"]["protocol"] == "postgres"
assert_type(create_client(project="team/project"), native.Client)
production = deployment(create_client(project="team/project"), "production")
async def use() -> None:
    assert_type(await production.connect("database"), native.PostgresConnection | native.LocalPostgresConnection)
    await production.connect("missing")  # type: ignore[arg-type]
`
			}
			if scenario == "empty" {
				configuration.Services = map[string]config.ServiceDeclaration{}
				usage = "from tnl_project import create_client, deployment, services\nassert not services\nproduction = deployment(create_client(project=\"team/project\"), \"production\")\nasync def use() -> None:\n    await production.connect(\"missing\")  # type: ignore[arg-type]\n"
			}
			if scenario == "factory" {
				path = "tnl.config.ts"
				usage = `from typing import assert_type
import tnl as native
from tnl_project import create_client, deployment
assert_type(create_client(project="team/project", services={"database": {"protocol": "postgres"}}), native.Client)
create_client(project="team/project")  # type: ignore[call-arg]
async def use() -> None:
    selected = deployment(create_client(project="team/project", services={"database": {"protocol": "postgres"}}), "production")
    assert_type(await selected.connect("only-in-another-worktree"), native.Connection | native.LocalConnection)
`
			}
			if scenario == "static" || scenario == "single" {
				usage += `
class DatabaseClient:
    def query(self) -> int:
        return 42

def create_database(connection: native.Connection | native.LocalPostgresConnection) -> DatabaseClient:
    assert_type(connection.port, int)
    return DatabaseClient()

async def create_async_database(connection: native.Connection | native.LocalPostgresConnection) -> DatabaseClient:
    return create_database(connection)

async def close_database(client: DatabaseClient) -> None:
    assert_type(client.query(), int)

get_database = deployment(create_client(project="team/project"), "production").client("database", create=create_database, close=close_database)
assert_type(get_database, native.ClientFactory[DatabaseClient])
get_async_database = deployment(create_client(project="team/project"), "production").client("database", create=create_async_database, close=close_database)
assert_type(get_async_database, native.ClientFactory[DatabaseClient])

async def use_clients() -> None:
    assert_type(await get_database(), DatabaseClient)
    assert_type(await get_async_database(), DatabaseClient)
    await get_database.aclose()
`
			}
			files, err := PythonFacade(configuration, path)
			if err != nil {
				t.Fatal(err)
			}
			if err := writeArtifacts(root, files, true); !os.IsNotExist(err) {
				t.Fatal("read-only check accepted absent output", err)
			}
			if _, err := os.Stat(filepath.Join(root, "python")); !os.IsNotExist(err) {
				t.Fatal("check created output")
			}
			if err := writeArtifacts(root, files, false); err != nil {
				t.Fatal(err)
			}
			if err := writeArtifacts(root, files, true); err != nil {
				t.Fatal(err)
			}
			if scenario == "factory" {
				other, err := PythonFacade(config.Project{}, path)
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
				t.Fatalf("generated facade typecheck: %v\n%s\n%s", err, output, files["python/tnl_project/__init__.py"])
			}
		})
	}
}

func TestPythonFacadeRejectsSymlinks(t *testing.T) {
	for _, scenario := range []string{"ancestor", "module", "file"} {
		t.Run(scenario, func(t *testing.T) {
			root, _ := filepath.EvalSymlinks(t.TempDir())
			outside := t.TempDir()
			files, err := PythonFacade(config.Project{}, "tnl.yml")
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
					err = os.Symlink(filepath.Join(outside, "untouched"), filepath.Join(root, "python/tnl_project/__init__.py"))
				}
			}
			if err != nil {
				t.Fatal(err)
			}
			if err := writeArtifacts(root, files, false); err == nil {
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
	configuration := config.Project{Services: map[string]config.ServiceDeclaration{"database": {Protocol: &protocol}}, Deployments: map[string]config.Deployment{"production": {Targets: map[string]config.DeploymentBinding{"database": {ServiceTarget: config.ServiceTarget{Address: &address}}}}}}
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
	if !strings.Contains(string(files["python/tnl_project/__init__.py"]), `"database": {"protocol": "postgres"}`) {
		t.Fatal("static service facts missing")
	}
}

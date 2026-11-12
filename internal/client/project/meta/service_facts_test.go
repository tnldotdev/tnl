package meta

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	clientproject "github.com/tnldotdev/tnl/internal/client/project"
	"github.com/tnldotdev/tnl/internal/config"
)

func TestServiceSnapshotNormalizedBoundedAndDetached(t *testing.T) {
	configuration := config.TNL{Services: config.Services{"api": {}}}
	for _, protocol := range []string{"tcp", "postgres", "mysql", "kubernetes"} {
		configuration.Services[protocol] = config.Service{Protocol: &protocol}
	}
	facts, err := snapshotServices(configuration)
	if err != nil || len(facts) != 5 || facts["api"] != "http" {
		t.Fatal("normalized service snapshot missing", facts, err)
	}
	configuration.Services["api"] = config.Service{Protocol: new("tcp")}
	if facts["api"] != "http" {
		t.Fatal("configuration mutation changed captured snapshot")
	}
	for count := range 130 {
		configuration.Services = config.Services{}
		for index := range count {
			configuration.Services[fmt.Sprintf("service-%d", index)] = config.Service{}
		}
		_, err := snapshotServices(configuration)
		if (err != nil) != (count > 128) {
			t.Fatal("incorrect snapshot service bound", count, err)
		}
	}
	for _, services := range []config.Services{{"bad/name": {}}, {"api": {Protocol: new("unknown")}}} {
		if _, err := snapshotServices(config.TNL{Services: services}); err == nil {
			t.Fatal("invalid generated facts accepted")
		}
	}
}

func TestServiceArtifactsShareFactsWithoutSelectionOrTargets(t *testing.T) {
	facts := serviceFacts{"database": "postgres", "api": "http"}
	typescript := string(typescriptServices(facts))
	python := string(pythonServices(facts)["python/tnl_project/__init__.py"])
	for _, name := range facts.names() {
		for _, output := range []string{typescript, python} {
			if !strings.Contains(output, name) || !strings.Contains(output, typeScriptString(facts[name])) {
				t.Fatal("language outputs disagree with normalized facts", name, output)
			}
		}
	}
	for _, forbidden := range []string{"publisherGroup", "targetBinding", "environment", "identity", "target", "credential", "typeof import", "declare module", "createProject", "export const tnl", "tnl ="} {
		if strings.Contains(typescript, forbidden) || strings.Contains(python, forbidden) {
			t.Fatal("generated service data contains behavior or selection", forbidden)
		}
	}
	if !strings.Contains(typescript, "export const services = Object.freeze({") || strings.Index(typescript, "  api:") > strings.Index(typescript, "  database:") {
		t.Fatal("typescript facts are not deterministic immutable data", typescript)
	}
	if !reflect.DeepEqual(typescriptServices(facts), typescriptServices(serviceFacts{"api": "http", "database": "postgres"})) {
		t.Fatal("map iteration changed generated output")
	}
}

func TestGenerateCapturesActualEvaluatedFactoryAndLiteralTypes(t *testing.T) {
	repository, err := filepath.Abs("../../../..")
	if err != nil {
		t.Fatal(err)
	}
	compiler := filepath.Join(repository, "node_modules/typescript/bin/tsc")
	if _, err := os.Stat(compiler); err != nil {
		t.Skip("install repository JavaScript dependencies for generated type checks")
	}
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "tnl.config.ts")
	source := `export default ({worktree}) => ({
  services: {
    api: {},
    db: {protocol: worktree.label.project ? "postgres" : "mysql", target: {type: "address", address: "private.internal:5432"}},
  },
});`
	if err := os.WriteFile(path, []byte(source), 0600); err != nil {
		t.Fatal(err)
	}
	project, err := clientproject.Resolve(t.Context(), clientproject.Selection{Path: path}, root, [32]byte{})
	if err != nil {
		t.Fatal("real factory evaluation failed", err)
	}
	if config.Protocol(project.Config.Services["db"]) != "postgres" {
		t.Fatal("factory did not choose the expected concrete branch")
	}
	if err := Generate(t.Context(), project, GeneratedDirectoryName, false); err != nil {
		t.Fatal(err)
	}
	if err := Generate(t.Context(), project, GeneratedDirectoryName, true); err != nil {
		t.Fatal("fresh generated output failed check", err)
	}
	data, err := os.ReadFile(filepath.Join(root, GeneratedDirectoryName, ProjectName))
	if err != nil || strings.Contains(string(data), "mysql") || strings.Contains(string(data), "private.internal") {
		t.Fatal("generated output used unevaluated branches or targets", string(data), err)
	}
	usage := `import {services} from "./.tnl/generated/project.js";
services.db.protocol satisfies "postgres";
services.api.protocol satisfies "http";
// @ts-expect-error this build did not choose mysql.
services.db.protocol satisfies "mysql";
// @ts-expect-error no invented service names.
services.missing;
// @ts-expect-error literal facts are read-only.
services.db.protocol = "postgres";
`
	options := map[string]any{"compilerOptions": map[string]any{"strict": true, "noEmit": true, "target": "ESNext", "module": "NodeNext", "moduleResolution": "NodeNext", "types": []string{}}, "files": []string{"usage.ts", ".tnl/generated/project.ts"}}
	encoded, _ := json.Marshal(options)
	for name, data := range map[string][]byte{"usage.ts": []byte(usage), "tsconfig.json": encoded, "package.json": []byte(`{"type":"module"}`)} {
		if err := os.WriteFile(filepath.Join(root, name), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	command := exec.CommandContext(t.Context(), "node", compiler, "--project", filepath.Join(root, "tsconfig.json"))
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("generated literal types failed: %v\n%s", err, output)
	}
	format := exec.CommandContext(t.Context(), "pnpm", "exec", "oxfmt", "--check", filepath.Join(root, GeneratedDirectoryName, ProjectName))
	format.Dir = repository
	if output, err := format.CombinedOutput(); err != nil {
		t.Fatalf("generated facts are not formatter-stable: %v\n%s", err, output)
	}
	project.Config.Services["db"] = config.Service{Protocol: new("mysql")}
	if Generate(t.Context(), project, GeneratedDirectoryName, true) == nil {
		t.Fatal("changed concrete build snapshot passed stale-artifact check")
	}
}

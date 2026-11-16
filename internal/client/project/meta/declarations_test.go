package meta

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tnldotdev/tnl/internal/config"
)

func TestGeneratedDeclarationsTypecheckSourceUnionsAndStaticShape(t *testing.T) {
	repository, err := filepath.Abs("../../../..")
	if err != nil {
		t.Fatal(err)
	}
	compiler := filepath.Join(repository, "node_modules", "typescript", "bin", "tsc")
	if _, err := os.Stat(compiler); os.IsNotExist(err) {
		t.Skip("install repository JavaScript dependencies to check generated declarations")
	}
	if _, err := exec.LookPath("node"); err != nil {
		t.Skip("Node.js is required to check generated declarations")
	}
	management := t.TempDir()
	if err := os.Symlink(filepath.Join(repository, "node_modules"), filepath.Join(management, "node_modules")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(management, "package.json"), []byte(`{"type":"module"}`), 0600); err != nil {
		t.Fatal(err)
	}
	managementProject := filepath.Join(management, "tsconfig.json")
	managementOptions := map[string]any{
		"extends": filepath.Join(repository, "packages/ts/tsconfig.management.json"),
		"compilerOptions": map[string]string{
			"outDir":          filepath.Join(management, "dist"),
			"tsBuildInfoFile": filepath.Join(management, "management.tsbuildinfo"),
		},
	}
	managementData, err := json.Marshal(managementOptions)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(managementProject, managementData, 0600); err != nil {
		t.Fatal(err)
	}
	build := exec.CommandContext(t.Context(), "node", compiler, "--build", managementProject)
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build management dependency: %s\n%v", output, err)
	}
	for _, format := range []string{"typescript", "yaml", "dynamic"} {
		t.Run(format, func(t *testing.T) {
			root := t.TempDir()
			directory := filepath.Join(root, GeneratedDirectoryName)
			if err := os.MkdirAll(directory, 0700); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(root, "tnl.config.ts")
			configuration := config.Project{}
			source := `import { defineConfig } from "@tnldotdev/tnl/config";
export default defineConfig(({worktree}) => ({
  services: {
    web: {},
    api: {},
    db: worktree.label.id ? {protocol: "postgres"} : {protocol: "mysql"},
    ...(worktree.label.id ? {worker: {protocol: "tcp" as const}} : {}),
  },
  deployments: {
    local: {targets: {web: {publicURL: {}, http: {paths: {"/api": "api"}}}, api: {}}},
    production: {targets: {db: {address: "db:5432"}}},
  },
  aliases: { review: { service: "web" } },
  webhooks: { stripe: { service: "web", path: "/hooks/stripe", provider: "stripe", methods: ["POST"] } },
  workloads: { deploy: { deployment: "production", github: { workflow: ".github/workflows/deploy.yml", branch: "main", events: ["push"] }, services: ["db"] } },
}));`
			usage := `import { createClient, tnl } from "@tnldotdev/tnl";
tnl.services.db.protocol satisfies "postgres" | "mysql";
tnl.services.web.paths["/api"].service satisfies "api";
tnl.aliases!.review.service satisfies "web";
tnl.webhooks!.stripe.path satisfies "/hooks/stripe";
tnl.webhooks!.stripe.methods satisfies readonly ["POST"];
tnl.services.db.port satisfies number;
// @ts-expect-error endpoints are runtime values, not literals from this checkout.
tnl.services.db.port satisfies 5432;
// @ts-expect-error unknown configured service.
createClient({project: "team/project", services: {db: {protocol: "postgres"}}}).deployment("production").connect("missing");
const connection = await createClient({project: "team/project", services: {db: {protocol: "postgres"}}}).deployment("production").connect("db");
connection.ssl.servername satisfies string;
connection.ssl.rejectUnauthorized satisfies true;
connection.ssl.ca satisfies string | undefined;
// @ts-expect-error connector admission never exports an application client key.
connection.ssl.key;
// @ts-expect-error connector admission never exports an application client certificate.
connection.ssl.cert;
// @ts-expect-error optional factory services remain optional.
tnl.services.worker.protocol;
`
			if format == "yaml" {
				path = filepath.Join(root, "tnl.yml")
				protocol := "postgres"
				address := config.Target("db.internal:5432")
				configuration.Services = map[string]config.ServiceDeclaration{"db": {Protocol: &protocol}, "api": {}, "web": {}}
				configuration.Deployments = map[string]config.Deployment{"local": {Targets: map[string]config.DeploymentBinding{
					"db": {ServiceTarget: config.ServiceTarget{Address: &address}}, "api": {}, "web": {Tunnel: &config.Tunnel{}, HTTP: &config.HTTPService{Paths: map[string]config.PathMount{"/api": {Service: "api"}}}},
				}}}
				if err := config.ValidateProject(configuration); err != nil {
					t.Fatal(err)
				}
				usage = `import { tnl } from "@tnldotdev/tnl";
tnl.services.db.protocol satisfies "postgres";
tnl.services.web.paths["/api"].service satisfies "api";
// @ts-expect-error no HTTP URL on database metadata.
tnl.services.db.url;
// @ts-expect-error no unknown service.
tnl.services.unknown;
`
			}
			if format == "dynamic" {
				source = `export default {services: {} as Record<string, {protocol: "http"}>};`
				usage = ""
			}
			declarations, err := Declarations(configuration, path, directory)
			if err != nil {
				t.Fatal(err)
			}
			options := map[string]any{"compilerOptions": map[string]any{"strict": true, "exactOptionalPropertyTypes": true, "skipLibCheck": false, "noEmit": true, "target": "ESNext", "module": "NodeNext", "moduleResolution": "NodeNext", "types": []string{"node"}, "typeRoots": []string{filepath.Join(repository, "node_modules/@types")}, "paths": map[string][]string{"@tnldotdev/tnl": {filepath.Join(repository, "packages/ts/src/index.ts")}, "@tnldotdev/tnl/config": {filepath.Join(repository, "packages/ts/src/config.ts")}}}, "references": []map[string]string{{"path": managementProject}}, "files": []string{"usage.ts", ".tnl/generated/project.d.ts"}}
			data, _ := json.Marshal(options)
			for name, content := range map[string][]byte{"tsconfig.json": data, "package.json": []byte(`{"type":"module"}`), "tnl.config.ts": []byte(source), "usage.ts": []byte(usage), ".tnl/generated/project.d.ts": declarations} {
				if err := os.WriteFile(filepath.Join(root, name), content, 0600); err != nil {
					t.Fatal(err)
				}
			}
			command := exec.CommandContext(t.Context(), "node", compiler, "--project", filepath.Join(root, "tsconfig.json"))
			output, err := command.CombinedOutput()
			if format == "dynamic" {
				if err == nil || !strings.Contains(string(output), "declare stable service names") {
					t.Fatalf("dynamic service diagnostic missing: %s %v", output, err)
				}
			} else if err != nil {
				t.Fatalf("generated declarations failed: %s\n%s", output, declarations)
			}
		})
	}
}

package project

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/tnldotdev/tnl/internal/config"
)

func TestTypeScriptEnvironmentsKeepDeclaredAndLocalTargetsSeparate(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "tnl.config.ts")
	source := `export default ({ worktree }) => ({
  server: "https://control.example",
  services: { web: {}, database: { protocol: "postgres" } },
  environments: {
    local: { server: "https://local-control.example", targets: {
      web: { publicURL: {}, name: "web-" + worktree.label.id, http: { readiness: { path: "/health" } } },
      database: { address: "127.0.0.1:5432" },
    } },
    staging: { server: "https://staging-control.example", targets: {
      web: { address: "http://web.staging.internal:3000" },
      database: { address: "db.staging.internal:5432", tls: { hostname: "database.internal", caFile: "certs/ca.pem" } },
    }, workloads: { accounts: { vercel: { project: "tnl-accounts-staging", environment: "production" }, visit: ["database"], maxDuration: "1h" } } },
  },
  collections: { customers: {} },
})`
	if err := os.WriteFile(path, []byte(source), 0600); err != nil {
		t.Fatal(err)
	}
	project, err := Resolve(t.Context(), Selection{Path: path}, root, [32]byte{})
	if err != nil {
		t.Fatal(err)
	}
	if project.Declared == nil || project.Declared.Services["database"].Target != nil || *project.Declared.Server != "https://control.example" {
		t.Fatal("local evaluation changed reusable declarations")
	}
	if string(*project.Config.Services["database"].Target.Address) != "127.0.0.1:5432" || config.TargetType(project.Config.Services["web"]) != "app" || project.Config.Services["web"].HTTP.Readiness.Path != "/health" || *project.Config.Server != "https://local-control.example" {
		t.Fatal("local worktree did not retain its listener, preview, or server settings")
	}
	staging := project.Declared.Environments["staging"]
	if string(*staging.Targets["database"].Address) != "db.staging.internal:5432" || *staging.Targets["database"].TLS.CAFile != "certs/ca.pem" || *staging.Targets["database"].TLS.Hostname != "database.internal" || staging.Workloads["accounts"].Services[0] != "database" || staging.Workloads["accounts"].DurationLimit().Hours() != 1 {
		t.Fatal("TypeScript environment fields were not normalized")
	}
}

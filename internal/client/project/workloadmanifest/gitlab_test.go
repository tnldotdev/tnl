package workloadmanifest

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	clientproject "github.com/tnldotdev/tnl/internal/client/project"
	"github.com/tnldotdev/tnl/internal/config"
)

func TestGitLabManifestDefaultsAndSelection(t *testing.T) {
	c := config.Project{Server: new("https://control.example.test"), Team: new("team"), Services: map[string]config.ServiceDeclaration{"api": {}}, Workloads: map[string]config.DeploymentWorkload{"deploy": {Deployment: "production", Workload: config.Workload{GitLab: &config.WorkloadGitLab{Project: "shop/storefront"}, Services: []string{"api"}}}}}
	data, err := Generate(c, clientproject.SourceIdentity{Key: "project", Fingerprint: strings.Repeat("a", 64), Label: "app"})
	if err != nil {
		t.Fatal(err)
	}
	var manifest Manifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		t.Fatal(err)
	}
	w := manifest.Workloads["deploy"]
	if w.Provider != "gitlab" || w.Acquisition.Method != "token-env" || w.Acquisition.TokenEnv != config.GitLabTokenEnv || w.Acquisition.Audience != *c.Server || w.MaxDurationSeconds != 0 || strings.Contains(string(data), "shop/storefront") {
		t.Fatal("manifest retained setup metadata or changed defaults")
	}
	directory, _, write := selectionFixture(t)
	write(manifest)
	if selected, err := Select(directory, "", "api", Runtime{GitLabCI: "true"}); err != nil || selected.Name != "deploy" {
		t.Fatal("GitLab job did not select native token acquisition", err)
	}
	if _, err := Select(directory, "", "api", Runtime{GitLabCI: "true", GitHubActions: "true"}); !errors.Is(err, ErrRequired) {
		t.Fatal("ambiguous runtime accepted", err)
	}
	for _, token := range []*config.WorkloadToken{{File: new("/run/job/token")}, {Env: new("ANOTHER_ID_TOKEN")}} {
		p := c.Workloads["deploy"]
		p.GitLab.Audience = "tnl-orders"
		p.Token = token
		c.Workloads["deploy"] = p
		data, err := Generate(c, clientproject.SourceIdentity{Key: "project", Fingerprint: strings.Repeat("a", 64), Label: "app"})
		if err != nil || json.Unmarshal(data, &manifest) != nil {
			t.Fatal("common token override rejected", err)
		}
		a := manifest.Workloads["deploy"].Acquisition
		if a.Audience != "tnl-orders" || token.File != nil && a.TokenFile != *token.File || token.Env != nil && a.TokenEnv != *token.Env {
			t.Fatal("GitLab default replaced explicit token source")
		}
	}
}

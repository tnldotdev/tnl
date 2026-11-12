package workloadmanifest

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/tnldotdev/tnl/internal/config"
)

func TestGitLabManifestDefaultsAndSelection(t *testing.T) {
	server := "https://control.example.test"
	p := config.Workload{GitLab: &config.WorkloadGitLab{Project: "shop/storefront"}, Services: []string{"api"}}
	a, err := AcquisitionFor(p, server)
	if err != nil {
		t.Fatal(err)
	}
	directory, manifest, write := selectionFixture(t)
	manifest.Workloads = map[string]Workload{"deploy": {Provider: p.Provider(), Services: p.Services, Acquisition: a}}
	data, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	w := manifest.Workloads["deploy"]
	if w.Provider != "gitlab" || w.Acquisition.Method != "token-env" || w.Acquisition.TokenEnv != config.GitLabTokenEnv || w.Acquisition.Audience != server || w.MaxDurationSeconds != 0 || strings.Contains(string(data), "shop/storefront") {
		t.Fatal("manifest retained setup metadata or changed defaults")
	}
	write(manifest)
	if selected, err := Select(directory, "", "api", Runtime{GitLabCI: "true"}); err != nil || selected.Name != "deploy" {
		t.Fatal("GitLab job did not select native token acquisition", err)
	}
	if _, err := Select(directory, "", "api", Runtime{GitLabCI: "true", GitHubActions: "true"}); !errors.Is(err, ErrRequired) {
		t.Fatal("ambiguous runtime accepted", err)
	}
	for _, token := range []*config.WorkloadToken{{File: new("/run/job/token")}, {Env: new("ANOTHER_ID_TOKEN")}} {
		p.GitLab.Audience = "tnl-orders"
		p.Token = token
		a, err := AcquisitionFor(p, server)
		if err != nil {
			t.Fatal("common token override rejected", err)
		}
		if a.Audience != "tnl-orders" || token.File != nil && a.TokenFile != *token.File || token.Env != nil && a.TokenEnv != *token.Env {
			t.Fatal("GitLab default replaced explicit token source")
		}
	}
}

package workloadmanifest

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	clientproject "github.com/tnldotdev/tnl/internal/client/project"
	"github.com/tnldotdev/tnl/internal/config"
)

func TestKubernetesProjectedTokenManifestAndSelection(t *testing.T) {
	c := config.Project{Server: new("https://control.example.test"), Team: new("team"), Services: map[string]config.ServiceDeclaration{"api": {}}, Workloads: map[string]config.DeploymentWorkload{"app": {Deployment: "production", Workload: config.Workload{Kubernetes: &config.WorkloadKubernetes{ServiceAccount: "orders"}, Services: []string{"api"}}}}}
	source := clientproject.SourceIdentity{Key: "project", Fingerprint: strings.Repeat("a", 64), Label: "app"}
	data, err := Generate(c, source)
	if err != nil {
		t.Fatal(err)
	}
	var manifest Manifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		t.Fatal(err)
	}
	w := manifest.Workloads["app"]
	if w.Provider != "kubernetes" || w.Acquisition.Method != "token-file" || w.Acquisition.TokenFile != KubernetesTokenFile || w.Acquisition.Audience != *c.Server || w.MaxDurationSeconds != 0 || strings.Contains(string(data), "kubeconfig") {
		t.Fatal("projected token defaults changed")
	}
	directory, _, write := selectionFixture(t)
	write(manifest)
	if selected, err := Select(directory, "", "api", Runtime{KubernetesServiceHost: "10.0.0.1"}); err != nil || selected.Name != "app" {
		t.Fatal("Pod environment did not select the workload", err)
	}
	if _, err := Select(directory, "", "api", Runtime{KubernetesServiceHost: "10.0.0.1", CloudRunService: "other"}); !errors.Is(err, ErrRequired) {
		t.Fatal("ambiguous runtime hints accepted", err)
	}
	for _, token := range []*config.WorkloadToken{{File: new("/another/mounted/token")}, {Env: new("POD_ID_TOKEN")}} {
		p := c.Workloads["app"]
		p.Token = token
		p.Kubernetes.Audience = "tnl-orders"
		c.Workloads["app"] = p
		data, err := Generate(c, source)
		if err != nil || json.Unmarshal(data, &manifest) != nil {
			t.Fatal("common token override rejected", err)
		}
		a := manifest.Workloads["app"].Acquisition
		if a.Audience != "tnl-orders" || token.File != nil && a.TokenFile != *token.File || token.Env != nil && a.TokenEnv != *token.Env {
			t.Fatal("projected-token default replaced the explicit source")
		}
	}
}

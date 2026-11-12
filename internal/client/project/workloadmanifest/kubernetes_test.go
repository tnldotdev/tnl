package workloadmanifest

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/tnldotdev/tnl/internal/config"
)

func TestKubernetesProjectedTokenManifestAndSelection(t *testing.T) {
	server := "https://control.example.test"
	p := config.Workload{Kubernetes: &config.WorkloadKubernetes{ServiceAccount: "orders"}, Services: []string{"api"}}
	a, err := AcquisitionFor(p, server)
	if err != nil {
		t.Fatal(err)
	}
	directory, manifest, write := selectionFixture(t)
	manifest.Workloads = map[string]Workload{"app": {Provider: p.Provider(), Services: p.Services, Acquisition: a}}
	data, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	w := manifest.Workloads["app"]
	if w.Provider != "kubernetes" || w.Acquisition.Method != "token-file" || w.Acquisition.TokenFile != KubernetesTokenFile || w.Acquisition.Audience != server || w.MaxDurationSeconds != 0 || strings.Contains(string(data), "kubeconfig") {
		t.Fatal("projected token defaults changed")
	}
	write(manifest)
	if selected, err := Select(directory, "", "api", Runtime{KubernetesServiceHost: "10.0.0.1"}); err != nil || selected.Name != "app" {
		t.Fatal("Pod environment did not select the workload", err)
	}
	if _, err := Select(directory, "", "api", Runtime{KubernetesServiceHost: "10.0.0.1", CloudRunService: "other"}); !errors.Is(err, ErrRequired) {
		t.Fatal("ambiguous runtime hints accepted", err)
	}
	for _, token := range []*config.WorkloadToken{{File: new("/another/mounted/token")}, {Env: new("POD_ID_TOKEN")}} {
		p.Token = token
		p.Kubernetes.Audience = "tnl-orders"
		a, err := AcquisitionFor(p, server)
		if err != nil {
			t.Fatal("common token override rejected", err)
		}
		if a.Audience != "tnl-orders" || token.File != nil && a.TokenFile != *token.File || token.Env != nil && a.TokenEnv != *token.Env {
			t.Fatal("projected-token default replaced the explicit source")
		}
	}
}

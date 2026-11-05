package workloadmanifest

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	clientproject "github.com/tnldotdev/tnl/internal/client/project"
	"github.com/tnldotdev/tnl/internal/config"
)

func TestGoogleManifestDefaultsSelectionAndOverrides(t *testing.T) {
	c := config.TNL{Server: new("https://control.example.test"), Team: new("team"), Services: config.Services{"api": {}}, Workloads: map[string]config.Workload{"app": {Google: &config.WorkloadGoogle{ServiceAccount: "orders@project.iam.gserviceaccount.com"}, Services: []string{"api"}}}}
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
	if w.Provider != "google" || w.Acquisition.Method != "google-metadata" || w.Acquisition.Audience != *c.Server || w.MaxDurationSeconds != 0 || strings.Contains(string(data), "service_account") {
		t.Fatal("Google manifest retained setup selectors or changed defaults")
	}
	directory, _, write := selectionFixture(t)
	write(manifest)
	if selected, err := Select(directory, "", "api", Runtime{CloudRunService: "orders"}); err != nil || selected.Name != "app" {
		t.Fatal("Cloud Run did not select native Google acquisition", err)
	}
	if _, err := Select(directory, "", "api", Runtime{CloudRunService: "orders", Vercel: "1"}); !errors.Is(err, ErrRequired) {
		t.Fatal("ambiguous runtime accepted", err)
	}
	for _, token := range []*config.WorkloadToken{{File: new("current.jwt")}, {Env: new("GOOGLE_ID_TOKEN")}} {
		p := c.Workloads["app"]
		p.Token = token
		c.Workloads["app"] = p
		if _, err := Generate(c, source); err != nil {
			t.Fatal("common token override rejected", err)
		}
	}
}

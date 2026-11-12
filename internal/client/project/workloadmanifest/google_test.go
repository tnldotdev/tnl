package workloadmanifest

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/tnldotdev/tnl/internal/config"
)

func TestGoogleManifestDefaultsSelectionAndOverrides(t *testing.T) {
	server := "https://control.example.test"
	p := config.Workload{Google: &config.WorkloadGoogle{ServiceAccount: "orders@project.iam.gserviceaccount.com"}, Services: []string{"api"}}
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
	if w.Provider != "google" || w.Acquisition.Method != "google-metadata" || w.Acquisition.Audience != server || w.MaxDurationSeconds != 0 || strings.Contains(string(data), "service_account") {
		t.Fatal("Google manifest retained setup selectors or changed defaults")
	}
	write(manifest)
	if selected, err := Select(directory, "", "api", Runtime{CloudRunService: "orders"}); err != nil || selected.Name != "app" {
		t.Fatal("Cloud Run did not select native Google acquisition", err)
	}
	if _, err := Select(directory, "", "api", Runtime{CloudRunService: "orders", Vercel: "1"}); !errors.Is(err, ErrRequired) {
		t.Fatal("ambiguous runtime accepted", err)
	}
	for _, token := range []*config.WorkloadToken{{File: new("current.jwt")}, {Env: new("GOOGLE_ID_TOKEN")}} {
		p.Token = token
		if _, err := AcquisitionFor(p, server); err != nil {
			t.Fatal("common token override rejected", err)
		}
	}
}

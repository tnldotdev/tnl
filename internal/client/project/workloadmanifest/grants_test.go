package workloadmanifest

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	clientproject "github.com/tnldotdev/tnl/internal/client/project"
	"github.com/tnldotdev/tnl/internal/config"
)

func TestManifestPreservesApplicationGrantsAndSelectsIdentityWithoutVisit(t *testing.T) {
	for name, grants := range map[string]config.WorkloadGrants{
		"publish only":   {Publish: []config.WorkloadResource{{Service: new("api")}}},
		"saved URL only": {Publish: []config.WorkloadResource{{PublicURL: new("preview.example.test")}}},
		"allocate only":  {Allocate: []config.WorkloadAllocation{{Domain: "previews.example.test"}}},
		"mixed":          {Visit: []config.WorkloadResource{{Service: new("db")}, {PublicURL: new("preview.example.test")}}, Publish: []config.WorkloadResource{{Service: new("api")}}, Allocate: []config.WorkloadAllocation{{Domain: "previews.example.test"}}},
	} {
		t.Run(name, func(t *testing.T) {
			directory, _, _ := selectionFixture(t)
			c := config.TNL{Server: new("https://control.example.test"), Team: new("team"), Services: config.Services{"api": {}, "db": {Protocol: new("postgres")}}, Workloads: map[string]config.Workload{"job": {GitHub: &config.WorkloadGitHub{Workflow: ".github/workflows/test.yml"}, Grants: grants}}}
			source := clientproject.SourceIdentity{Key: "project", Fingerprint: strings.Repeat("a", 64), Label: "app"}
			data, err := Generate(c, source)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(data), `"private_key"`) || strings.Contains(string(data), `"credential"`) {
				t.Fatal("manifest contains runtime credentials")
			}
			var manifest Manifest
			if err := json.Unmarshal(data, &manifest); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(manifest.Workloads["job"].Grants, grants) {
				t.Fatal("manifest lost an operation or selector")
			}
			for _, service := range c.Workloads["job"].ReferencedServices() {
				if manifest.Services[service] != config.Protocol(c.Services[service]) {
					t.Fatal("publication service omitted from manifest")
				}
			}
			if err := os.WriteFile(filepath.Join(directory, ".tnl", "generated", Filename), data, 0600); err != nil {
				t.Fatal(err)
			}
			selected, err := Select(directory, "job", "", Runtime{})
			if err != nil || selected.Name != "job" {
				t.Fatal("identity-only selection required a visitor service", err)
			}
			if _, err := Select(directory, "job", "api", Runtime{}); !errors.Is(err, ErrDenied) {
				t.Fatal("publication grant became visit authority", err)
			}
			_, err = Select(directory, "job", "db", Runtime{})
			if (err == nil) != (name == "mixed") {
				t.Fatal("visit service selection changed", err)
			}
		})
	}
}

func TestManifestRejectsRemovedServiceList(t *testing.T) {
	directory, _, _ := selectionFixture(t)
	path := filepath.Join(directory, ".tnl", "generated", Filename)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	data = []byte(strings.Replace(string(data), `"grants":`, `"services":["api"],"grants":`, 1))
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Select(directory, "job", "", Runtime{}); !errors.Is(err, ErrInvalid) {
		t.Fatal("manifest accepted removed workload services field", err)
	}
}

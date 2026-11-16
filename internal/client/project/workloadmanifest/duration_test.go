package workloadmanifest

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	clientproject "github.com/tnldotdev/tnl/internal/client/project"
	"github.com/tnldotdev/tnl/internal/config"
)

func TestManifestOptionalHardDuration(t *testing.T) {
	c := config.Project{Server: new("https://control.example"), Team: new("team"), Services: map[string]config.ServiceDeclaration{"api": {}}, Workloads: map[string]config.DeploymentWorkload{"app": {Deployment: "production", Workload: config.Workload{GitHub: &config.WorkloadGitHub{Workflow: ".github/workflows/test.yml"}, Services: []string{"api"}}}}}
	source := clientproject.SourceIdentity{Key: "project", Fingerprint: strings.Repeat("a", 64), Label: "app"}
	for _, duration := range []*config.Duration{nil, new(config.Duration(24 * time.Hour))} {
		policy := c.Workloads["app"]
		policy.MaxDuration = duration
		c.Workloads["app"] = policy
		data, err := Generate(c, source)
		if err != nil {
			t.Fatal(err)
		}
		var manifest Manifest
		if err := json.Unmarshal(data, &manifest); err != nil {
			t.Fatal(err)
		}
		want := 0
		if duration != nil {
			want = int(duration.Value() / time.Second)
		}
		workload := manifest.Workloads["app"]
		if workload.MaxDurationSeconds != want || manifest.Validate() != nil {
			t.Fatal("manifest changed the optional hard limit")
		}
		for _, invalid := range []int{-1, int(config.MaxWorkloadMaxDurationSeconds + 1)} {
			workload.MaxDurationSeconds = invalid
			manifest.Workloads["app"] = workload
			if manifest.Validate() == nil {
				t.Fatal("manifest accepted an invalid duration")
			}
		}
	}
}

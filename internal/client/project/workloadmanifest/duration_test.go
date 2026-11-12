package workloadmanifest

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/config"
)

func TestManifestOptionalHardDuration(t *testing.T) {
	_, manifest, _ := selectionFixture(t)
	for _, duration := range []*config.Duration{nil, new(config.Duration(24 * time.Hour))} {
		policy := config.Workload{MaxDuration: duration}
		manifest.Workloads = map[string]Workload{"app": {Provider: "github", Services: []string{"api"}, MaxDurationSeconds: int(policy.DurationLimit().Seconds()), Acquisition: Acquisition{Method: "github-actions", Audience: manifest.Server}}}
		data, err := json.Marshal(manifest)
		if err != nil {
			t.Fatal(err)
		}
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

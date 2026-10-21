package main

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/projectconfig"
)

func TestWaitDoesNotTreatOldSnapshotAsFreshOwnerCheck(t *testing.T) {
	project := projectConfiguration{Project: projectconfig.Project{Root: t.TempDir(), Config: config.TNL{Services: config.Services{"web": {}}}}}
	var output bytes.Buffer
	err := runAppWait(t.Context(), project, filepath.Join(t.TempDir(), "state"), waitCommand{Timeout: 10 * time.Millisecond, Output: "json"}, &output)
	if err == nil {
		t.Fatal("wait succeeded without an owner check")
	}
	var result struct {
		State     string `json:"state"`
		CheckedBy string `json:"checked_by"`
		Services  []struct {
			Ready bool `json:"ready"`
		} `json:"services"`
	}
	if decodeErr := json.Unmarshal(output.Bytes(), &result); decodeErr != nil {
		t.Fatal(decodeErr)
	}
	if result.State != "timed out" || result.CheckedBy != "local publisher process unavailable" || len(result.Services) != 1 || result.Services[0].Ready {
		t.Fatalf("wait=%s", output.String())
	}
}

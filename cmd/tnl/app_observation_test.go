package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"
	"time"

	clientproject "github.com/tnldotdev/tnl/internal/client/project"
	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/failure"
	publisherapp "github.com/tnldotdev/tnl/internal/publisher/app"
)

func TestWaitDoesNotTreatOldSnapshotAsFreshOwnerCheck(t *testing.T) {
	project := projectConfiguration{Project: clientproject.Project{Root: t.TempDir(), Config: config.TNL{Services: config.Services{"web": {}}}}}
	state, err := clientstate.Open(t.Context(), filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := state.Close(); err != nil {
			t.Error(err)
		}
	})
	old, err := publisherapp.ReadSnapshotFrom(t.Context(), state, project.Root)
	if err != nil {
		t.Fatal(err)
	}
	old.Services = []publisherapp.Service{{
		Name: "web", Directory: project.Root, RegistrationID: "old-registration", Target: "http://127.0.0.1:3000",
		Registered: true, Routable: true, Ready: true, RunNumber: 7,
		Observation: &publisherapp.Observation{RegistrationID: "old-registration", RunNumber: 7,
			CheckedAt: time.Now().Add(-time.Hour), Status: 204, Ready: true},
	}}
	if err := publisherapp.CommitSnapshot(t.Context(), state, &old, "service.readiness", nil); err != nil {
		t.Fatal(err)
	}
	saved, err := publisherapp.ReadSnapshotFrom(t.Context(), state, project.Root)
	if err != nil || len(saved.Services) != 1 || !saved.Services[0].Ready || saved.Services[0].Observation == nil {
		t.Fatal("fixture did not persist old readiness", saved, err)
	}
	var output bytes.Buffer
	err = runAppWait(t.Context(), project, state.Root(), waitCommand{Timeout: 10 * time.Millisecond, Output: "json"}, &output)
	if reason, _ := failure.ReasonOf(err); reason != failure.AppReadinessTimeout || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("old readiness without an owner did not time out with its original cause", err)
	}
	var result struct {
		State     string `json:"state"`
		CheckedBy string `json:"checked_by"`
		Services  []struct {
			Registered  bool                      `json:"registered"`
			Routable    bool                      `json:"routable"`
			Ready       bool                      `json:"ready"`
			Observation *publisherapp.Observation `json:"observation"`
			Failure     string                    `json:"failure"`
		} `json:"services"`
	}
	if decodeErr := json.Unmarshal(output.Bytes(), &result); decodeErr != nil {
		t.Fatalf("decode wait result: %v; command error: %v; output: %q", decodeErr, err, output.String())
	}
	if result.State != "timed out" || result.CheckedBy != "local publisher process unavailable" || len(result.Services) != 1 || result.Services[0].Ready {
		t.Fatalf("wait=%s", output.String())
	}
	if service := result.Services[0]; service.Registered || service.Routable || service.Observation != nil || service.Failure != "runtime.manager_unavailable" {
		t.Fatalf("wait presented saved readiness as current: %s", output.String())
	}
}

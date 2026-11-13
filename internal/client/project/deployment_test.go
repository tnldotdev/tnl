package project

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/tnldotdev/tnl/internal/config"
)

func TestDeploymentSelectionDoesNotDiscoverOrChangeSiblingBindings(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "tnl.json")
	source := `{"version":1,"tnl":{"services":{"db":{"protocol":"postgres"},"web":{}},"deployments":{"local":{"targets":{"db":{"type":"compose","service":"db","port":5432},"web":{}}},"staging":{"targets":{"db":{"address":"staging.internal:5432"}}},"production":{"targets":{"db":{"address":"production.internal:5432"}}}},"workloads":{"migrate":{"deployment":"production","fly":{"app":"orders"},"services":["db"]}}}}`
	if err := os.WriteFile(path, []byte(source), 0600); err != nil {
		t.Fatal(err)
	}
	// no local Compose file exists. selecting a remote deployment must not open it.
	staging, err := Resolve(t.Context(), Selection{Path: path, Deployment: "staging"}, root, [32]byte{})
	if err != nil {
		t.Fatal(err)
	}
	production, err := staging.SelectDeployment("production")
	if err != nil {
		t.Fatal(err)
	}
	if staging.Deployment != "staging" || len(staging.Config.Services) != 1 || len(staging.Config.Workloads) != 0 || production.Deployment != "production" || len(production.Config.Workloads) != 1 || config.PublisherGroupName(production.Config.Services["db"]) != "production" {
		t.Fatal("selected deployment borrowed a sibling's services or workloads")
	}
	production.Config.Services["db"].Target.Address = new(config.Target("changed.internal:5432"))
	if got := string(*staging.Config.Services["db"].Target.Address); got != "staging.internal:5432" {
		t.Fatal("one selection changed its sibling", got)
	}
	again, err := staging.SelectDeployment("production")
	if err != nil || string(*again.Config.Services["db"].Target.Address) != "production.internal:5432" {
		t.Fatal("one selection changed the evaluated declaration", err)
	}
	if _, err := staging.SelectDeployment("local"); err == nil {
		t.Fatal("local selection silently skipped missing Compose configuration")
	}
	if _, err := staging.SelectDeployment("missing"); err == nil {
		t.Fatal("missing selection fell back to another deployment")
	}
}

func TestWorkloadSelectionAndSnapshotRetainExactDeployment(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "tnl.config.ts")
	source := `export default {services:{db:{protocol:"postgres"}},deployments:{production:{targets:{db:{address:"production.internal:5432"}}},staging:{targets:{db:{address:"staging.internal:5432"}}}},workloads:{migrate:{deployment:"production",fly:{app:"orders"},services:["db"]}}};`
	if err := os.WriteFile(path, []byte(source), 0600); err != nil {
		t.Fatal(err)
	}
	project, err := Resolve(t.Context(), Selection{Path: path, Workload: "migrate"}, root, [32]byte{})
	if err != nil {
		t.Fatal(err)
	}
	if project.Deployment != "production" || string(*project.Config.Services["db"].Target.Address) != "production.internal:5432" {
		t.Fatal("workload used a default or sibling deployment")
	}
	for _, selection := range []Selection{{Path: path, Workload: "missing"}, {Path: path, Deployment: "staging", Workload: "migrate"}} {
		if _, err := Resolve(t.Context(), selection, root, [32]byte{}); err == nil {
			t.Fatal("missing or mismatched workload selection was accepted")
		}
	}
	encoded, digest, err := project.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	// transferring a prepared selection never evaluates the source again.
	if err := os.WriteFile(path, []byte(`throw new Error("must not evaluate")`), 0600); err != nil {
		t.Fatal(err)
	}
	restored, err := ReadSnapshot(bytes.NewReader(encoded))
	if err != nil {
		t.Fatal(err)
	}
	again, restoredDigest, err := restored.Snapshot()
	if err != nil || restored.Deployment != "production" || restoredDigest != digest || !bytes.Equal(encoded, again) {
		t.Fatal("snapshot changed its captured deployment", err)
	}
}

package connector

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	clientproject "github.com/tnldotdev/tnl/internal/client/project"
	"github.com/tnldotdev/tnl/internal/client/project/workloadmanifest"
	"github.com/tnldotdev/tnl/internal/config"
)

func TestWorkloadManifestWithoutGitOrRuntimeConfig(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	c := config.TNL{Server: new("https://control.example"), Team: new("acme"), Services: config.Services{"inventory": {Protocol: new("http"), Target: &config.ServiceTarget{Type: "address", Address: new(config.Target("http://private-target.invalid:3000"))}}, "models": {Protocol: new("postgres")}}, Workloads: map[string]config.Workload{"storefront": {Vercel: &config.WorkloadVercel{Project: "store", Environment: "production"}, Services: []string{"inventory", "models"}}}}
	data, err := workloadmanifest.Generate(c, clientproject.SourceIdentity{Key: "project-store", Fingerprint: strings.Repeat("a", 64), Label: "store"})
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(data, []byte("private-target")) || bytes.Contains(data, []byte(root)) || bytes.Contains(data, []byte("team_one")) {
		t.Fatal("manifest retained target, checkout, or authority constraints")
	}
	path := filepath.Join(root, workloadmanifest.Filename)
	if err = os.WriteFile(path, data, 0644); err != nil {
		t.Fatal(err)
	}
	// invalid project configuration deliberately exists but must not be evaluated.
	if err = os.WriteFile(filepath.Join(root, "tnl.config.ts"), []byte("throw new Error('must not load')"), 0644); err != nil {
		t.Fatal(err)
	}
	project, scope, err := connectionProject(t.Context(), ContextOptions{Directory: root, Manifest: path, Workload: "storefront"})
	if err != nil {
		t.Fatal(err)
	}
	if scope.TeamID != "acme" || scope.Workload != "storefront" || scope.ProjectKey != "project-store" || scope.SourceID != strings.Repeat("a", 64) || scope.WorktreeKey != "deployment" || len(scope.Services) != 2 || config.Protocol(project.Config.Services["models"]) != "postgres" {
		t.Fatal("deployment context changed")
	}
	var wire map[string]any
	if json.Unmarshal(data, &wire) != nil {
		t.Fatal("manifest JSON")
	}
	wire["assertion"] = "must-not-persist"
	bad, _ := json.Marshal(wire)
	if err = os.WriteFile(path, bad, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err = workloadmanifest.Read(path); err == nil {
		t.Fatal("manifest accepted an assertion field")
	}
}

func TestConnectionGroupManifestIsExplicitAndIsolated(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	manifest := workloadmanifest.Manifest{Schema: 1, Server: "https://control.example", Team: "acme", ProjectKey: "tractors", SourceFingerprint: strings.Repeat("a", 64), ProjectLabel: "tractors", Services: map[string]string{"diagnostics": "http"}, Workloads: map[string]workloadmanifest.Workload{"monitor": {Provider: "fly", Services: []string{"diagnostics"}, MaxDurationSeconds: 3600, Acquisition: workloadmanifest.Acquisition{Method: "callback", Audience: "https://control.example"}}}}
	for index := range 127 {
		manifest.Services[fmt.Sprintf("service-%d", index)] = "tcp"
	}
	var digest string
	for _, character := range []string{"a", "b"} {
		manifest.PublisherGroupID = "pgrp_" + strings.Repeat(character, 22)
		data, err := json.Marshal(manifest)
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(root, character+".json")
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
		project, scope, err := connectionProject(t.Context(), ContextOptions{Directory: root, Manifest: path, Workload: "monitor"})
		if err != nil {
			t.Fatal(err)
		}
		if scope.PublisherGroupID != manifest.PublisherGroupID || scope.ConfigDigest == digest {
			t.Fatal("group scope crossed owners")
		}
		if len(project.Config.Services) != 1 || len(scope.Services) != 1 || scope.Services[0] != "diagnostics" {
			t.Fatal("descriptor inventory widened the workload selection")
		}
		digest = scope.ConfigDigest
	}
	manifest.PublisherGroupID = ""
	if err := manifest.Validate(); err == nil {
		t.Fatal("non-group manifest accepted another provider's callback acquisition")
	}
}

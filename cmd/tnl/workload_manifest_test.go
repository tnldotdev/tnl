package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/controlstate"
	"github.com/tnldotdev/tnl/internal/projectconfig"
	"github.com/tnldotdev/tnl/internal/workloadmanifest"
)

func TestWorkloadManifestWithoutGitOrRuntimeConfig(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	c := config.TNL{Server: new("https://control.example"), Team: new("acme"), Services: config.Services{"inventory": {Protocol: new("http"), Target: &config.ServiceTarget{Type: "address", Address: new(config.Target("http://private-target.invalid:3000"))}}, "models": {Protocol: new("postgres")}}, Workloads: map[string]config.Workload{"storefront": {Provider: "vercel", TeamID: "team_one", ProjectID: "prj_store", Environment: "production", Services: []string{"inventory", "models"}}}}
	data, err := workloadmanifest.Generate(c, projectconfig.SourceIdentity{Key: "project-store", Fingerprint: strings.Repeat("a", 64), Label: "store"})
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
	project, scope, err := connectionProject(t.Context(), connectionsContextOptions{Directory: root, Manifest: path, Workload: "storefront"})
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

func TestVercelWorkloadTrustedSetup(t *testing.T) {
	original := readVercelWorkload
	t.Cleanup(func() { readVercelWorkload = original })
	calls := 0
	readVercelWorkload = func(_ context.Context, team, project string) (string, string, error) {
		calls++
		if team != "team_one" || project != "prj_store" {
			t.Fatal("setup selected another provider project")
		}
		return "acme", "team", nil
	}
	p := config.Workload{Provider: "vercel", TeamID: "team_one", ProjectID: "prj_store", Environment: "production", Services: []string{"inventory"}}
	trust, err := bindProviderWorkload(t.Context(), p, controlstate.ProjectWorkload{})
	if err != nil {
		t.Fatal(err)
	}
	if trust.Issuer != "https://oidc.vercel.com/acme" || trust.Audience != "https://vercel.com/acme" || trust.Claims["project_id"] != "prj_store" {
		t.Fatal("incorrect saved Vercel trust")
	}
	readVercelWorkload = func(context.Context, string, string) (string, string, error) {
		t.Fatal("unchanged setup consulted provider credentials")
		return "", "", nil
	}
	previous := controlstate.ProjectWorkload{Provider: "vercel", Trust: trust}
	reused, err := bindProviderWorkload(t.Context(), p, previous)
	if err != nil || calls != 1 || !reflect.DeepEqual(reused, trust) {
		t.Fatal("saved setup did not survive credential removal", err)
	}
}

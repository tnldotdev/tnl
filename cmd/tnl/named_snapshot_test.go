package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	clientproject "github.com/tnldotdev/tnl/internal/client/project"
)

func TestNamedAndAppSelectionShareTheSameSnapshot(t *testing.T) {
	root := t.TempDir()
	configuration := filepath.Join(root, "tnl.json")
	if err := os.WriteFile(configuration, []byte(`{"version":1,"tnl":{"server":"https://unselected.example.test","team":"unselected","services":{"api":{},"web":{},"sdk":{}},"deployments":{"local":{"targets":{"api":{"address":"http://127.0.0.1:3000","access":{"team":true}},"web":{"address":"http://127.0.0.1:3000","public_url":{},"access":{"team":true}},"sdk":{"access":{"team":true}}}}}}}`), 0600); err != nil {
		t.Fatal(err)
	}
	load := func(deployment string) projectConfiguration {
		t.Helper()
		project, err := loadProjectConfigurationWithSalt(t.Context(), cli{ConfigPath: configuration, Apply: applyCommand{Deployment: deployment}}, [32]byte{})
		if err != nil {
			t.Fatal(err)
		}
		return project
	}
	project := load("local")
	flags := publishCommand{Target: "api"}
	flags.ServerURL, flags.Team = "https://selected.example.test", "selected"
	if err := project.applyPublish(&flags); err != nil {
		t.Fatal(err)
	}
	named, err := namedInvocation(flags)
	if err != nil {
		t.Fatal(err)
	}
	namedSnapshot, _, err := named.project.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	app := load("")
	server, team := "https://selected.example.test", "selected"
	app.Config.Server, app.Config.Team = &server, &team
	appSnapshot, _, err := app.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(namedSnapshot, appSnapshot) {
		t.Fatalf("named and app snapshots differ:\nnamed: %s\napp: %s", namedSnapshot, appSnapshot)
	}
	restored, err := clientproject.ReadSnapshot(bytes.NewReader(namedSnapshot))
	if err != nil {
		t.Fatal(err)
	}
	again, _, err := restored.Snapshot()
	if err != nil || !bytes.Equal(namedSnapshot, again) {
		t.Fatalf("snapshot changed in transfer: %v\nbefore: %s\nafter: %s", err, namedSnapshot, again)
	}
}

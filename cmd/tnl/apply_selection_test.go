package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/alecthomas/kong"
)

func TestDeploymentCommandsLoadOnlyTheSelectedProjectBindings(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "tnl.json")
	// local Compose discovery would fail because there is no Compose file here.
	source := `{"version":1,"tnl":{"services":{"db":{"protocol":"postgres"},"web":{}},"deployments":{"local":{"targets":{"db":{"type":"compose","service":"db","port":5432},"web":{}}},"production":{"targets":{"db":{"address":"production.internal:5432"}}}}}}`
	if err := os.WriteFile(path, []byte(source), 0600); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{
		{"--config", path, "apply", "--deployment", "production"},
		{"--config", path, "connect", "db", "--deployment", "production"},
		{"--config", path, "status", "--deployment", "production"},
	} {
		var flags cli
		parser, err := kong.New(&flags)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := parser.Parse(args); err != nil {
			t.Fatal(err)
		}
		project, err := loadProjectConfigurationWithSalt(t.Context(), flags, [32]byte{})
		if err != nil {
			t.Fatal(err)
		}
		if project.Deployment != "production" || len(project.Config.Services) != 1 || string(*project.Config.Services["db"].Target.Address) != "production.internal:5432" || len(project.Declared.Services) != 2 {
			t.Fatal("command discovered or loaded a sibling deployment", args, project)
		}
	}
}

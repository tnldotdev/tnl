package main

import (
	"testing"

	clientproject "github.com/tnldotdev/tnl/internal/client/project"
	"github.com/tnldotdev/tnl/internal/config"
)

func TestApplySelectsEnvironmentServerBeforeProjectContext(t *testing.T) {
	declared := config.TNL{Server: new("https://default-control.example"), Team: new("team"), Environments: map[string]config.Environment{"staging": {Server: new("https://staging-control.example")}, "production": {}}}
	project := projectConfiguration{Project: clientproject.Project{Declared: &declared, Config: config.TNL{Server: new("https://local-control.example")}}}
	for _, test := range []struct{ name, explicit, want string }{
		{"staging", "", "https://staging-control.example"},
		{"production", "", "https://default-control.example"},
		{"staging", "https://explicit-control.example", "https://explicit-control.example"},
	} {
		flags := applyCommand{Environment: test.name, scopedTeamFlags: scopedTeamFlags{remoteFlags: remoteFlags{ServerURL: test.explicit}}}
		if err := applyEnvironmentCommandContext(project, &flags); err != nil || flags.ServerURL != test.want {
			t.Fatalf("environment server=%s, want %s: %v", flags.ServerURL, test.want, err)
		}
	}
	flags := applyCommand{Environment: "staging", scopedTeamFlags: scopedTeamFlags{remoteFlags: remoteFlags{AccessToken: "explicit-token"}}}
	if err := applyEnvironmentCommandContext(project, &flags); err == nil {
		t.Fatal("project configuration selected an explicit credential's server")
	}
}

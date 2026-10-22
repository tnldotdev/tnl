package main

import (
	"testing"

	clientproject "github.com/tnldotdev/tnl/internal/client/project"
	"github.com/tnldotdev/tnl/internal/config"
)

func TestConnectKeyAndOverrideUseEffectiveServerAndTeam(t *testing.T) {
	rootServer, rootTeam := "https://root.example.test", "root-team"
	alias := "database"
	project := projectConfiguration{Project: clientproject.Project{Config: config.TNL{Server: &rootServer, Team: &rootTeam, Services: config.Services{"orders": {Name: &alias}}}}}
	for _, name := range []string{"orders", alias, "svc_arbitrary"} {
		flags := connectStartCommand{Name: name}
		if err := project.applyConnect(&flags); err != nil {
			t.Fatal(err)
		}
		if flags.ServerURL != rootServer || flags.ProjectTeam != rootTeam {
			t.Fatalf("%s selected %s/%s, want %s/%s", name, flags.ServerURL, flags.ProjectTeam, rootServer, rootTeam)
		}
	}
	flags := connectStartCommand{Name: alias, scopedTeamFlags: scopedTeamFlags{remoteFlags: remoteFlags{ServerURL: "https://explicit.example.test"}, teamSelectionFlags: teamSelectionFlags{Team: "explicit-team"}}}
	if err := project.applyConnect(&flags); err != nil || flags.ServerURL != "https://explicit.example.test" || flags.selection().SelectedTeam != "explicit-team" || flags.ProjectTeam != "" {
		t.Fatal("explicit scope retained another server's project team", flags.scopedTeamFlags, err)
	}
}

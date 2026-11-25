package main

import (
	"io"
	"strings"
	"testing"

	clientproject "github.com/tnldotdev/tnl/internal/client/project"
	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/failure"
)

func TestConnectKeyAndOverrideUseEffectiveServerAndTeam(t *testing.T) {
	rootServer, rootTeam := "https://root.example.test", "root-team"
	alias := "database"
	project := projectConfiguration{Project: clientproject.Project{Config: config.TNL{Server: &rootServer, Team: &rootTeam, Services: config.Services{"orders": {Name: &alias}}}}}
	for _, name := range []string{"orders", alias, "svc_0123456789abcdefghijkl", "orders.example.test", "https://orders.example.test/"} {
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

func TestConnectRejectsLocalClientURLsBeforeStarting(t *testing.T) {
	var flags cli
	_, err := commandForTest(&flags, io.Discard)([]string{"connect", "postgresql://orders.example.test:15432/?hostaddr=127.0.0.1&secret=private"})
	presented := presentHumanFailure(err)
	if presented.reason != failure.InvalidTunnelFlags || !strings.Contains(presented.message, "local client URL is not a saved address") {
		t.Fatalf("unexpected diagnostic: %+v", presented)
	}
	if strings.Contains(presented.message, "private") || strings.Contains(presented.message, "15432") {
		t.Fatalf("diagnostic copied local dial details: %q", presented.message)
	}
}

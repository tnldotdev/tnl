package main

import (
	"context"
	"reflect"
	"testing"

	"github.com/tnldotdev/tnl/internal/config"
	controlstate "github.com/tnldotdev/tnl/internal/control/state"
)

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

package main

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/tnldotdev/tnl/internal/clientstate"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/pkg/api/authorityv1"
)

type selectedTeamAPI struct {
	teamAPI
	domainCalls int
}

func (api *selectedTeamAPI) GetTeam(_ context.Context, id string) (authorityv1.Team, error) {
	return authorityv1.Team{Id: id, DisplayName: id}, nil
}

func (api *selectedTeamAPI) ListTeamDomains(_ context.Context, _ string) (authorityv1.DomainPage, error) {
	api.domainCalls++
	return authorityv1.DomainPage{}, errors.New("domain service unavailable")
}

func TestTeamSelectionDoesNotRequireDomains(t *testing.T) {
	db, err := clientstate.Open(t.Context(), filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	store, err := db.Server(t.Context(), "https://control.example.test")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SaveSelectedTeam(t.Context(), "removed-team"); err != nil {
		t.Fatal(err)
	}
	api := &selectedTeamAPI{}
	session := teamSession{store: store, api: api, identity: authorityv1.IdentityContext{
		PersonalTeamId: "personal", Memberships: []authorityv1.Membership{
			{TeamId: "personal", TeamDisplayName: "Personal"},
			{TeamId: "studio-id", TeamDisplayName: "studio"},
			{TeamId: "other-id", TeamDisplayName: "other"},
		},
	}}
	current, err := session.current(t.Context())
	if err != nil || current.team.Id != "personal" || api.domainCalls != 0 {
		t.Fatalf("stale saved team: %#v, %v; domain reads %d", current, err, api.domainCalls)
	}
	selected, _, err := store.SelectedTeam(t.Context())
	if err != nil || selected != "personal" {
		t.Fatalf("saved team = %q, %v", selected, err)
	}
	session.selectedTeam, session.projectTeam = "studio", "stale-project"
	current, err = session.current(t.Context())
	if err != nil || current.team.Id != "studio-id" || api.domainCalls != 0 {
		t.Fatalf("explicit slug selection: %#v, %v; domain reads %d", current, err, api.domainCalls)
	}
	if _, err := session.currentWithDomains(t.Context()); err == nil || api.domainCalls != 1 {
		t.Fatalf("domain-dependent selection: %v; domain reads %d", err, api.domainCalls)
	}
	selected, _, err = store.SelectedTeam(t.Context())
	if err != nil || selected != "personal" {
		t.Fatalf("one-command override changed saved team: %q, %v", selected, err)
	}
	if _, err := session.resolveMembership(t.Context(), "missing"); err == nil {
		t.Fatal("missing team was accepted")
	} else if reason, _, ok := failure.Describe(err); !ok || reason != failure.TeamNotFound {
		t.Fatalf("missing team reason = %q, %v", reason, err)
	}
	session.identity.Memberships = append(session.identity.Memberships, authorityv1.Membership{TeamId: "another", TeamDisplayName: "studio"})
	if _, err := session.resolveMembership(t.Context(), "studio"); err == nil {
		t.Fatal("ambiguous team was accepted")
	} else if reason, _, ok := failure.Describe(err); !ok || reason != failure.TeamSelectionAmbiguous {
		t.Fatalf("ambiguous team reason = %q, %v", reason, err)
	}
}

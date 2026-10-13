package localpublisher

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/tnldotdev/tnl/internal/clientauth"
	"github.com/tnldotdev/tnl/internal/clientstate"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/pkg/api/authorityv1"
)

type teamAPI interface {
	IdentityContext(context.Context) (authorityv1.IdentityContext, error)
	GetTeam(context.Context, string) (authorityv1.Team, error)
	ListTeamDomains(context.Context, string) (authorityv1.DomainPage, error)
}

type teamContext struct {
	team       authorityv1.Team
	membership authorityv1.Membership
	domains    []authorityv1.Domain
	mode       naming.ManagedURLMode
	builtin    bool
}

type teamSession struct {
	store                     *clientstate.Store
	authenticated             *clientauth.Client
	api                       teamAPI
	identity                  authorityv1.IdentityContext
	projectTeam, selectedTeam string
}

func (s *teamSession) current(ctx context.Context) (teamContext, error) {
	membership, err := s.currentMembership(ctx)
	if err != nil {
		return teamContext{}, err
	}
	team, err := s.api.GetTeam(ctx, membership.TeamId)
	if err != nil {
		return teamContext{}, err
	}
	current := teamContext{team: team, membership: membership,
		builtin: s.identity.Identity.Administrator && team.Kind == authorityv1.Personal && team.Id == s.identity.PersonalTeamId}
	if s.authenticated != nil {
		current.mode = naming.ManagedURLMode(s.authenticated.Discovery.ManagedUrlMode)
	}
	return current, nil
}

func (s *teamSession) currentWithDomains(ctx context.Context) (teamContext, error) {
	current, err := s.current(ctx)
	if err != nil {
		return teamContext{}, err
	}
	domains, err := s.api.ListTeamDomains(ctx, current.team.Id)
	if err != nil {
		return teamContext{}, err
	}
	current.domains = domains.Domains
	return current, nil
}

func (s *teamSession) currentMembership(ctx context.Context) (authorityv1.Membership, error) {
	if selected := s.selectedTeam; selected != "" {
		return s.resolveMembership(ctx, selected)
	}
	if s.projectTeam != "" {
		selected, err := s.resolveMembership(ctx, s.projectTeam)
		if err != nil {
			return authorityv1.Membership{}, failure.Wrap("resolve project team", failure.TeamNotFound,
				fmt.Errorf("resolve project team %q: %w (use --team to override or tnl team list to find a membership)", s.projectTeam, err))
		}
		return selected, nil
	}
	teamID, _, err := s.store.SelectedTeam(ctx)
	if err != nil {
		return authorityv1.Membership{}, err
	}
	membership, found := membershipForTeam(s.identity.Memberships, teamID)
	if !found {
		teamID = s.identity.PersonalTeamId
		membership, found = membershipForTeam(s.identity.Memberships, teamID)
		if !found {
			return authorityv1.Membership{}, failure.Wrap("select personal team", failure.TeamNotFound,
				errors.New("authenticated identity has no personal-team membership"))
		}
	}
	if err := s.store.SaveSelectedTeam(ctx, teamID); err != nil {
		return authorityv1.Membership{}, err
	}
	return membership, nil
}

func (s *teamSession) resolveMembership(ctx context.Context, team string) (authorityv1.Membership, error) {
	if team == "" {
		selected, found, err := s.store.SelectedTeam(ctx)
		if err != nil {
			return authorityv1.Membership{}, err
		}
		if found {
			team = selected
		} else {
			team = s.identity.PersonalTeamId
		}
	}
	var matches []authorityv1.Membership
	for _, membership := range s.identity.Memberships {
		if membership.TeamId == team {
			return membership, nil
		}
	}
	for _, membership := range s.identity.Memberships {
		if membership.TeamDisplayName == team {
			matches = append(matches, membership)
		}
	}
	if len(matches) == 0 {
		return authorityv1.Membership{}, failure.Wrap("select team", failure.TeamNotFound,
			fmt.Errorf("team %q is not in the current identity's memberships", team))
	}
	if len(matches) > 1 {
		ids := make([]string, len(matches))
		for index := range matches {
			ids[index] = matches[index].TeamId
		}
		return authorityv1.Membership{}, failure.Wrap("select team", failure.TeamSelectionAmbiguous,
			fmt.Errorf("team name %q is ambiguous; matching IDs: %s", team, strings.Join(ids, ", ")))
	}
	return matches[0], nil
}

func membershipForTeam(memberships []authorityv1.Membership, teamID string) (authorityv1.Membership, bool) {
	for _, membership := range memberships {
		if membership.TeamId == teamID {
			return membership, true
		}
	}
	return authorityv1.Membership{}, false
}

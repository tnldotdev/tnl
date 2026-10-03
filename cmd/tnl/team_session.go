package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/tnldotdev/tnl/internal/clientauth"
	"github.com/tnldotdev/tnl/internal/clientstate"
	"github.com/tnldotdev/tnl/internal/opaqueid"
	"github.com/tnldotdev/tnl/pkg/api/authorityv1"
)

type teamAPI interface {
	IdentityContext(context.Context) (authorityv1.IdentityContext, error)
	CreateTeam(context.Context, authorityv1.CreateTeamRequest, string) (authorityv1.Team, error)
	GetTeam(context.Context, string) (authorityv1.Team, error)
	ListTeamMemberships(context.Context, string) (authorityv1.MembershipPage, error)
	SetMembershipRole(context.Context, string, string, authorityv1.TeamRole) (authorityv1.Membership, error)
	RemoveMembership(context.Context, string, string) error
	ListTeamInvitations(context.Context, string) (authorityv1.InvitationPage, error)
	CreateTeamInvitation(context.Context, string, authorityv1.CreateInvitationRequest, string) (authorityv1.InvitationSecret, error)
	RevokeTeamInvitation(context.Context, string, string) error
	AcceptInvitation(context.Context, string) (authorityv1.Membership, error)
	ListTeamDomains(context.Context, string) (authorityv1.DomainPage, error)
	ClaimTeamDomain(context.Context, string, string, string, bool) (authorityv1.Domain, error)
	SetTeamDefaultDomain(context.Context, string, string) (authorityv1.Team, error)
	ReleaseTeamDomain(context.Context, string, string) error
}

type teamContext struct {
	team           authorityv1.Team
	membership     authorityv1.Membership
	domains        []authorityv1.Domain
	guestNamespace string
}

type teamSession struct {
	database      *clientstate.Database
	store         *clientstate.Store
	authenticated *clientauth.Client
	api           teamAPI
	identity      authorityv1.IdentityContext
	projectTeam   string
	selectedTeam  string
}

func openTeamSession(ctx context.Context, flags remoteFlags, command string, diagnostics io.Writer) (*teamSession, error) {
	serverURL, database, err := resolveServer(ctx, flags.StateDir, flags.ServerURL)
	if err != nil {
		return nil, err
	}
	store, err := database.Server(ctx, serverURL)
	if err != nil {
		database.Close()
		return nil, err
	}
	if err := requireSignInOutsideDemo(ctx, database, serverURL, flags.AccessToken); err != nil {
		database.Close()
		return nil, err
	}
	authenticated, err := clientauth.Authenticate(ctx, clientauth.Config{
		ServerEndpoint: serverURL, State: database, AccessToken: flags.AccessToken,
		Diagnostics: diagnostics, LoginToken: loginTokenPrompt(os.Stdin, diagnostics),
		AuthenticationPrompt: authenticationPrompt(diagnostics, command),
		OpenURL:              interactiveBrowserOpener(os.Stdin),
	})
	if err != nil {
		database.Close()
		return nil, err
	}
	api := teamAPI(authenticated.Authority)
	identity, err := api.IdentityContext(ctx)
	if err != nil {
		database.Close()
		return nil, err
	}
	return &teamSession{
		database: database, store: store, authenticated: authenticated, api: api,
		identity: identity, projectTeam: flags.ProjectTeam, selectedTeam: flags.SelectedTeam,
	}, nil
}

func (s *teamSession) Close() error { return s.database.Close() }

func (s *teamSession) current(ctx context.Context) (teamContext, error) {
	membership, err := s.currentMembership(ctx)
	if err != nil {
		return teamContext{}, err
	}
	team, err := s.api.GetTeam(ctx, membership.TeamId)
	if err != nil {
		return teamContext{}, err
	}
	return teamContext{team: team, membership: membership}, nil
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
			return authorityv1.Membership{}, fmt.Errorf("resolve project team %q: %w (use --team to override or tnl team list to find a membership)", s.projectTeam, err)
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
			return authorityv1.Membership{}, errors.New("authenticated identity has no personal-team membership")
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
		return authorityv1.Membership{}, fmt.Errorf("team %q is not in the current identity's memberships", team)
	}
	if len(matches) > 1 {
		ids := make([]string, len(matches))
		for index := range matches {
			ids[index] = matches[index].TeamId
		}
		return authorityv1.Membership{}, fmt.Errorf("team name %q is ambiguous; matching IDs: %s", team, strings.Join(ids, ", "))
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

func randomIdempotencyKey() (string, error) { return opaqueid.New(opaqueid.IdempotencyPrefix) }

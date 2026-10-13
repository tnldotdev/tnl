package main

import (
	"context"
	"io"
	"os"

	"github.com/tnldotdev/tnl/internal/clientauth"
	"github.com/tnldotdev/tnl/internal/clientstate"
	"github.com/tnldotdev/tnl/internal/localpublisher"
	"github.com/tnldotdev/tnl/internal/naming"
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
	team       authorityv1.Team
	membership authorityv1.Membership
	domains    []authorityv1.Domain
	mode       naming.ManagedURLMode
	builtin    bool
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
	current, err := s.selection().Current(ctx, false)
	return teamFromLocal(current), err
}

func (s *teamSession) currentWithDomains(ctx context.Context) (teamContext, error) {
	current, err := s.selection().Current(ctx, true)
	return teamFromLocal(current), err
}

func (s *teamSession) currentMembership(ctx context.Context) (authorityv1.Membership, error) {
	return s.selection().CurrentMembership(ctx)
}

func (s *teamSession) resolveMembership(ctx context.Context, team string) (authorityv1.Membership, error) {
	return s.selection().ResolveMembership(ctx, team)
}

func (s *teamSession) selection() localpublisher.TeamSelection {
	return localpublisher.TeamSelection{Store: s.store, Authenticated: s.authenticated, API: s.api,
		Identity: s.identity, ProjectTeam: s.projectTeam, SelectedTeam: s.selectedTeam}
}

func randomIdempotencyKey() (string, error) { return opaqueid.New(opaqueid.IdempotencyPrefix) }

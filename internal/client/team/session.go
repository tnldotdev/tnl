package team

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	clientauth "github.com/tnldotdev/tnl/internal/client/auth"
	clientserver "github.com/tnldotdev/tnl/internal/client/server"
	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/pkg/api/authorityv1"
)

// Options selects a signed-in server context. callers supply any sign-in UI.
type Options struct {
	ServerURL, StateDir, AccessToken string
	ProjectTeam, SelectedTeam        string
	Diagnostics                      io.Writer
	AuthenticationPrompt             func(clientauth.Prompt) error
	OpenURL                          func(string) error
	HTTPClient                       *http.Client
}

type API interface {
	IdentityContext(context.Context) (authorityv1.IdentityContext, error)
	GetTeam(context.Context, string) (authorityv1.Team, error)
	ListTeamDomains(context.Context, string) (authorityv1.DomainPage, error)
}

// Session owns the database opened by Open and selects teams from one identity.
type Session struct {
	database      *clientstate.Database
	store         *clientstate.Store
	authenticated *clientauth.Client
	api           API
	identity      authorityv1.IdentityContext
	projectTeam   string
	selectedTeam  string
}

func Open(ctx context.Context, options Options) (*Session, error) {
	serverURL, database, err := clientserver.Open(ctx, options.StateDir, options.ServerURL)
	if err != nil {
		return nil, err
	}
	store, err := database.Server(ctx, serverURL)
	if err != nil {
		database.Close()
		return nil, err
	}
	if err := clientauth.RequireSignInOutsideDemo(ctx, database, serverURL, options.AccessToken); err != nil {
		database.Close()
		return nil, err
	}
	authenticated, err := clientauth.Authenticate(ctx, clientauth.Config{
		ServerEndpoint: serverURL, State: database, AccessToken: options.AccessToken,
		Diagnostics: options.Diagnostics, AuthenticationPrompt: options.AuthenticationPrompt, OpenURL: options.OpenURL,
		HTTPClient: options.HTTPClient,
	})
	if err != nil {
		database.Close()
		return nil, err
	}
	identity, err := authenticated.Authority.IdentityContext(ctx)
	if err != nil {
		database.Close()
		return nil, err
	}
	return NewSession(database, store, authenticated, identity, options), nil
}

// NewSession reuses authentication and identity facts already read by a caller.
// pass a database only when transferring its lifetime to this session; otherwise
// the caller retains ownership and Close is a no-op.
func NewSession(database *clientstate.Database, store *clientstate.Store, authenticated *clientauth.Client, identity authorityv1.IdentityContext, options Options) *Session {
	return &Session{database: database, store: store, authenticated: authenticated,
		api: authenticated.Authority, identity: identity,
		projectTeam: options.ProjectTeam, selectedTeam: options.SelectedTeam}
}

func (s *Session) Close() error {
	if s.database == nil {
		return nil
	}
	return s.database.Close()
}

func (s *Session) Database() *clientstate.Database       { return s.database }
func (s *Session) Store() *clientstate.Store             { return s.store }
func (s *Session) Authenticated() *clientauth.Client     { return s.authenticated }
func (s *Session) Identity() authorityv1.IdentityContext { return s.identity }
func (s *Session) ProjectTeam() string                   { return s.projectTeam }
func (s *Session) SelectedTeam() string                  { return s.selectedTeam }

func (s *Session) Current(ctx context.Context) (Context, error) {
	membership, err := s.CurrentMembership(ctx)
	if err != nil {
		return Context{}, err
	}
	selected, err := s.api.GetTeam(ctx, membership.TeamId)
	if err != nil {
		return Context{}, err
	}
	current := Context{team: selected, membership: membership}
	if s.authenticated != nil {
		current.mode = naming.ManagedURLMode(s.authenticated.Discovery.ManagedUrlMode)
	}
	return current, nil
}

func (s *Session) CurrentWithDomains(ctx context.Context) (Context, error) {
	current, err := s.Current(ctx)
	if err != nil {
		return Context{}, err
	}
	domains, err := s.api.ListTeamDomains(ctx, current.team.Id)
	if err != nil {
		return Context{}, err
	}
	current.domains = domains.Domains
	return current, nil
}

func (s *Session) CurrentMembership(ctx context.Context) (authorityv1.Membership, error) {
	if s.selectedTeam != "" {
		return s.ResolveMembership(ctx, s.selectedTeam)
	}
	if s.projectTeam != "" {
		selected, err := s.ResolveMembership(ctx, s.projectTeam)
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
		teamID = s.InitialTeam()
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

func (s *Session) InitialTeam() string {
	if s.identity.DefaultTeamId != nil && *s.identity.DefaultTeamId != "" {
		return *s.identity.DefaultTeamId
	}
	return s.identity.PersonalTeamId
}

func (s *Session) ResolveMembership(ctx context.Context, selected string) (authorityv1.Membership, error) {
	if selected == "" {
		saved, found, err := s.store.SelectedTeam(ctx)
		if err != nil {
			return authorityv1.Membership{}, err
		}
		if found {
			selected = saved
		} else {
			selected = s.InitialTeam()
		}
	}
	for _, membership := range s.identity.Memberships {
		if membership.TeamId == selected {
			return membership, nil
		}
	}
	var matches []authorityv1.Membership
	for _, membership := range s.identity.Memberships {
		if membership.TeamDisplayName == selected {
			matches = append(matches, membership)
		}
	}
	if len(matches) == 0 {
		return authorityv1.Membership{}, failure.Wrap("select team", failure.TeamNotFound,
			fmt.Errorf("team %q is not in the current identity's memberships", selected))
	}
	if len(matches) > 1 {
		ids := make([]string, len(matches))
		for index := range matches {
			ids[index] = matches[index].TeamId
		}
		return authorityv1.Membership{}, failure.Wrap("select team", failure.TeamSelectionAmbiguous,
			fmt.Errorf("team name %q is ambiguous; matching IDs: %s", selected, strings.Join(ids, ", ")))
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

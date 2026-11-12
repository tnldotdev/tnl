package connector

import (
	"context"
	"io"

	"github.com/tnldotdev/tnl/internal/client/auth"
	clientproject "github.com/tnldotdev/tnl/internal/client/project"
	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	authorityv1 "github.com/tnldotdev/tnl/pkg/api/control/authority/v1"
)

// Operations composes connector operations with the client's sign-in UI.
// the opener resolves a human client context; connector owns its lifetime.
type Operations struct {
	OpenSession SessionOpener
}

type SessionOptions struct {
	ServerURL, StateDir, AccessToken, ProjectTeam, SelectedTeam string
}

type SessionOpener func(context.Context, SessionOptions, string, io.Writer) (*Session, error)

// Session is the signed-in client context used by a connector.
type Session struct {
	database          *clientstate.Database
	store             *clientstate.Store
	authenticated     *auth.Client
	identity          authorityv1.IdentityContext
	currentMembership func(context.Context) (authorityv1.Membership, error)
}

func NewSession(database *clientstate.Database, store *clientstate.Store, authenticated *auth.Client, identity authorityv1.IdentityContext, membership func(context.Context) (authorityv1.Membership, error)) *Session {
	return &Session{database: database, store: store, authenticated: authenticated, identity: identity, currentMembership: membership}
}

func (s *Session) Close() error { return s.database.Close() }

type projectConfiguration struct{ clientproject.Project }

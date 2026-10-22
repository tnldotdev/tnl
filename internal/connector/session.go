package connector

import (
	"context"
	"io"
	"path/filepath"
	"reflect"
	"time"

	clientauth "github.com/tnldotdev/tnl/internal/client/auth"
	projectconfig "github.com/tnldotdev/tnl/internal/client/project"
	"github.com/tnldotdev/tnl/internal/client/project/workloadmanifest"
	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	connectionruntime "github.com/tnldotdev/tnl/internal/connector/runtime"
	workloadclient "github.com/tnldotdev/tnl/internal/connector/workload"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/pkg/api/authorityv1"
)

// Operations composes native connector operations with the client's sign-in UI.
// the opener resolves a human client context; connector owns its lifetime.
type Operations struct {
	OpenSession SessionOpener
}

type SessionOptions struct {
	ServerURL, StateDir, AccessToken, ProjectTeam, SelectedTeam string
}

type SessionOpener func(context.Context, SessionOptions, string, io.Writer) (*Session, error)

// Session is the signed-in client context used by a native connector.
type Session struct {
	database          *clientstate.Database
	store             *clientstate.Store
	authenticated     *clientauth.Client
	identity          authorityv1.IdentityContext
	currentMembership func(context.Context) (authorityv1.Membership, error)
}

func NewSession(database *clientstate.Database, store *clientstate.Store, authenticated *clientauth.Client, identity authorityv1.IdentityContext, membership func(context.Context) (authorityv1.Membership, error)) *Session {
	return &Session{database: database, store: store, authenticated: authenticated, identity: identity, currentMembership: membership}
}

func (s *Session) Close() error { return s.database.Close() }

type projectConfiguration struct{ projectconfig.Project }

// a lost exchange response must retry the same assertion and in-memory key.
// a replacement owner/key cannot take over an already committed execution.
func exchangeConnectionWorkload(ctx context.Context, client *workloadclient.Client, scope connectionruntime.Context, assertion string) (authorityv1.WorkloadSession, error) {
	var session authorityv1.WorkloadSession
	var err error
	for attempt := range 3 {
		session, err = client.Exchange(ctx, scope.TeamID, scope.ProjectKey, scope.SourceID, scope.Workload, assertion, scope.Services)
		if err == nil {
			return session, nil
		}
		_, definition, known := failure.Describe(err)
		if !known || definition.Retry != failure.RetryLater || attempt == 2 || ctx.Err() != nil {
			break
		}
		timer := time.NewTimer(time.Duration(attempt+1) * 100 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return authorityv1.WorkloadSession{}, ctx.Err()
		case <-timer.C:
		}
	}
	return session, err
}

func Identify(ctx context.Context, options ContextOptions, input io.Reader) (authorityv1.WorkloadIdentity, error) {
	_, scope, err := connectionProject(ctx, options)
	if err != nil {
		return authorityv1.WorkloadIdentity{}, err
	}
	var request connectionruntime.StartRequest
	if connectionruntime.ReadJSON(input, &request) != nil || request.Schema != 1 || !reflect.DeepEqual(request.Context, scope) {
		return authorityv1.WorkloadIdentity{}, connectionruntime.ErrInvalid
	}
	if request.Assertion == "" {
		m, err := workloadmanifest.Read(options.Manifest)
		if err != nil {
			return authorityv1.WorkloadIdentity{}, err
		}
		hints := m.Workloads[scope.Workload].Acquisition
		if hints.TokenFile != "" && !filepath.IsAbs(hints.TokenFile) {
			hints.TokenFile = filepath.Join(scope.Directory, hints.TokenFile)
		}
		request.Assertion, err = workloadclient.Acquire(ctx, hints, nil)
		if err != nil {
			return authorityv1.WorkloadIdentity{}, err
		}
	}
	client, err := workloadclient.New(scope.Server, nil)
	if err != nil {
		return authorityv1.WorkloadIdentity{}, err
	}
	return client.IdentifyPolicy(ctx, scope.TeamID, scope.ProjectKey, scope.SourceID, scope.Workload, request.Assertion)
}

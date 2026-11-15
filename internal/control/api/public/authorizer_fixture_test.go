package public

import (
	"context"

	"github.com/tnldotdev/tnl/internal/policy/authorization"
)

func testPublicURLReadPrincipal() publicURLReadPrincipal {
	return publicURLReadPrincipal{identityID: "identity_1", teamIDs: map[string]struct{}{"team_1": {}}}
}

type recordingAuthorizer struct {
	principal            publicURLReadPrincipal
	decision             authorization.Decision
	readErr, mutationErr error
	readTokens           []string
	requests             []authorization.Request
}

func (a *recordingAuthorizer) Authorize(_ context.Context, request authorization.Request) (authorization.Decision, error) {
	a.requests = append(a.requests, request)
	return a.decision, a.mutationErr
}

func (a *recordingAuthorizer) AuthorizePublicURLReads(_ context.Context, token string) (publicURLReadPrincipal, error) {
	a.readTokens = append(a.readTokens, token)
	return a.principal, a.readErr
}

package public

import "context"

func testControlReadPrincipal() controlReadPrincipal {
	return controlReadPrincipal{identityID: "identity_1", teamIDs: map[string]struct{}{"team_1": {}}}
}

type recordingAuthorizer struct {
	principal  controlReadPrincipal
	readErr    error
	readTokens []string
}

func (a *recordingAuthorizer) AuthorizeControlReads(_ context.Context, token string) (controlReadPrincipal, error) {
	a.readTokens = append(a.readTokens, token)
	return a.principal, a.readErr
}

package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/tnldotdev/tnl/internal/auth"
	"github.com/tnldotdev/tnl/internal/credentials"
	"github.com/tnldotdev/tnl/internal/state"
	"github.com/tnldotdev/tnl/pkg/protocol/serverv1"
)

func TestControlSessionLogout(t *testing.T) {
	access, _, _, err := credentials.NewAccessToken()
	if err != nil {
		t.Fatal(err)
	}
	want := auth.Principal{
		SessionID: "control_session_0123456789abcdef0123456789abcdef",
		Identity:  state.Identity{ID: "identity"}, Grants: []auth.Grant{auth.GrantPublish},
	}
	var authenticated credentials.AccessToken
	var loggedOut auth.Principal
	service := authServiceStub{
		authenticate: func(_ context.Context, token credentials.AccessToken) (auth.Principal, error) {
			authenticated = token
			return want, nil
		},
		logout: func(_ context.Context, principal auth.Principal) error {
			loggedOut = principal
			return nil
		},
	}
	request := httptest.NewRequest(http.MethodPost, logoutPath, nil)
	request.Header.Set(authorizationHeader, "bEaReR "+access.String())
	response := httptest.NewRecorder()
	NewHandler(fixtureCapabilities(t), service).ServeHTTP(response, request)
	if response.Code != http.StatusNoContent || response.Body.Len() != 0 {
		t.Fatalf("status = %d, body = %q", response.Code, response.Body.String())
	}
	if authenticated != access || loggedOut.SessionID != want.SessionID || loggedOut.Identity != want.Identity {
		t.Fatalf("authenticated = %q, logged out = %#v", authenticated, loggedOut)
	}
}

func TestControlSessionLogoutRejectsInvalidBearer(t *testing.T) {
	access, _, _, err := credentials.NewAccessToken()
	if err != nil {
		t.Fatal(err)
	}
	login, err := credentials.NewLoginToken()
	if err != nil {
		t.Fatal(err)
	}
	service := authServiceStub{authenticate: func(context.Context, credentials.AccessToken) (auth.Principal, error) {
		return auth.Principal{}, auth.ErrUnauthenticated
	}}
	for name, values := range map[string][]string{
		"missing": nil, "duplicate": {"Bearer " + access.String(), "Bearer " + access.String()},
		"wrong scheme": {"Basic " + access.String()}, "wrong token class": {"Bearer " + login.String()},
		"oversized": {"Bearer " + strings.Repeat("x", maxCredentialBytes+1)},
	} {
		t.Run(name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, logoutPath, nil)
			for _, value := range values {
				request.Header.Add(authorizationHeader, value)
			}
			response := httptest.NewRecorder()
			NewHandler(fixtureCapabilities(t), service).ServeHTTP(response, request)
			assertBearerProblem(t, response, http.StatusUnauthorized, serverv1.Unauthenticated)
		})
	}
}

func TestControlSessionLogoutProblems(t *testing.T) {
	access, _, _, err := credentials.NewAccessToken()
	if err != nil {
		t.Fatal(err)
	}
	for name, test := range map[string]struct {
		authenticateErr error
		logoutErr       error
		status          int
		code            serverv1.ProblemCode
	}{
		"authentication failure": {authenticateErr: errors.New("read failed"), status: 500, code: serverv1.Internal},
		"logout failure":         {logoutErr: errors.New("write failed"), status: 500, code: serverv1.Internal},
		"revoked":                {logoutErr: auth.ErrUnauthenticated, status: 401, code: serverv1.Unauthenticated},
	} {
		t.Run(name, func(t *testing.T) {
			service := authServiceStub{
				authenticate: func(context.Context, credentials.AccessToken) (auth.Principal, error) {
					return auth.Principal{SessionID: "control_session_0123456789abcdef0123456789abcdef"}, test.authenticateErr
				},
				logout: func(context.Context, auth.Principal) error { return test.logoutErr },
			}
			request := httptest.NewRequest(http.MethodPost, logoutPath, nil)
			request.Header.Set(authorizationHeader, "Bearer "+access.String())
			response := httptest.NewRecorder()
			NewHandler(fixtureCapabilities(t), service).ServeHTTP(response, request)
			if response.Code != test.status {
				t.Fatalf("status = %d, want %d", response.Code, test.status)
			}
			var problem serverv1.Problem
			if err := json.Unmarshal(response.Body.Bytes(), &problem); err != nil || problem.Code != test.code {
				t.Fatalf("problem = %#v, error = %v", problem, err)
			}
		})
	}
}

type authServiceStub struct {
	authenticate func(context.Context, credentials.AccessToken) (auth.Principal, error)
	logout       func(context.Context, auth.Principal) error
}

func (authServiceStub) Exchange(context.Context, credentials.LoginToken) (auth.IssuedControlSession, error) {
	panic("unexpected Exchange call")
}

func (authServiceStub) Refresh(context.Context, credentials.RefreshToken) (auth.IssuedControlSession, error) {
	panic("unexpected Refresh call")
}

func (s authServiceStub) Authenticate(ctx context.Context, token credentials.AccessToken) (auth.Principal, error) {
	if s.authenticate == nil {
		panic("unexpected Authenticate call")
	}
	return s.authenticate(ctx, token)
}

func (s authServiceStub) Logout(ctx context.Context, principal auth.Principal) error {
	if s.logout == nil {
		panic("unexpected Logout call")
	}
	return s.logout(ctx, principal)
}

func assertBearerProblem(t *testing.T, response *httptest.ResponseRecorder, status int, code serverv1.ProblemCode) {
	t.Helper()
	if response.Code != status || response.Header().Get("WWW-Authenticate") != "Bearer" {
		t.Fatalf("status = %d, authenticate = %q", response.Code, response.Header().Get("WWW-Authenticate"))
	}
	var problem serverv1.Problem
	if err := json.Unmarshal(response.Body.Bytes(), &problem); err != nil || problem.Code != code {
		t.Fatalf("problem = %#v, error = %v", problem, err)
	}
}

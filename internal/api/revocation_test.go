package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/0xcadams/tnl/internal/auth"
	"github.com/0xcadams/tnl/internal/credentials"
	"github.com/0xcadams/tnl/internal/state"
	"github.com/0xcadams/tnl/pkg/protocol/corev1"
)

func TestCredentialRevocation(t *testing.T) {
	accessToken, _, _, err := credentials.NewAccessToken()
	if err != nil {
		t.Fatal(err)
	}
	_, targetID, _, err := credentials.NewAccessToken()
	if err != nil {
		t.Fatal(err)
	}
	wantPrincipal := state.Principal{ID: "principal"}
	var authenticated credentials.AccessToken
	var revoked credentials.CredentialID
	service := authServiceStub{
		authenticate: func(_ context.Context, token credentials.AccessToken) (state.Principal, error) {
			authenticated = token
			return wantPrincipal, nil
		},
		revoke: func(_ context.Context, principal state.Principal, credentialID credentials.CredentialID) error {
			if principal != wantPrincipal {
				t.Fatalf("principal = %#v, want %#v", principal, wantPrincipal)
			}
			revoked = credentialID
			return nil
		},
	}
	request := httptest.NewRequest(http.MethodDelete, credentialsPath+targetID.String(), nil)
	request.Header.Set(authorizationHeader, "bEaReR "+accessToken.String())
	request.Header.Set(requestIDHeader, "req_revoke")
	response := httptest.NewRecorder()

	NewHandler(fixtureCapabilities(t), service).ServeHTTP(response, request)

	if response.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d: %s", response.Code, http.StatusNoContent, response.Body.String())
	}
	if response.Body.Len() != 0 {
		t.Fatalf("response body = %q, want empty", response.Body.String())
	}
	if authenticated != accessToken || revoked != targetID {
		t.Fatalf("authenticated = %q, revoked = %q", authenticated, revoked)
	}
	for header, want := range map[string]string{
		"Cache-Control":          "no-store",
		requestIDHeader:          "req_revoke",
		"X-Content-Type-Options": "nosniff",
	} {
		if got := response.Header().Get(header); got != want {
			t.Fatalf("%s = %q, want %q", header, got, want)
		}
	}
	if contentType := response.Header().Get("Content-Type"); contentType != "" {
		t.Fatalf("Content-Type = %q, want empty", contentType)
	}
}

func TestCredentialRevocationRejectsBearerCredentialsWithoutDisclosure(t *testing.T) {
	bootstrap, err := credentials.NewBootstrapToken()
	if err != nil {
		t.Fatal(err)
	}
	accessToken, targetID, _, err := credentials.NewAccessToken()
	if err != nil {
		t.Fatal(err)
	}
	service := authServiceStub{
		authenticate: func(context.Context, credentials.AccessToken) (state.Principal, error) {
			return state.Principal{}, auth.ErrUnauthenticated
		},
	}

	for name, values := range map[string][]string{
		"missing":           nil,
		"duplicate":         {"Bearer " + accessToken.String(), "Bearer " + accessToken.String()},
		"wrong scheme":      {"Basic " + accessToken.String()},
		"empty":             {"Bearer "},
		"leading space":     {" Bearer " + accessToken.String()},
		"repeated space":    {"Bearer  " + accessToken.String()},
		"trailing space":    {"Bearer " + accessToken.String() + " "},
		"wrong token class": {"Bearer " + bootstrap.String()},
		"oversized":         {"Bearer " + strings.Repeat("x", maxCredentialBytes+1)},
	} {
		t.Run(name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodDelete, credentialsPath+targetID.String(), nil)
			for _, value := range values {
				request.Header.Add(authorizationHeader, value)
			}
			response := httptest.NewRecorder()

			NewHandler(fixtureCapabilities(t), service).ServeHTTP(response, request)

			assertBearerProblem(t, response, http.StatusUnauthorized, corev1.Unauthenticated)
			if strings.Contains(response.Body.String(), accessToken.String()) ||
				strings.Contains(response.Body.String(), bootstrap.String()) {
				t.Fatalf("response exposed credential: %s", response.Body.String())
			}
		})
	}
}

func TestCredentialRevocationProblems(t *testing.T) {
	accessToken, targetID, _, err := credentials.NewAccessToken()
	if err != nil {
		t.Fatal(err)
	}
	principal := state.Principal{ID: "principal"}

	for name, test := range map[string]struct {
		path            string
		authenticateErr error
		revokeErr       error
		status          int
		code            corev1.ProblemCode
	}{
		"invalid ID": {
			path: credentialsPath + "invalid", status: http.StatusBadRequest, code: corev1.InvalidArgument,
		},
		"authentication storage failure": {
			path: credentialsPath + targetID.String(), authenticateErr: errors.New("read failed"),
			status: http.StatusInternalServerError, code: corev1.Internal,
		},
		"not found": {
			path: credentialsPath + targetID.String(), revokeErr: auth.ErrCredentialNotFound,
			status: http.StatusNotFound, code: corev1.NotFound,
		},
		"revocation storage failure": {
			path: credentialsPath + targetID.String(), revokeErr: errors.New("write failed"),
			status: http.StatusInternalServerError, code: corev1.Internal,
		},
	} {
		t.Run(name, func(t *testing.T) {
			service := authServiceStub{
				authenticate: func(context.Context, credentials.AccessToken) (state.Principal, error) {
					return principal, test.authenticateErr
				},
				revoke: func(context.Context, state.Principal, credentials.CredentialID) error {
					return test.revokeErr
				},
			}
			request := httptest.NewRequest(http.MethodDelete, test.path, nil)
			request.Header.Set(authorizationHeader, "Bearer "+accessToken.String())
			response := httptest.NewRecorder()

			NewHandler(fixtureCapabilities(t), service).ServeHTTP(response, request)

			if response.Code != test.status {
				t.Fatalf("status = %d, want %d: %s", response.Code, test.status, response.Body.String())
			}
			var problem corev1.Problem
			if err := json.Unmarshal(response.Body.Bytes(), &problem); err != nil {
				t.Fatal(err)
			}
			if problem.Code != test.code {
				t.Fatalf("problem code = %q, want %q", problem.Code, test.code)
			}
		})
	}
}

func TestCredentialRevocationEndToEnd(t *testing.T) {
	db, err := state.Open(context.Background(), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	bootstrap, err := credentials.NewBootstrapToken()
	if err != nil {
		t.Fatal(err)
	}
	service, err := auth.NewService(db, bootstrap)
	if err != nil {
		t.Fatal(err)
	}
	first, err := service.Exchange(context.Background(), bootstrap)
	if err != nil {
		t.Fatal(err)
	}
	second, err := service.Exchange(context.Background(), bootstrap)
	if err != nil {
		t.Fatal(err)
	}
	handler := NewHandler(fixtureCapabilities(t), service)

	assertRevokeStatus(t, handler, first.Token, first.CredentialID, http.StatusNoContent)
	assertRevokeStatus(t, handler, second.Token, first.CredentialID, http.StatusNoContent)
	assertRevokeStatus(t, handler, first.Token, second.CredentialID, http.StatusUnauthorized)
}

func TestCredentialRevocationMethodAndPathRouting(t *testing.T) {
	_, credentialID, _, err := credentials.NewAccessToken()
	if err != nil {
		t.Fatal(err)
	}
	for name, test := range map[string]struct {
		method string
		path   string
		status int
		allow  string
	}{
		"method":      {method: http.MethodGet, path: credentialsPath + credentialID.String(), status: http.StatusMethodNotAllowed, allow: http.MethodDelete},
		"missing ID":  {method: http.MethodDelete, path: credentialsPath, status: http.StatusNotFound},
		"nested path": {method: http.MethodDelete, path: credentialsPath + credentialID.String() + "/nested", status: http.StatusNotFound},
	} {
		t.Run(name, func(t *testing.T) {
			request := httptest.NewRequest(test.method, test.path, nil)
			response := httptest.NewRecorder()
			NewHandler(fixtureCapabilities(t), nil).ServeHTTP(response, request)
			if response.Code != test.status {
				t.Fatalf("status = %d, want %d", response.Code, test.status)
			}
			if allow := response.Header().Get("Allow"); allow != test.allow {
				t.Fatalf("Allow = %q, want %q", allow, test.allow)
			}
		})
	}
}

type authServiceStub struct {
	authenticate func(context.Context, credentials.AccessToken) (state.Principal, error)
	revoke       func(context.Context, state.Principal, credentials.CredentialID) error
}

func (authServiceStub) Exchange(
	context.Context,
	credentials.BootstrapToken,
) (auth.IssuedAccessToken, error) {
	panic("unexpected Exchange call")
}

func (s authServiceStub) Authenticate(
	ctx context.Context,
	token credentials.AccessToken,
) (state.Principal, error) {
	if s.authenticate == nil {
		panic("unexpected Authenticate call")
	}
	return s.authenticate(ctx, token)
}

func (s authServiceStub) Revoke(
	ctx context.Context,
	principal state.Principal,
	credentialID credentials.CredentialID,
) error {
	if s.revoke == nil {
		panic("unexpected Revoke call")
	}
	return s.revoke(ctx, principal, credentialID)
}

func assertBearerProblem(
	t *testing.T,
	response *httptest.ResponseRecorder,
	status int,
	code corev1.ProblemCode,
) {
	t.Helper()
	if response.Code != status {
		t.Fatalf("status = %d, want %d: %s", response.Code, status, response.Body.String())
	}
	if authenticate := response.Header().Get("WWW-Authenticate"); authenticate != "Bearer" {
		t.Fatalf("WWW-Authenticate = %q, want Bearer", authenticate)
	}
	var problem corev1.Problem
	if err := json.Unmarshal(response.Body.Bytes(), &problem); err != nil {
		t.Fatal(err)
	}
	if problem.Code != code {
		t.Fatalf("problem code = %q, want %q", problem.Code, code)
	}
}

func assertRevokeStatus(
	t *testing.T,
	handler http.Handler,
	token credentials.AccessToken,
	credentialID credentials.CredentialID,
	status int,
) {
	t.Helper()
	request := httptest.NewRequest(http.MethodDelete, credentialsPath+credentialID.String(), nil)
	request.Header.Set(authorizationHeader, "Bearer "+token.String())
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != status {
		t.Fatalf("status = %d, want %d: %s", response.Code, status, response.Body.String())
	}
}

package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/auth"
	"github.com/tnldotdev/tnl/internal/certificates"
	"github.com/tnldotdev/tnl/internal/credentials"
	"github.com/tnldotdev/tnl/internal/routes"
	"github.com/tnldotdev/tnl/internal/state"
	"github.com/tnldotdev/tnl/pkg/protocol/serverv1"
	"golang.org/x/time/rate"
)

func TestCapabilities(t *testing.T) {
	want := fixtureCapabilities(t)
	handler := NewHandler(want, nil)
	request := httptest.NewRequest(http.MethodGet, capabilitiesPath, nil)
	request.Header.Set(requestIDHeader, "req_client123")
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusOK)
	}
	assertResponseHeaders(t, response, "application/json", "req_client123")

	var got serverv1.Capabilities
	if err := json.Unmarshal(response.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("capabilities = %#v, want %#v", got, want)
	}
}

func TestHealthAndReadiness(t *testing.T) {
	var readinessErr error
	readiness := func(ctx context.Context) error {
		deadline, ok := ctx.Deadline()
		if !ok || time.Until(deadline) <= 0 || time.Until(deadline) > readinessTimeout {
			t.Fatalf("readiness deadline = %v, %t", deadline, ok)
		}
		return readinessErr
	}
	handler := NewHandlerWithServicesAndConfig(
		fixtureCapabilities(t), nil, nil, nil, HandlerConfig{Readiness: readiness},
	)

	request := httptest.NewRequest(http.MethodGet, healthPath, nil)
	request.Header.Set(requestIDHeader, "req_health")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || response.Body.String() != `{"status":"ok"}` {
		t.Fatalf("health status = %d, body = %q", response.Code, response.Body.String())
	}
	assertResponseHeaders(t, response, "application/json", "req_health")

	request = httptest.NewRequest(http.MethodGet, readinessPath, nil)
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || response.Body.String() != `{"checks":{"state":"ok"},"status":"ready"}` {
		t.Fatalf("readiness status = %d, body = %q", response.Code, response.Body.String())
	}

	readinessErr = errors.New("state unavailable")
	request = httptest.NewRequest(http.MethodGet, readinessPath, nil)
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusServiceUnavailable || response.Body.String() != `{"checks":{"state":"failed"},"status":"not_ready"}` {
		t.Fatalf("failed readiness status = %d, body = %q", response.Code, response.Body.String())
	}
}

func TestHealthAndReadinessRequireGET(t *testing.T) {
	for _, path := range []string{healthPath, readinessPath} {
		t.Run(path, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, path, nil)
			response := httptest.NewRecorder()
			NewHandler(fixtureCapabilities(t), nil).ServeHTTP(response, request)
			if response.Code != http.StatusMethodNotAllowed || response.Header().Get("Allow") != http.MethodGet {
				t.Fatalf("status = %d, Allow = %q", response.Code, response.Header().Get("Allow"))
			}
		})
	}
}

func TestRelayMapReturnsConfiguredSelectedRegion(t *testing.T) {
	relayMap := []byte(`{"Regions":{"1":{"RegionID":1}}}`)
	handler := NewHandlerWithServicesAndConfig(
		fixtureCapabilities(t), nil, nil, nil, HandlerConfig{RelayMap: relayMap},
	)
	request := httptest.NewRequest(http.MethodGet, relayMapPath, nil)
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusOK || response.Body.String() != string(relayMap) {
		t.Fatalf("status = %d, body = %q", response.Code, response.Body.String())
	}
	if response.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("Cache-Control = %q", response.Header().Get("Cache-Control"))
	}
}

func TestOIDCTokenExchangeIsBoundedAndRateLimited(t *testing.T) {
	token, credentialID, _, err := credentials.NewAccessToken()
	if err != nil {
		t.Fatal(err)
	}
	service := &oidcAuthServiceStub{issued: auth.IssuedAccessToken{
		Token: token, CredentialID: credentialID, ExpiresAt: time.Now().Add(time.Hour).UTC(),
	}}
	handler := NewHandler(fixtureCapabilities(t), service).(*handler)
	handler.oidcLimit = rate.NewLimiter(0, 1)

	request := httptest.NewRequest(http.MethodPost, oidcExchangePath, strings.NewReader(`{"id_token":"id-token"}`))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || service.token != "id-token" {
		t.Fatalf("status = %d, token = %q, body = %s", response.Code, service.token, response.Body.String())
	}

	request = httptest.NewRequest(http.MethodPost, oidcExchangePath, strings.NewReader(`{"id_token":"id-token"}`))
	request.Header.Set("Content-Type", "application/json")
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusTooManyRequests || service.calls != 1 {
		t.Fatalf("status = %d, calls = %d, body = %s", response.Code, service.calls, response.Body.String())
	}
}

func TestRequestObservation(t *testing.T) {
	internalErr := errors.New("storage unavailable")
	tests := map[string]struct {
		method      string
		path        string
		body        string
		contentType string
		auth        AuthService
		wantStatus  int
		wantOp      Operation
		wantResult  RequestResult
	}{
		"success": {
			method: http.MethodGet, path: capabilitiesPath,
			wantStatus: http.StatusOK, wantOp: OperationCapabilitiesGet, wantResult: RequestSuccess,
		},
		"client error": {
			method: http.MethodPost, path: tokenExchangePath, body: `{}`, contentType: "application/json",
			wantStatus: http.StatusBadRequest, wantOp: OperationTokenExchange, wantResult: RequestClientError,
		},
		"server error": {
			method: http.MethodPost, path: tokenExchangePath,
			body: `{"login_token":"tnl_login_test"}`, contentType: "application/json",
			auth: tokenExchangerFunc(func(context.Context, credentials.LoginToken) (auth.IssuedAccessToken, error) {
				return auth.IssuedAccessToken{}, internalErr
			}),
			wantStatus: http.StatusInternalServerError, wantOp: OperationTokenExchange, wantResult: RequestServerError,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			observer := &recordingObserver{}
			handler := NewHandlerWithServicesAndConfig(
				fixtureCapabilities(t), test.auth, nil, nil, HandlerConfig{Observer: observer},
			)
			request := httptest.NewRequest(test.method, test.path, strings.NewReader(test.body))
			if test.contentType != "" {
				request.Header.Set("Content-Type", test.contentType)
			}
			response := httptest.NewRecorder()

			handler.ServeHTTP(response, request)

			if response.Code != test.wantStatus {
				t.Fatalf("status = %d, want %d", response.Code, test.wantStatus)
			}
			if len(observer.observations) != 1 {
				t.Fatalf("observations = %#v, want one", observer.observations)
			}
			got := observer.observations[0]
			if got.operation != test.wantOp || got.result != test.wantResult || got.duration <= 0 {
				t.Fatalf("observation = %#v, want operation %q and result %q", got, test.wantOp, test.wantResult)
			}
		})
	}
}

func TestOperationNamesAreStableAndDoNotContainResourceIDs(t *testing.T) {
	if got := operationForRequest(http.MethodGet, healthPath); got != OperationHealthGet {
		t.Fatalf("health operation = %q", got)
	}
	if got := operationForRequest(http.MethodGet, readinessPath); got != OperationReadinessGet {
		t.Fatalf("readiness operation = %q", got)
	}
	const want = "routes.heartbeat"
	for _, path := range []string{
		routePathPrefix + "route_first/heartbeat",
		routePathPrefix + "route_second/heartbeat",
	} {
		operation := operationForRequest(http.MethodPost, path)
		if operation != OperationRouteHeartbeat || string(operation) != want || strings.Contains(string(operation), "route_") {
			t.Fatalf("operation for %q = %q, want %q", path, operation, want)
		}
	}
}

func TestUnexpectedAuthErrorIsReportedAndSanitized(t *testing.T) {
	underlying := errors.New("database unavailable")
	wrapped := fmt.Errorf("exchange access token: %w", underlying)
	reporter := &recordingErrorReporter{}
	exchanger := tokenExchangerFunc(func(
		context.Context,
		credentials.LoginToken,
	) (auth.IssuedAccessToken, error) {
		return auth.IssuedAccessToken{}, wrapped
	})
	const credential = "tnl_login_do-not-report"
	request := httptest.NewRequest(
		http.MethodPost,
		tokenExchangePath,
		strings.NewReader(`{"login_token":"`+credential+`"}`),
	)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set(requestIDHeader, "req_authfailure")
	response := httptest.NewRecorder()

	NewHandlerWithServicesAndConfig(
		fixtureCapabilities(t), exchanger, nil, nil, HandlerConfig{ErrorReporter: reporter},
	).ServeHTTP(response, request)

	assertUnexpectedErrorReport(t, reporter, wrapped, underlying, "req_authfailure", OperationTokenExchange)
	assertSanitizedInternalProblem(t, response, "req_authfailure", credential, wrapped.Error())
}

func TestUnknownRouteErrorIsReportedOnceAndSanitized(t *testing.T) {
	underlying := errors.New("database unavailable")
	wrapped := fmt.Errorf("list routes: %w", underlying)
	reporter := &recordingErrorReporter{}
	handler := NewHandlerWithServicesAndConfig(
		fixtureCapabilities(t),
		authenticatingAuthService{AuthService: nil},
		failingListRouteService{RouteService: nil, err: wrapped},
		nil,
		HandlerConfig{ErrorReporter: reporter},
	)
	request := httptest.NewRequest(http.MethodGet, routesPath, nil)
	request.Header.Set(authorizationHeader, "Bearer credential-do-not-report")
	request.Header.Set(requestIDHeader, "req_routefailure")
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	assertUnexpectedErrorReport(t, reporter, wrapped, underlying, "req_routefailure", OperationRoutesList)
	assertSanitizedInternalProblem(t, response, "req_routefailure", "credential-do-not-report", wrapped.Error())
}

func TestDatabaseContentionIsTemporarilyUnavailable(t *testing.T) {
	db, err := sql.Open(
		"sqlite",
		"file:"+filepath.ToSlash(filepath.Join(t.TempDir(), "contention.db"))+"?_busy_timeout=1&_txlock=immediate",
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := db.Exec("CREATE TABLE values_table (value INTEGER)"); err != nil {
		t.Fatal(err)
	}
	tx, err := db.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = tx.Rollback() })
	if _, err := tx.Exec("INSERT INTO values_table VALUES (1)"); err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec("INSERT INTO values_table VALUES (2)")
	if !state.IsDatabaseContention(err) {
		t.Fatalf("expected database contention, got %v", err)
	}

	response := httptest.NewRecorder()
	writeInternalError(response, "req_contention", err)
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusServiceUnavailable)
	}
	var problem serverv1.Problem
	if err := json.Unmarshal(response.Body.Bytes(), &problem); err != nil {
		t.Fatal(err)
	}
	if problem.Code != serverv1.TemporarilyUnavailable {
		t.Fatalf("problem code = %q, want %q", problem.Code, serverv1.TemporarilyUnavailable)
	}
}

func TestCertificateRateLimitResponse(t *testing.T) {
	response := httptest.NewRecorder()
	writeCertificateError(response, "req_test", &certificates.RateLimitError{RetryAt: time.Now().Add(90 * time.Second)})
	if response.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusTooManyRequests)
	}
	retryAfter, err := time.ParseDuration(response.Header().Get("Retry-After") + "s")
	if err != nil || retryAfter < 80*time.Second || retryAfter > 90*time.Second {
		t.Fatalf("Retry-After = %q", response.Header().Get("Retry-After"))
	}
}

func TestCertificateStateResponseIsNotALeaseConflict(t *testing.T) {
	response := httptest.NewRecorder()
	writeCertificateError(response, "req_test", certificates.ErrInvalidState)
	if response.Code != http.StatusPreconditionFailed {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusPreconditionFailed)
	}
	var problem serverv1.Problem
	if err := json.Unmarshal(response.Body.Bytes(), &problem); err != nil {
		t.Fatal(err)
	}
	if problem.Code != serverv1.PreconditionFailed {
		t.Fatalf("code = %q", problem.Code)
	}
}

func TestRequestIDGeneration(t *testing.T) {
	handler := NewHandler(fixtureCapabilities(t), nil)
	pattern := regexp.MustCompile(`^req_[A-Za-z0-9]+$`)

	for name, incoming := range map[string][]string{
		"missing":   nil,
		"invalid":   {"not a request ID"},
		"duplicate": {"req_first", "req_second"},
	} {
		t.Run(name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, capabilitiesPath, nil)
			for _, value := range incoming {
				request.Header.Add(requestIDHeader, value)
			}
			response := httptest.NewRecorder()

			handler.ServeHTTP(response, request)

			requestID := response.Header().Get(requestIDHeader)
			if !pattern.MatchString(requestID) || len(incoming) == 1 && requestID == incoming[0] {
				t.Fatalf("request ID = %q", requestID)
			}
		})
	}
}

func TestProblemResponses(t *testing.T) {
	handler := NewHandler(fixtureCapabilities(t), nil)
	tests := map[string]struct {
		method      string
		path        string
		status      int
		code        serverv1.ProblemCode
		problemType string
		allow       string
	}{
		"unknown path": {
			method:      http.MethodGet,
			path:        "/v1/unknown",
			status:      http.StatusNotFound,
			code:        serverv1.NotFound,
			problemType: "https://tnl.dev/problems/not-found",
		},
		"unsupported method": {
			method:      http.MethodPost,
			path:        capabilitiesPath,
			status:      http.StatusMethodNotAllowed,
			code:        serverv1.InvalidArgument,
			problemType: "https://tnl.dev/problems/method-not-allowed",
			allow:       http.MethodGet,
		},
		"unsupported token method": {
			method:      http.MethodGet,
			path:        tokenExchangePath,
			status:      http.StatusMethodNotAllowed,
			code:        serverv1.InvalidArgument,
			problemType: "https://tnl.dev/problems/method-not-allowed",
			allow:       http.MethodPost,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			request := httptest.NewRequest(test.method, test.path, nil)
			request.Header.Set(requestIDHeader, "req_problem")
			response := httptest.NewRecorder()

			handler.ServeHTTP(response, request)

			if response.Code != test.status {
				t.Fatalf("status = %d, want %d", response.Code, test.status)
			}
			assertResponseHeaders(t, response, "application/problem+json", "req_problem")
			if got := response.Header().Get("Allow"); got != test.allow {
				t.Fatalf("Allow = %q, want %q", got, test.allow)
			}

			var problem serverv1.Problem
			if err := json.Unmarshal(response.Body.Bytes(), &problem); err != nil {
				t.Fatal(err)
			}
			if problem.Status != test.status || problem.Code != test.code || problem.Type != test.problemType {
				t.Fatalf("problem = %#v", problem)
			}
			if problem.RequestId != "req_problem" || problem.Details == nil || len(problem.Details) != 0 {
				t.Fatalf("problem metadata = %#v", problem)
			}
		})
	}
}

func TestCapabilitiesResponseIsBounded(t *testing.T) {
	capabilities := fixtureCapabilities(t)
	capabilities.Transport.RelayProfile = strings.Repeat("x", maxJSONResponseBytes)
	request := httptest.NewRequest(http.MethodGet, capabilitiesPath, nil)
	response := httptest.NewRecorder()

	NewHandler(capabilities, nil).ServeHTTP(response, request)

	if response.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusInternalServerError)
	}
	var problem serverv1.Problem
	if err := json.Unmarshal(response.Body.Bytes(), &problem); err != nil {
		t.Fatal(err)
	}
	if problem.Code != serverv1.Internal {
		t.Fatalf("problem code = %q, want %q", problem.Code, serverv1.Internal)
	}
}

func TestTokenExchange(t *testing.T) {
	login, err := credentials.NewLoginToken()
	if err != nil {
		t.Fatal(err)
	}
	access, credentialID, _, err := credentials.NewAccessToken()
	if err != nil {
		t.Fatal(err)
	}
	expiresAt := time.Date(2026, time.September, 28, 12, 0, 0, 0, time.UTC)
	var received credentials.LoginToken
	exchanger := tokenExchangerFunc(func(
		_ context.Context,
		token credentials.LoginToken,
	) (auth.IssuedAccessToken, error) {
		received = token
		return auth.IssuedAccessToken{
			Token: access, CredentialID: credentialID, ExpiresAt: expiresAt,
		}, nil
	})
	body, err := json.Marshal(serverv1.TokenExchangeRequest{LoginToken: login.String()})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, tokenExchangePath, strings.NewReader(string(body)))
	request.Header.Set("Content-Type", "application/json; charset=utf-8")
	request.Header.Set(requestIDHeader, "req_exchange")
	response := httptest.NewRecorder()

	NewHandler(fixtureCapabilities(t), exchanger).ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d: %s", response.Code, http.StatusOK, response.Body.String())
	}
	assertResponseHeaders(t, response, "application/json", "req_exchange")
	if received != login {
		t.Fatalf("login token = %q, want configured token", received)
	}
	var got serverv1.TokenExchangeResponse
	if err := json.Unmarshal(response.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	want := serverv1.TokenExchangeResponse{
		AccessToken:  access.String(),
		CredentialId: credentialID.String(),
		ExpiresAt:    expiresAt,
		TokenType:    serverv1.Bearer,
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("response = %#v, want %#v", got, want)
	}
}

func TestTokenExchangePersistsUsableAccessToken(t *testing.T) {
	db, err := state.Open(context.Background(), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	login, err := credentials.NewLoginToken()
	if err != nil {
		t.Fatal(err)
	}
	exchange, err := auth.NewService(db, login, auth.DefaultAccessTokenLifetime)
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(serverv1.TokenExchangeRequest{LoginToken: login.String()})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, tokenExchangePath, strings.NewReader(string(body)))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()

	NewHandler(fixtureCapabilities(t), exchange).ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d: %s", response.Code, http.StatusOK, response.Body.String())
	}
	var issued serverv1.TokenExchangeResponse
	if err := json.Unmarshal(response.Body.Bytes(), &issued); err != nil {
		t.Fatal(err)
	}
	credentialID, hash, err := credentials.ParseAccessToken(credentials.AccessToken(issued.AccessToken))
	if err != nil {
		t.Fatal(err)
	}
	if credentialID.String() != issued.CredentialId {
		t.Fatalf("credential ID = %q, want %q", credentialID, issued.CredentialId)
	}
	principal, err := state.AuthenticateAccessCredential(
		context.Background(), db, credentialID, hash, time.Now(),
	)
	if err != nil {
		t.Fatal(err)
	}
	if principal.ID != "principal_local" {
		t.Fatalf("principal ID = %q, want principal_local", principal.ID)
	}
}

func TestTokenExchangeRejectsCredentialsWithoutDisclosure(t *testing.T) {
	login := "tnl_login_do-not-disclose"
	for name, test := range map[string]struct {
		err    error
		status int
		code   serverv1.ProblemCode
	}{
		"unauthenticated": {err: auth.ErrUnauthenticated, status: http.StatusUnauthorized, code: serverv1.Unauthenticated},
		"internal":        {err: errors.New("storage failed"), status: http.StatusInternalServerError, code: serverv1.Internal},
	} {
		t.Run(name, func(t *testing.T) {
			exchanger := tokenExchangerFunc(func(
				context.Context,
				credentials.LoginToken,
			) (auth.IssuedAccessToken, error) {
				return auth.IssuedAccessToken{}, test.err
			})
			request := httptest.NewRequest(
				http.MethodPost,
				tokenExchangePath,
				strings.NewReader(`{"login_token":"`+login+`"}`),
			)
			request.Header.Set("Content-Type", "application/json")
			response := httptest.NewRecorder()

			NewHandler(fixtureCapabilities(t), exchanger).ServeHTTP(response, request)

			if response.Code != test.status {
				t.Fatalf("status = %d, want %d", response.Code, test.status)
			}
			var problem serverv1.Problem
			if err := json.Unmarshal(response.Body.Bytes(), &problem); err != nil {
				t.Fatal(err)
			}
			if problem.Code != test.code || strings.Contains(response.Body.String(), login) {
				t.Fatalf("problem = %s", response.Body.String())
			}
		})
	}
}

func TestTokenExchangeRejectsInvalidRequests(t *testing.T) {
	tests := map[string]struct {
		contentType string
		body        string
		status      int
	}{
		"missing content type": {body: `{}`, status: http.StatusUnsupportedMediaType},
		"wrong content type":   {contentType: "text/plain", body: `{}`, status: http.StatusUnsupportedMediaType},
		"empty object":         {contentType: "application/json", body: `{}`, status: http.StatusBadRequest},
		"unknown field":        {contentType: "application/json", body: `{"login_token":"x","extra":true}`, status: http.StatusBadRequest},
		"trailing value":       {contentType: "application/json", body: `{"login_token":"x"} {}`, status: http.StatusBadRequest},
		"malformed JSON":       {contentType: "application/json", body: `{`, status: http.StatusBadRequest},
		"oversized token":      {contentType: "application/json", body: `{"login_token":"` + strings.Repeat("x", maxCredentialBytes+1) + `"}`, status: http.StatusBadRequest},
		"oversized body":       {contentType: "application/json", body: `{"login_token":"` + strings.Repeat("x", maxJSONRequestBytes) + `"}`, status: http.StatusRequestEntityTooLarge},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, tokenExchangePath, strings.NewReader(test.body))
			if test.contentType != "" {
				request.Header.Set("Content-Type", test.contentType)
			}
			response := httptest.NewRecorder()

			NewHandler(fixtureCapabilities(t), nil).ServeHTTP(response, request)

			if response.Code != test.status {
				t.Fatalf("status = %d, want %d: %s", response.Code, test.status, response.Body.String())
			}
			assertResponseHeaders(t, response, "application/problem+json", response.Header().Get(requestIDHeader))
		})
	}
}

type tokenExchangerFunc func(
	context.Context,
	credentials.LoginToken,
) (auth.IssuedAccessToken, error)

func (f tokenExchangerFunc) Exchange(
	ctx context.Context,
	token credentials.LoginToken,
) (auth.IssuedAccessToken, error) {
	return f(ctx, token)
}

type oidcAuthServiceStub struct {
	issued auth.IssuedAccessToken
	token  string
	calls  int
}

func (*oidcAuthServiceStub) Exchange(
	context.Context,
	credentials.LoginToken,
) (auth.IssuedAccessToken, error) {
	panic("unexpected Exchange call")
}

func (s *oidcAuthServiceStub) ExchangeOIDC(_ context.Context, token string) (auth.IssuedAccessToken, error) {
	s.calls++
	s.token = token
	return s.issued, nil
}

func (*oidcAuthServiceStub) Authenticate(
	context.Context,
	credentials.AccessToken,
) (state.Principal, error) {
	panic("unexpected Authenticate call")
}

func (*oidcAuthServiceStub) Revoke(
	context.Context,
	state.Principal,
	credentials.CredentialID,
) error {
	panic("unexpected Revoke call")
}

func (tokenExchangerFunc) Authenticate(
	context.Context,
	credentials.AccessToken,
) (state.Principal, error) {
	panic("unexpected Authenticate call")
}

func (tokenExchangerFunc) Revoke(
	context.Context,
	state.Principal,
	credentials.CredentialID,
) error {
	panic("unexpected Revoke call")
}

type requestObservation struct {
	operation Operation
	result    RequestResult
	duration  time.Duration
}

type recordingObserver struct {
	observations []requestObservation
}

func (o *recordingObserver) ObserveRequest(operation Operation, result RequestResult, duration time.Duration) {
	o.observations = append(o.observations, requestObservation{
		operation: operation,
		result:    result,
		duration:  duration,
	})
}

type errorReport struct {
	err       error
	requestID string
	operation Operation
}

type recordingErrorReporter struct {
	reports []errorReport
}

func (r *recordingErrorReporter) ReportError(err error, requestID string, operation Operation) {
	r.reports = append(r.reports, errorReport{err: err, requestID: requestID, operation: operation})
}

type authenticatingAuthService struct {
	AuthService
}

func (authenticatingAuthService) Authenticate(
	context.Context,
	credentials.AccessToken,
) (state.Principal, error) {
	return state.Principal{ID: "principal_test"}, nil
}

type failingListRouteService struct {
	RouteService
	err error
}

func (s failingListRouteService) List(context.Context, string) ([]routes.Route, error) {
	return nil, s.err
}

func assertUnexpectedErrorReport(
	t *testing.T,
	reporter *recordingErrorReporter,
	wantErr, underlying error,
	requestID string,
	operation Operation,
) {
	t.Helper()
	if len(reporter.reports) != 1 {
		t.Fatalf("error reports = %#v, want one", reporter.reports)
	}
	got := reporter.reports[0]
	if got.err != wantErr || !errors.Is(got.err, underlying) {
		t.Fatalf("reported error = %v, want wrapped error %v", got.err, wantErr)
	}
	if got.requestID != requestID || got.operation != operation {
		t.Fatalf("error report = %#v, want request ID %q and operation %q", got, requestID, operation)
	}
}

func assertSanitizedInternalProblem(
	t *testing.T,
	response *httptest.ResponseRecorder,
	requestID string,
	forbidden ...string,
) {
	t.Helper()
	if response.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusInternalServerError)
	}
	assertResponseHeaders(t, response, "application/problem+json", requestID)
	var problem serverv1.Problem
	if err := json.Unmarshal(response.Body.Bytes(), &problem); err != nil {
		t.Fatal(err)
	}
	want := serverv1.Problem{
		Type:      "https://tnl.dev/problems/internal",
		Title:     "Internal server error",
		Status:    http.StatusInternalServerError,
		Code:      serverv1.Internal,
		RequestId: requestID,
		Details:   map[string]interface{}{},
	}
	if !reflect.DeepEqual(problem, want) {
		t.Fatalf("problem = %#v, want %#v", problem, want)
	}
	for _, value := range forbidden {
		if strings.Contains(response.Body.String(), value) {
			t.Fatalf("problem response disclosed %q: %s", value, response.Body.String())
		}
	}
}

func fixtureCapabilities(t *testing.T) serverv1.Capabilities {
	t.Helper()
	data, err := os.ReadFile("../../api/fixtures/server/v1/capabilities.json")
	if err != nil {
		t.Fatal(err)
	}
	var capabilities serverv1.Capabilities
	if err := json.Unmarshal(data, &capabilities); err != nil {
		t.Fatal(err)
	}
	return capabilities
}

func assertResponseHeaders(
	t *testing.T,
	response *httptest.ResponseRecorder,
	contentType string,
	requestID string,
) {
	t.Helper()
	for header, want := range map[string]string{
		"Cache-Control":          "no-store",
		"Content-Type":           contentType,
		requestIDHeader:          requestID,
		"X-Content-Type-Options": "nosniff",
	} {
		if got := response.Header().Get(header); got != want {
			t.Fatalf("%s = %q, want %q", header, got, want)
		}
	}
}

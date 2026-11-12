package authority

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/control/oidc"
	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/security/credentials"
	authorityv1 "github.com/tnldotdev/tnl/pkg/api/control/authority/v1"
	"go.opentelemetry.io/otel/trace"
)

func TestAuthorityFailuresPreserveRequestContext(t *testing.T) {
	cause := errors.New("private-provider-material")
	store := &authorityContextFailureStore{err: cause}
	h := &handler{store: store, oidc: &oidc.Server{}, workloads: &oidc.WorkloadVerifier{}}
	for _, test := range []struct {
		name, body, title string
		handle            func(http.ResponseWriter, *http.Request)
		status            int
		code              authorityv1.ProblemCode
		reason            failure.Reason
	}{
		{
			name: "authentication handler", title: "authentication is unavailable",
			handle: func(w http.ResponseWriter, r *http.Request) { h.authenticateControlRequest(w, r) },
			status: http.StatusServiceUnavailable, code: authorityv1.Unavailable, reason: failure.ServerAPIInternal,
		},
		{
			name: "missing authentication store", title: "authentication is unavailable",
			handle: func(w http.ResponseWriter, r *http.Request) { (&handler{}).authenticateControlRequest(w, r) },
			status: http.StatusServiceUnavailable, code: authorityv1.Unavailable, reason: failure.ServerAPIInternal,
		},
		{
			name: "state helper", title: "internal server error",
			handle: func(w http.ResponseWriter, r *http.Request) {
				writeControlStateProblem(r.Context(), w, "create team", cause)
			},
			status: http.StatusInternalServerError, code: authorityv1.Internal, reason: failure.ServerAPIInternal,
		},
		{
			name: "disabled device handler", title: "authentication is unavailable",
			handle: (&handler{}).StartDeviceLogin,
			status: http.StatusServiceUnavailable, code: authorityv1.Unavailable, reason: failure.ServerAPIInternal,
		},
		{
			name: "device storage handler", body: `{}`, title: "authentication is unavailable",
			handle: h.StartDeviceLogin,
			status: http.StatusServiceUnavailable, code: authorityv1.Unavailable, reason: failure.ServerAPIInternal,
		},
		{
			name: "device provider helper", title: "identity provider is unavailable; reopen the approval URL to retry",
			handle: func(w http.ResponseWriter, r *http.Request) {
				h.deviceError(r.Context(), w, fmt.Errorf("%w: %w", oidc.ErrUnavailable, cause))
			},
			status: http.StatusServiceUnavailable, code: authorityv1.Unavailable, reason: failure.ServerIdentityProviderUnavailable,
		},
		{
			name: "publisher enrollment handler", title: "authentication is unavailable",
			body:   `{"enrollment_key":"enrollment-secret","public_key":"` + base64.RawURLEncoding.EncodeToString(make([]byte, ed25519.PublicKeySize)) + `"}`,
			handle: h.RedeemPublisherEnrollment,
			status: http.StatusServiceUnavailable, code: authorityv1.Unavailable, reason: failure.ServerAPIInternal,
		},
		{
			name: "environment visitor renewal handler", title: "internal server error",
			body: `{"sequence":1,"signature":"` + base64.RawURLEncoding.EncodeToString(make([]byte, ed25519.SignatureSize)) + `"}`,
			handle: func(w http.ResponseWriter, r *http.Request) {
				h.RenewEnvironmentVisitorSession(w, r, "visitor-session")
			},
			status: http.StatusInternalServerError, code: authorityv1.Internal, reason: failure.ServerAPIInternal,
		},
		{
			name: "company state helper", title: "internal server error",
			handle: func(w http.ResponseWriter, r *http.Request) {
				companyError(r.Context(), w, "read company connections", cause)
			},
			status: http.StatusInternalServerError, code: authorityv1.Internal, reason: failure.ServerAPIInternal,
		},
		{
			name: "company provider helper", title: "authentication is unavailable",
			handle: func(w http.ResponseWriter, r *http.Request) {
				companyError(r.Context(), w, "verify human request", fmt.Errorf("%w: %w", oidc.ErrUnavailable, cause))
			},
			status: http.StatusServiceUnavailable, code: authorityv1.Unavailable, reason: failure.ServerAPIInternal,
		},
		{
			name: "service state helper", title: "internal server error",
			handle: func(w http.ResponseWriter, r *http.Request) {
				serviceAccessError(r.Context(), w, "get website service", cause)
			},
			status: http.StatusInternalServerError, code: authorityv1.Internal, reason: failure.ServerAPIInternal,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			var logs bytes.Buffer
			previous := log.Writer()
			log.SetOutput(&logs)
			t.Cleanup(func() { log.SetOutput(previous) })
			span := trace.NewSpanContext(trace.SpanContextConfig{
				TraceID: trace.TraceID{1}, SpanID: trace.SpanID{2}, TraceFlags: trace.FlagsSampled,
			})
			ctx := trace.ContextWithSpanContext(t.Context(), span)
			request := httptest.NewRequestWithContext(ctx, http.MethodPost, "/", strings.NewReader(test.body))
			request.Header.Set("Authorization", "Bearer access-token-secret")
			// the recorder has no request context; correlation must come from request.
			response := httptest.NewRecorder()
			test.handle(response, request)
			var problem authorityv1.Problem
			if err := json.Unmarshal(response.Body.Bytes(), &problem); err != nil {
				t.Fatal(err)
			}
			if response.Code != test.status || response.Header().Get("Content-Type") != "application/problem+json" ||
				problem.Code != test.code || problem.Title != test.title || problem.Detail != test.title || problem.RequestId == "" {
				t.Fatalf("problem contract changed: %d %s", response.Code, response.Body.String())
			}
			for _, field := range []string{
				"request_id=" + problem.RequestId, "reason=" + string(test.reason),
				"trace_id=" + span.TraceID().String(), "span_id=" + span.SpanID().String(),
			} {
				if !strings.Contains(logs.String(), field) {
					t.Errorf("log lost request context %q: %s", field, logs.String())
				}
			}
			for _, secret := range []string{cause.Error(), "access-token-secret", "enrollment-secret"} {
				if strings.Contains(response.Body.String(), secret) || strings.Contains(logs.String(), secret) {
					t.Errorf("problem or operator log exposed %q", secret)
				}
			}
			if strings.Contains(response.Body.String(), span.TraceID().String()) || strings.Contains(response.Body.String(), span.SpanID().String()) {
				t.Fatal("HTTP problem exposed internal trace identifiers")
			}
		})
	}
}

type authorityContextFailureStore struct {
	Store
	err error
}

func (s *authorityContextFailureStore) AuthenticateAccessToken(context.Context, credentials.AccessToken, time.Time) (controlstate.ControlPrincipal, error) {
	return controlstate.ControlPrincipal{}, s.err
}

func (s *authorityContextFailureStore) CreateDeviceLogin(context.Context, controlstate.DeviceLoginOptions, time.Time) (controlstate.DeviceLogin, string, error) {
	return controlstate.DeviceLogin{}, "", s.err
}

func (s *authorityContextFailureStore) RedeemPublisherEnrollment(context.Context, string, ed25519.PublicKey, time.Time) (controlstate.PublisherIdentity, error) {
	return controlstate.PublisherIdentity{}, s.err
}

func (s *authorityContextFailureStore) RenewEnvironmentVisitorSession(context.Context, string, string, controlstate.WorkloadRenewal, time.Time) (controlstate.WorkloadSession, error) {
	return controlstate.WorkloadSession{}, s.err
}

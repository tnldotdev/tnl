package public

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type publisherAuthenticationErrors struct {
	PublisherIdentityStore
	err   error
	calls int
}

func (s *publisherAuthenticationErrors) AuthenticatePublisherAccess(context.Context, string, string, time.Time) (controlstate.PublisherIdentity, error) {
	s.calls++
	return controlstate.PublisherIdentity{}, s.err
}

func TestPublisherAuthenticationHTTPSeparatesDenialOutageAndFault(t *testing.T) {
	outage := &pgconn.PgError{Code: "57P03", Message: "private database credential"}
	fault := errors.New("private independent cleanup fault")
	for _, test := range []struct {
		name   string
		err    error
		status int
		code   controlv1.ProblemCode
	}{
		{"invalid", controlstate.ErrPublisherIdentity, 401, controlv1.Unauthenticated},
		{"permission", controlstate.ErrServiceAccess, 403, controlv1.Forbidden},
		{"permission with fault", errors.Join(controlstate.ErrServiceAccess, fault), 500, controlv1.Internal},
		{"known outage", fmt.Errorf("authentication: %w", outage), 503, controlv1.Unavailable},
		{"protocol fault", &pgconn.PgError{Code: "08P01", Message: "private database protocol fault"}, 500, controlv1.Internal},
		{"unexpected", fault, 500, controlv1.Internal},
		{"outage with fault", errors.Join(outage, fault), 500, controlv1.Internal},
		{"invalid with fault", errors.Join(controlstate.ErrPublisherIdentity, fault), 500, controlv1.Internal},
		{"canceled with fault", errors.Join(context.Canceled, fault), 500, controlv1.Internal},
	} {
		t.Run(test.name, func(t *testing.T) {
			store := &publisherAuthenticationErrors{err: test.err}
			h, err := NewHandler(Config{}, Stores{PublisherIdentities: store}, nil, nil)
			if err != nil {
				t.Fatal(err)
			}
			request := httptest.NewRequest(http.MethodGet, "/v1/publisher/services/svc_"+strings.Repeat("A", 22), nil)
			request.Header.Set("Authorization", "Bearer private-publisher-token")
			response := httptest.NewRecorder()
			h.ServeHTTP(response, request)
			var problem controlv1.Problem
			if response.Code != test.status || store.calls != 1 || json.Unmarshal(response.Body.Bytes(), &problem) != nil || problem.Code != test.code {
				t.Fatalf("publisher authentication status=%d calls=%d body=%s", response.Code, store.calls, response.Body.String())
			}
			for _, secret := range []string{"private-publisher-token", "private database", "private independent"} {
				if strings.Contains(response.Body.String(), secret) {
					t.Fatal("publisher authentication disclosed a private cause")
				}
			}
			if (response.Header().Get("WWW-Authenticate") != "") != (test.status == 401) {
				t.Fatal("permission or infrastructure fault became a credential challenge")
			}
		})
	}
}

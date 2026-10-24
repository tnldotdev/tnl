package public

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	"github.com/tnldotdev/tnl/internal/observability"
	"github.com/tnldotdev/tnl/internal/policy/visitorscope"
	"github.com/tnldotdev/tnl/internal/security/visitortoken"
)

type visitorPreparationStore struct {
	PublicURLStore
	err error
}

func (s visitorPreparationStore) IssueVisitorToken(_ context.Context, _ string, scope visitorscope.Scope, _ controlstate.VisitorTokenSource, now time.Time) (controlstate.IssuedVisitorToken, error) {
	if s.err != nil {
		return controlstate.IssuedVisitorToken{}, s.err
	}
	return controlstate.IssuedVisitorToken{Token: visitortoken.Token("signed.visitor.permission"), Permission: visitortoken.Permission{Scope: scope, Hostname: "service.example.test", Port: 25443, VisitorPolicyRevision: 1, ExpiresAt: now.Add(time.Minute)}}, nil
}

func (visitorPreparationStore) CreateVisitorGrantCredentials(context.Context, string, visitorscope.Scope, string, time.Time, time.Time) (controlstate.VisitorGrantCredentials, error) {
	return controlstate.VisitorGrantCredentials{}, errors.New("unexpected credential creation")
}

func (visitorPreparationStore) IssueVisitorClientCertificate(context.Context, string, visitorscope.Scope, controlstate.VisitorTokenSource, []byte, time.Time) (controlstate.ServiceClientCertificate, error) {
	return controlstate.ServiceClientCertificate{}, errors.New("unexpected certificate issuance")
}

func TestVisitorPreparationMetricsDistinguishDenialFromInfrastructureFailure(t *testing.T) {
	for _, test := range []struct {
		name, outcome string
		err           error
		status        int
	}{
		{"issued", "success", nil, 200},
		{"denied", "denied", controlstate.ErrVisitorPermission, 403},
		{"signing unavailable", "error", errors.New("secret database cause"), 500},
	} {
		t.Run(test.name, func(t *testing.T) {
			metrics := observability.New("control")
			h := &handler{store: visitorPreparationStore{err: test.err}}
			mux := http.NewServeMux()
			mux.HandleFunc("POST /visitor-token", h.IssueVisitorToken)
			r := httptest.NewRequest("POST", "/visitor-token", strings.NewReader(`{"resource":{"kind":"service","id":"svc_0123456789abcdefghijkl"},"source":{"kind":"browser_session","secret":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}}`))
			r.Header.Set("Content-Type", "application/json")
			response := httptest.NewRecorder()
			metrics.APIRequests("control", mux).ServeHTTP(response, r)
			if response.Code != test.status {
				t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
			}
			w := httptest.NewRecorder()
			metrics.Handler().ServeHTTP(w, httptest.NewRequest("GET", "/metrics", nil))
			text := w.Body.String()
			if !strings.Contains(text, `tnl_outcome="`+test.outcome+`"`) || strings.Contains(text, "secret") || strings.Contains(text, "signed.visitor.permission") {
				t.Fatal("preparation metric lost its result or leaked credential/cause")
			}
			if test.err == nil && !strings.Contains(text, `tnl_authorization_decisions_total{tnl_operation="visitor_token.issue",tnl_outcome="success"} 1`) {
				t.Fatal("successful prepared permission was not observed")
			}
		})
	}
}

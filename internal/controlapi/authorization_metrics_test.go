package controlapi

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/controlstate"
	"github.com/tnldotdev/tnl/internal/observability"
)

type connectorDecisionStore struct {
	PublicURLStore
	allowed  bool
	admitted bool
	err      error
}

func (s connectorDecisionStore) AuthorizeVisitorServiceConnector(context.Context, string, string, string, int64, controlstate.SubjectConnectorVisitor, time.Time) (controlstate.PrivateVisitorValidity, error) {
	return controlstate.PrivateVisitorValidity{Allowed: s.allowed, Admitted: s.admitted, ValidUntil: time.Now().Add(time.Minute)}, s.err
}

func TestConnectorDecisionMetricsDistinguishHTTP200DenialAndStateFailure(t *testing.T) {
	for _, test := range []struct {
		name, outcome string
		allowed       bool
		admitted      bool
		err           error
		status        int
	}{
		{"allowed and admitted", "success", true, true, nil, 200},
		{"allowed not admitted", "rejected", true, false, nil, 200},
		{"denied", "denied", false, false, nil, 200},
		{"state failure", "error", false, false, errors.New("secret database cause"), 500},
	} {
		t.Run(test.name, func(t *testing.T) {
			metrics := observability.New("control")
			h := &handler{store: connectorDecisionStore{allowed: test.allowed, admitted: test.admitted, err: test.err}}
			mux := http.NewServeMux()
			mux.HandleFunc("POST /service/{service}/run/{run}", func(w http.ResponseWriter, r *http.Request) {
				h.AuthorizeServiceConnector(w, r, r.PathValue("service"), r.PathValue("run"))
			})
			r := httptest.NewRequest("POST", "/service/private-service/run/private-run", strings.NewReader(`{"run_number":1,"grant_revision":1,"source_ip":"192.0.2.7","connector_session_id":"private-session","subject":{"kind":"workload_session","workload_session_id":"wls_aaaaaaaaaaaaaaaaaaaaaa"},"visitor_connection_id":"private-visitor"}`))
			r.Header.Set("Content-Type", "application/json")
			r.Header.Set("Authorization", "Bearer private-token")
			response := httptest.NewRecorder()
			metrics.APIRequests("control", mux).ServeHTTP(response, r)
			if response.Code != test.status {
				t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
			}
			w := httptest.NewRecorder()
			metrics.Handler().ServeHTTP(w, httptest.NewRequest("GET", "/metrics", nil))
			text := w.Body.String()
			if !strings.Contains(text, `tnl_outcome="`+test.outcome+`"`) {
				t.Fatal("missing semantic request outcome", test.outcome)
			}
			if test.err == nil {
				labels := `tnl_operation="service_connector",tnl_outcome="` + test.outcome + `"`
				if test.allowed && !test.admitted {
					labels += `,tnl_reason="not_admitted"`
				}
				if !strings.Contains(text, `tnl_authorization_decisions_total{`+labels+`} 1`) {
					t.Fatal("missing handler decision")
				}
			}
			if strings.Contains(text, "private-") || strings.Contains(text, "secret") {
				t.Fatal("decision metrics leaked request identities or state failure cause")
			}
		})
	}
}

package public

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	"github.com/tnldotdev/tnl/internal/observability"
)

type certificateDecisionStore struct {
	PublicURLStore
	allowed  bool
	admitted bool
	err      error
}

func (s certificateDecisionStore) AuthorizeServiceClientCertificate(context.Context, string, string, string, string, int64, netip.Addr, []byte, time.Time) (controlstate.ServiceVisitorValidity, error) {
	return controlstate.ServiceVisitorValidity{Allowed: s.allowed, Admitted: s.admitted, ValidUntil: time.Now().Add(time.Minute)}, s.err
}

func TestCertificateDecisionMetricsDistinguishHTTP200DenialAndStateFailure(t *testing.T) {
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
			h := &handler{store: certificateDecisionStore{allowed: test.allowed, admitted: test.admitted, err: test.err}}
			mux := http.NewServeMux()
			mux.HandleFunc("POST /service/{service}/run/{run}", func(w http.ResponseWriter, r *http.Request) {
				h.AuthorizeServiceClientCertificate(w, r, r.PathValue("service"), r.PathValue("run"))
			})
			r := httptest.NewRequest("POST", "/service/service/run/service-run", strings.NewReader(`{"run_number":1,"source_ip":"192.0.2.7","visitor_connection_id":"private-visitor","certificate":"Y2VydA=="}`))
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
				labels := `tnl_operation="service_client_certificate",tnl_outcome="` + test.outcome + `"`
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

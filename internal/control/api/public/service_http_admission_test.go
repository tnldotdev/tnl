package public

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	"github.com/tnldotdev/tnl/internal/security/credentials"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type httpAdmissionStore struct {
	ServiceHTTPStore
	auth    controlstate.ServiceHTTPRun
	visitor string
	source  netip.Addr
	port    int
	calls   int
	err     error
}

func (s *httpAdmissionStore) AuthorizeServiceHTTPVisitor(_ context.Context, auth controlstate.ServiceHTTPRun, visitor string, source netip.Addr, port int, now time.Time) (controlstate.ServiceVisitorValidity, error) {
	s.auth, s.visitor, s.source, s.port = auth, visitor, source, port
	s.calls++
	return controlstate.ServiceVisitorValidity{Allowed: true, Admitted: false, ValidUntil: now.Add(time.Minute)}, s.err
}

func TestServiceHTTPAdmissionRequiresRunBearerAndExactSourceAndPort(t *testing.T) {
	for _, test := range []struct {
		name, bearer, source string
		port                 int
		err                  error
		status, calls        int
	}{
		{"authorized pending", "run-secret", "192.0.2.7", 443, nil, 200, 1},
		{"missing bearer", "", "192.0.2.7", 443, nil, 401, 0},
		{"source with zone", "run-secret", "fe80::1%en0", 443, nil, 400, 0},
		{"wrong port", "run-secret", "192.0.2.7", 25443, nil, 400, 0},
		{"state denial", "run-secret", "192.0.2.7", 443, controlstate.ErrServiceAccess, 404, 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			store := &httpAdmissionStore{err: test.err}
			h := &handler{dependencies: Stores{ServiceHTTP: store}}
			body := fmt.Sprintf(`{"run_number":"7","visitor_connection_id":"vc_%s","source_ip":%q,"destination_port":%d}`, strings.Repeat("V", 22), test.source, test.port)
			r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
			r.Header.Set("Content-Type", "application/json")
			if test.bearer != "" {
				r.Header.Set("Authorization", "Bearer "+test.bearer)
			}
			response := httptest.NewRecorder()
			h.AuthorizeServiceHTTPVisitor(response, r, "service", "run")
			if response.Code != test.status || store.calls != test.calls || response.Header().Get("Cache-Control") != "no-store" {
				t.Fatal("HTTP admission boundary changed", response.Code, store.calls, response.Body.String())
			}
			if store.calls != 0 && (store.auth.Subject.ID != "service" || store.auth.RunID != "run" || store.auth.Number != 7 || store.auth.Token != credentials.ServiceRunToken(test.bearer) || store.visitor != "vc_"+strings.Repeat("V", 22) || store.source.String() != test.source || store.port != test.port) {
				t.Fatal("HTTP admission changed the exact publisher or visitor facts")
			}
			if response.Code == 200 {
				var result controlv1.ServiceClientCertificateDecision
				if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil || !result.Allowed || result.Admitted || result.ValidUntil.IsZero() {
					t.Fatal("HTTP admission lost the shared decision facts", result, err)
				}
			}
		})
	}
}

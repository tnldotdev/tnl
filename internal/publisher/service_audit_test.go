package publisher

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"

	"github.com/tnldotdev/tnl/internal/observability/serviceaudit"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

type auditSinkFunc func(serviceaudit.Observation) bool

func (f auditSinkFunc) Observe(o serviceaudit.Observation) bool { return f(o) }

func TestHTTPServiceAuditRecordsFinalAuthorizationWithoutRequestSecrets(t *testing.T) {
	const urlID = "url_0123456789ABCDEFGHIJKL"
	const runID = "pr_0123456789ABCDEFGHIJKL"
	const visitorID = "vc_0123456789ABCDEFGHIJKL"
	var events []serviceaudit.Observation
	forwarded := 0
	route, err := newTestPublicURLServer(t, PublicURLServerConfig{Hostname: "route.example", PublicURLID: urlID, PublishRunID: runID, PublishRunNumber: 1,
		AuditSink: auditSinkFunc(func(o serviceaudit.Observation) bool { events = append(events, o); return true }),
		Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			forwarded++
			if len(events) != 1 || events[0].Outcome != "allowed" {
				t.Error("audit waited for application completion")
			}
			w.WriteHeader(204)
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer route.Close()
	for _, denied := range []bool{false, true} {
		r := httptest.NewRequest("GET", "/private-secret?token=secret", nil)
		r.Host = "route.example"
		r.TLS = &tls.ConnectionState{ServerName: "route.example"}
		r.Header.Set("Authorization", "Bearer never-audit-this")
		r.Header.Set("Cookie", "secret=never-audit-this")
		if denied {
			r.Header.Set(visitorTokenHeader, "invalid-visitor-token")
		}
		r = r.WithContext(context.WithValue(r.Context(), denialContextKey{}, denied))
		r = r.WithContext(context.WithValue(r.Context(), visitorSessionKey{}, &visitorSession{visitor: Visitor{Run: route.run, Header: tunnelv1.VisitorStreamHeader{VisitorConnectionID: visitorID}, Source: netip.MustParseAddrPort("192.0.2.7:1234")}}))
		w := httptest.NewRecorder()
		serveTestPublicRequest(t, route, w, r)
		if denied && w.Code != 403 || !denied && w.Code != 204 {
			t.Fatalf("status %d", w.Code)
		}
	}
	if forwarded != 1 || len(events) != 2 || events[1].Outcome != "denied" || events[1].Reason != "authorization" {
		t.Fatalf("wrong decision boundary: %+v", events)
	}
	for _, e := range events {
		if e.Validate() != nil || e.SourceIP != "192.0.2.7" || e.VisitorConnectionID != visitorID {
			t.Fatalf("wrong correlation: %+v", e)
		}
		encoded, _ := json.Marshal(e)
		for _, secret := range []string{"private-secret", "token=secret", "never-audit-this"} {
			if strings.Contains(string(encoded), secret) {
				t.Fatal("request secret in audit")
			}
		}
	}
}

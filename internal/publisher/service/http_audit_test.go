package service

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/observability/serviceaudit"
	"github.com/tnldotdev/tnl/internal/publisher/httpaccess"
)

func TestServiceHTTPAuditUsesOnlyRunAndDecisionFacts(t *testing.T) {
	for _, h2 := range []bool{false, true} {
		name := "http1"
		if h2 {
			name = "http2"
		}
		t.Run(name, func(t *testing.T) {
			events := make(chan serviceaudit.Observation, 8)
			client, _, _, token := serviceHTTPApplicationFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// the authorization decision is reported before application work.
				if len(events) != 1 {
					t.Error("request decision waited for the application")
				}
				_, _ = io.Copy(w, r.Body)
			}), h2, true, connectorAuditSink(func(o serviceaudit.Observation) bool { events <- o; return true }))
			for _, test := range []struct {
				path, credential, outcome, reason string
				status                            int
			}{
				{"/private-path?query=private-query", "", "denied", "authorization", http.StatusForbidden},
				{"/private-path", "invalid-secret", "denied", "authorization", http.StatusForbidden},
				{"/__tnl/unknown", token.Reveal(), "", "", http.StatusForbidden},
				{"/private-path", token.Reveal(), "allowed", "", http.StatusOK},
			} {
				request, err := http.NewRequestWithContext(t.Context(), http.MethodPost, "https://preview.example.test"+test.path, strings.NewReader("private-body"))
				if err != nil {
					t.Fatal(err)
				}
				request.Header.Set("Authorization", "application-secret")
				if test.credential != "" {
					request.Header.Set(httpaccess.VisitorTokenHeader, test.credential)
				}
				response, err := client.Do(request)
				if err != nil {
					t.Fatal(err)
				}
				_, _ = io.Copy(io.Discard, response.Body)
				_ = response.Body.Close()
				if response.StatusCode != test.status {
					t.Fatalf("HTTP decision for %s: %s, want %d", test.path, response.Status, test.status)
				}
				if test.outcome == "" {
					if len(events) != 0 {
						t.Fatal("browser preparation claimed an application decision")
					}
					continue
				}
				var event serviceaudit.Observation
				select {
				case event = <-events:
				case <-time.After(5 * time.Second):
					t.Fatal("request decision was not reported")
				}
				if event.Validate() != nil || event.ServiceKind != "service" || event.ServiceID != "svc_"+strings.Repeat("A", 22) ||
					event.RunID != "srun_"+strings.Repeat("R", 22) || event.RunNumber != 1 || event.SourceIP != "192.0.2.1" ||
					event.VisitorConnectionID != "vc_"+strings.Repeat("V", 22) || event.Outcome != test.outcome || event.Reason != test.reason || len(events) != 0 {
					t.Fatal("HTTP decision lost its exact run, source, or outcome", event)
				}
				encoded, err := json.Marshal(event)
				if err != nil {
					t.Fatal(err)
				}
				for _, secret := range []string{"private-path", "private-query", "private-body", "application-secret", "invalid-secret", token.Reveal()} {
					if strings.Contains(string(encoded), secret) {
						t.Fatal("HTTP audit retained application data or a credential")
					}
				}
			}
		})
	}
}

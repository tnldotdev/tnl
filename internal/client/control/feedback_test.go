package control

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/tnldotdev/tnl/internal/security/credentials"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestReviewerFeedbackClientUsesExactServiceRun(t *testing.T) {
	const service, run = "svc_example", "srun_example"
	const token = credentials.ServiceRunToken("publisher-service-run-token")
	for _, operation := range []string{"read", "report", "reply", "thread.resolved", "thread.reopened"} {
		t.Run(operation, func(t *testing.T) {
			calls := 0
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				if r.Method != http.MethodPost || r.URL.Path != "/v1/services/"+service+"/runs/"+run+"/feedback/authorization" || r.Header.Get("Authorization") != "Bearer "+token.String() || r.Header.Get("Idempotency-Key") != "" {
					t.Error("authorization escaped its run")
				}
				var body map[string]json.RawMessage
				if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
					t.Error(err)
				}
				if string(body["run_number"]) != `"7"` || string(body["operation"]) != `"`+operation+`"` || len(body) != 4 {
					t.Error("content or wrong run in authorization", body)
				}
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{}`))
			}))
			defer server.Close()
			client, err := New(server.URL, server.Client(), "person-control-token")
			if err != nil {
				t.Fatal(err)
			}
			_, err = client.AuthorizeReviewerFeedback(t.Context(), service, run, controlv1.AuthorizeReviewerFeedbackRequest{PreviewId: "pv_example", RunNumber: 7, Operation: controlv1.FeedbackOperation(operation)}, token)
			if err != nil || calls != 1 {
				t.Fatal(calls, err)
			}
		})
	}
}

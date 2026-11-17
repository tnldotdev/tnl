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
	const service, run, feedback = "svc_example", "srun_example", "fb_example"
	const token = credentials.ServiceRunToken("publisher-service-run-token")
	for _, test := range []struct {
		name, suffix, key string
		call              func(*Client) error
	}{
		{"report", "", "report-key", func(c *Client) error {
			_, err := c.CreateFeedbackReport(t.Context(), service, run, "report-key", controlv1.CreateFeedbackReportRequest{RunNumber: 7}, token)
			return err
		}},
		{"page", "/query", "", func(c *Client) error {
			_, err := c.ListPreviewPageFeedback(t.Context(), service, run, controlv1.PreviewPageFeedbackRequest{RunNumber: 7}, token)
			return err
		}},
		{"append", "/" + feedback + "/events", "event-key", func(c *Client) error {
			_, err := c.AppendReviewerFeedbackEvent(t.Context(), service, run, feedback, "event-key", controlv1.AppendReviewerFeedbackEventRequest{RunNumber: 7}, token)
			return err
		}},
		{"thread", "/" + feedback + "/query", "", func(c *Client) error {
			_, err := c.GetReviewerFeedbackThread(t.Context(), service, run, feedback, controlv1.ReviewerFeedbackReadRequest{RunNumber: 7}, token)
			return err
		}},
		{"events", "/" + feedback + "/events/query", "", func(c *Client) error {
			_, err := c.ListReviewerFeedbackEvents(t.Context(), service, run, feedback, controlv1.ReviewerFeedbackReadRequest{RunNumber: 7}, token)
			return err
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			calls := 0
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				if r.Method != http.MethodPost || r.URL.Path != "/v1/services/"+service+"/runs/"+run+"/feedback"+test.suffix ||
					r.Header.Get("Authorization") != "Bearer "+token.String() || r.Header.Get("Idempotency-Key") != test.key {
					t.Errorf("unexpected feedback request: %s %s, headers %v", r.Method, r.URL, r.Header)
				}
				var body map[string]json.RawMessage
				if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
					t.Error(err)
				}
				if string(body["run_number"]) != `"7"` || body["publish_run_number"] != nil {
					t.Errorf("feedback run fields = %v", body)
				}
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{}`))
			}))
			defer server.Close()
			client, err := New(server.URL, server.Client(), "person-control-token")
			if err != nil {
				t.Fatal(err)
			}
			if err := test.call(client); err != nil || calls != 1 {
				t.Fatalf("feedback request: %d calls, %v", calls, err)
			}
		})
	}
}

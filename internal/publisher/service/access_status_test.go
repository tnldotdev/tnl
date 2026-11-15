package service

import (
	"encoding/json"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/publisher/httpaccess"
	publisherv1 "github.com/tnldotdev/tnl/pkg/api/publisher/browser/v1"
)

func TestBrowserAccessStatusSharesTheForwardingDecision(t *testing.T) {
	var forwarded atomic.Int32
	var frontend HTTP
	client, policy, update, _ := serviceHTTPConfiguredFixture(t, http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		forwarded.Add(1)
		response.WriteHeader(http.StatusNoContent)
	}), false, true, func(f *HTTP) {
		f.PreviewID = "pv_0123456789abcdefghijkl"
		f.Number, f.Header.RunNumber = 2, 2
		frontend = *f
	})
	for _, denied := range []bool{true, false} {
		update.Anonymous = !denied
		update.View.VisitorPolicyRevision++
		now := time.Now()
		update.View.ObservedAt, update.View.ValidUntil = now, now.Add(10*time.Second)
		if err := policy.Apply(policy.Begin(), update); err != nil {
			t.Fatal(err)
		}
		cookie := ""
		if denied {
			cookie = httpaccess.VisitorTokenCookie + "=invalid-visitor-token"
		}
		for _, path := range []string{"/__tnl/access", "/"} {
			response, body := feedbackVisit(t, client, http.MethodGet, path, cookie)
			status := http.StatusForbidden
			if !denied {
				status = http.StatusNoContent
				if path == "/__tnl/access" {
					status = http.StatusOK
				}
			}
			if response.StatusCode != status {
				t.Fatal("browser access and forwarding decisions diverged", path, response.StatusCode, status)
			}
			if path == "/__tnl/access" {
				var result publisherv1.BrowserAccessStatus
				if json.Unmarshal(body, &result) != nil || result.Allowed == denied || result.RunNumber != 2 ||
					result.PreviewId != frontend.PreviewID || result.ServiceId != frontend.Subject.ID || result.ServiceRunId != frontend.RunID ||
					response.Header.Get("Cache-Control") != "no-store" || strings.Contains(string(body), "public_url_id") || strings.Contains(string(body), "publish_run_number") {
					t.Fatal("browser access lost canonical service-run scope", string(body))
				}
			}
		}
	}
	if forwarded.Load() != 1 {
		t.Fatal("access status reached the local service", forwarded.Load())
	}
}

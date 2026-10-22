package public

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/tnldotdev/tnl/internal/observability"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestDrainingControlRejectsNewRunsBeforeStateWork(t *testing.T) {
	h := &handler{config: Config{AcceptingNewWork: func() bool { return false }}}
	metrics := observability.New("control")
	t.Cleanup(func() { _ = metrics.Shutdown(t.Context()) })
	for name, serve := range map[string]http.HandlerFunc{
		"public URL": func(w http.ResponseWriter, r *http.Request) {
			h.CreatePublishRun(w, r, "url", controlv1.CreatePublishRunParams{})
		},
		"prepare service": func(w http.ResponseWriter, r *http.Request) {
			h.PrepareServiceRun(w, r, "service", controlv1.PrepareServiceRunParams{})
		},
		"start service": func(w http.ResponseWriter, r *http.Request) { h.StartServiceRun(w, r, "service", "run") },
	} {
		t.Run(name, func(t *testing.T) {
			w := httptest.NewRecorder()
			metrics.APIRequests("control", serve).ServeHTTP(w, httptest.NewRequest("POST", "/", strings.NewReader("invalid body")))
			if w.Code != 503 || w.Header().Get("Retry-After") != "1" || !strings.Contains(w.Body.String(), "control is draining") {
				t.Fatal(w.Code, w.Body.String())
			}
		})
	}
	metricResponse := httptest.NewRecorder()
	metrics.Handler().ServeHTTP(metricResponse, httptest.NewRequest("GET", "/metrics", nil))
	if !strings.Contains(metricResponse.Body.String(), `tnl_outcome="rejected",tnl_reason="draining"`) {
		t.Fatal("drain was classified as infrastructure failure")
	}
	// renewal still reaches its ordinary credential boundary during drain.
	w := httptest.NewRecorder()
	h.HeartbeatPublishRun(w, httptest.NewRequest("POST", "/", strings.NewReader(`{"publish_run_number":1}`)), "run")
	if w.Code != http.StatusUnauthorized || strings.Contains(w.Body.String(), "control is draining") {
		t.Fatal("drain blocked an existing run at the new-work gate", w.Code, w.Body.String())
	}
}

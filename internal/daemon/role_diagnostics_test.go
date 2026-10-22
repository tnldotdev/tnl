package daemon

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	daemonconfig "github.com/tnldotdev/tnl/internal/daemon/config"
	"github.com/tnldotdev/tnl/internal/observability"
)

func TestRoleDiagnosticsAndDrainKeepLivenessIndependentOfReadiness(t *testing.T) {
	d := &daemon{startedAt: time.Now().UTC(), processRunID: "process-instance"}
	d.draining.Store(true)
	m := observability.New("relay")
	t.Cleanup(func() { _ = m.Shutdown(t.Context()) })
	handler := d.withRoleDiagnostics(observability.ProcessHandler(m.Handler(), func() bool { return d.ready(t.Context(), daemonconfig.RoleRelay, time.Now()) == nil }), daemonconfig.RoleRelay)
	for _, test := range []struct {
		path   string
		status int
	}{{"/health", 204}, {"/ready", 503}, {"/debug/roles", 200}} {
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, test.path, nil))
		if response.Code != test.status {
			t.Fatalf("%s: %d", test.path, response.Code)
		}
		if test.path == "/debug/roles" {
			var result processDiagnostic
			if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
				t.Fatal(err)
			}
			if result.ProcessRunID != d.processRunID || !result.Draining || result.SnapshotAt.Before(d.startedAt) || response.Header().Get("Cache-Control") != "no-store" {
				t.Fatal(result)
			}
		}
	}
}

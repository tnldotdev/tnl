package publisher

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	policy "github.com/tnldotdev/tnl/internal/policy/httpprotection"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestPublicURLDefaultProtection(t *testing.T) {
	for _, purpose := range []controlv1.PublicURLPurpose{controlv1.App, controlv1.Alias, controlv1.Demo} {
		t.Run(string(purpose), func(t *testing.T) {
			var forwarded int
			server, err := newTestPublicURLServer(t, PublicURLServerConfig{Hostname: "route.example", Purpose: purpose, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				forwarded++
				w.WriteHeader(204)
			})})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := server.Close(); err != nil {
					t.Error(err)
				}
			})
			r := newInlineTestRequest()
			r.URL.RawQuery = "q=" + url.QueryEscape("<script>alert(1)</script>")
			response := httptest.NewRecorder()
			serveTestPublicRequest(t, server, response, r)
			if response.Code != 403 || response.Header().Get("Tnl-Error-Code") != "TNL_HTTP_PROTECTION_REJECTED" || forwarded != 0 {
				t.Fatalf("status=%d forwarded=%d body=%s", response.Code, forwarded, response.Body)
			}
			response = httptest.NewRecorder()
			serveTestPublicRequest(t, server, response, newInlineTestRequest())
			if response.Code != 204 || forwarded != 1 {
				t.Fatalf("status=%d forwarded=%d", response.Code, forwarded)
			}
		})
	}
}

func TestPublicURLProtectionModesDoNotGrantAccess(t *testing.T) {
	for _, mode := range []policy.Mode{policy.Block, policy.Detect, policy.Off} {
		server, err := newTestPublicURLServer(t, PublicURLServerConfig{Hostname: "route.example", AccessMode: "restricted", Protection: policy.Settings{WAF: mode}, Handler: http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
			t.Error("unauthorized request reached application")
		})})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = server.Close() })
		r := newInlineTestRequest()
		r.URL.RawQuery = "q=" + url.QueryEscape("<script>alert(1)</script>")
		w := httptest.NewRecorder()
		serveTestPublicRequest(t, server, w, r)
		if w.Code != 403 || strings.Contains(w.Body.String(), "TNL_HTTP_PROTECTION_REJECTED") {
			t.Fatal("protection ran before visitor authorization", w.Code, w.Body)
		}
	}
}

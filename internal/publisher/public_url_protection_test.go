package publisher

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"testing"
	"time"

	policy "github.com/tnldotdev/tnl/internal/policy/httpprotection"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestTemporaryBlocksPublicURLAuthorizationAndAcceptedSource(t *testing.T) {
	for _, access := range []controlv1.VisitorAccessMode{"restricted", "anonymous"} {
		t.Run(string(access), func(t *testing.T) {
			reports := make(chan policy.Rejections, 1)
			forwarded := 0
			config := PublicURLServerConfig{Hostname: "route.example", AccessMode: access, Protection: policy.Settings{TemporaryBlocks: true},
				ReportRejections: func(_ context.Context, r policy.Rejections) error { reports <- r; return nil },
				SourceBlocked:    func(netip.Addr, time.Time) bool { return false },
				Handler:          http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { forwarded++; w.WriteHeader(204) })}
			server, err := newTestPublicURLServer(t, config)
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				if err := server.Close(); err != nil {
					t.Error(err)
				}
			}()
			for range policy.BlockThreshold {
				r := newInlineTestRequest()
				r.RemoteAddr = "192.0.2.1:2345"
				r.Header.Set("X-Forwarded-For", "203.0.113.1")
				r.URL.RawQuery = "q=" + url.QueryEscape("<script>alert(1)</script>")
				w := httptest.NewRecorder()
				serveTestPublicRequest(t, server, w, r)
				if w.Code != 403 {
					t.Fatal("request was not rejected", w.Code)
				}
			}
			if access == "restricted" {
				if len(reports) != 0 {
					t.Fatal("authorization failures counted as WAF rejections")
				}
				return
			}
			select {
			case report := <-reports:
				if report.SourceIP != "192.0.2.1" || report.Validate(time.Now()) != nil {
					t.Fatal("report trusted a visitor forwarding header", report)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("eligible public URL rejections were not reported")
			}
			r := newInlineTestRequest()
			r.RemoteAddr = "192.0.2.1:3456"
			w := httptest.NewRecorder()
			serveTestPublicRequest(t, server, w, r)
			if w.Code != 403 || forwarded != 0 {
				t.Fatal("local source block did not protect a later request")
			}
		})
	}
}

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

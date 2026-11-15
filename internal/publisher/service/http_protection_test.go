package service

import (
	"context"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/observability/serviceaudit"
	protectionpolicy "github.com/tnldotdev/tnl/internal/policy/httpprotection"
	"github.com/tnldotdev/tnl/internal/publisher/httpaccess"
	"github.com/tnldotdev/tnl/internal/publisher/httpprotection"
)

func TestServiceHTTPProtectionTemporaryBlockUsesForwardedSource(t *testing.T) {
	var blocked atomic.Bool
	var forwarded atomic.Int32
	inspector, err := httpprotection.Prepare(t.Context(), protectionpolicy.Settings{TemporaryBlocks: true},
		func(context.Context, protectionpolicy.Rejections) error {
			t.Error("ordinary requests produced attack evidence")
			return nil
		}, func(source netip.Addr, _ time.Time) bool {
			if source.String() != "192.0.2.1" {
				t.Error("block did not use the admitted visitor source", source)
			}
			return blocked.Load()
		}, [32]byte{1})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := inspector.Close(); err != nil {
			t.Error(err)
		}
	})
	client, _, _, token := serviceHTTPConfiguredFixture(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		forwarded.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}), true, true, func(f *HTTP) { f.protection = inspector })
	for _, deny := range []bool{false, true, false} {
		blocked.Store(deny)
		request, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, "https://preview.example.test/", nil)
		request.Header.Set(httpaccess.VisitorTokenHeader, token.Reveal())
		request.Header.Set("X-Forwarded-For", "198.51.100.1")
		response, err := client.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		response.Body.Close()
		if response.ProtoMajor != 2 || deny && response.StatusCode != 403 || !deny && response.StatusCode != 204 {
			t.Fatal("refreshed source block did not gate the existing HTTP/2 connection", response.Status)
		}
	}
	if forwarded.Load() != 2 {
		t.Fatal("blocked source reached target", forwarded.Load())
	}
}

func TestServiceHTTPProtectionAuditUsesValidDecisionReason(t *testing.T) {
	events := make(chan serviceaudit.Observation, 1)
	client, _, _, token := serviceHTTPConfiguredFixture(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Error("blocked request reached target")
	}), false, true, func(f *HTTP) {
		f.AuditSink = connectorAuditSink(func(event serviceaudit.Observation) bool {
			events <- event
			return true
		})
	})
	request, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, "https://preview.example.test/?q="+url.QueryEscape("<script>alert(1)</script>"), nil)
	request.Header.Set(httpaccess.VisitorTokenHeader, token.Reveal())
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusForbidden {
		t.Fatal("inspection did not reject request", response.Status)
	}
	event := serviceHTTPAwait(t, events)
	if event.Outcome != "denied" || event.Reason != "invalid_request" || event.Validate() != nil {
		t.Fatal("inspection emitted an invalid service decision", event)
	}
}

func TestServiceHTTPProtection(t *testing.T) {
	for _, inline := range []bool{false, true} {
		for _, mode := range []protectionpolicy.Mode{"", protectionpolicy.Detect, protectionpolicy.Off} {
			t.Run(string(mode)+"/inline="+map[bool]string{false: "false", true: "true"}[inline], func(t *testing.T) {
				var forwarded atomic.Int32
				client, _, _, token := serviceHTTPConfiguredFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					forwarded.Add(1)
					w.WriteHeader(http.StatusNoContent)
				}), false, inline, func(f *HTTP) { f.Protection.WAF = mode })
				request, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, "https://preview.example.test/?q="+url.QueryEscape("<script>alert(1)</script>"), nil)
				request.Header.Set(httpaccess.VisitorTokenHeader, token.Reveal())
				response, err := client.Do(request)
				if err != nil {
					t.Fatal(err)
				}
				response.Body.Close()
				if mode == "" {
					if response.StatusCode != 403 || response.Header.Get("Tnl-Error-Code") != "TNL_HTTP_PROTECTION_REJECTED" || forwarded.Load() != 0 {
						t.Fatal("default blocking did not reject before target access", response.Status, forwarded.Load())
					}
				} else if response.StatusCode != http.StatusNoContent || forwarded.Load() != 1 {
					t.Fatal("explicit mode did not allow the application request", response.Status)
				}
				request.URL.RawQuery = ""
				response, err = client.Do(request)
				if err != nil {
					t.Fatal(err)
				}
				response.Body.Close()
				if response.StatusCode != http.StatusNoContent {
					t.Fatal("ordinary request rejected", response.Status)
				}
			})
		}
	}
}

func TestServiceHTTPProtectionNeverGrantsAccess(t *testing.T) {
	for _, mode := range []protectionpolicy.Mode{protectionpolicy.Block, protectionpolicy.Detect, protectionpolicy.Off} {
		t.Run(string(mode), func(t *testing.T) {
			client, _, _, _ := serviceHTTPConfiguredFixture(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
				t.Error("unauthorized request reached the target")
			}), false, true, func(f *HTTP) { f.Protection.WAF = mode })
			response, err := client.Get("https://preview.example.test/?q=" + url.QueryEscape("<script>alert(1)</script>"))
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			body, _ := io.ReadAll(response.Body)
			if response.StatusCode != 403 || strings.Contains(string(body), "TNL_HTTP_PROTECTION_REJECTED") {
				t.Fatal("inspection ran before authorization", response.Status, string(body))
			}
		})
	}
}

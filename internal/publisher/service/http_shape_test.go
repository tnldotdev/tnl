package service

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/publisher/httpaccess"
	"github.com/tnldotdev/tnl/internal/publisher/requestlimit"
	"github.com/tnldotdev/tnl/internal/testutil/visitorfixture"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestServiceHTTPShapePrecedesAuthorizationAndApplicationAdmission(t *testing.T) {
	for _, inline := range []bool{false, true} {
		for _, h2 := range []bool{false, true} {
			t.Run(fmt.Sprintf("inline=%t/http2=%t", inline, h2), func(t *testing.T) {
				var forwarded, ownerChecks, admissions, preparations atomic.Int32
				var budget *requestlimit.HTTP
				client, _, _, token := serviceHTTPConfiguredFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					forwarded.Add(1)
					w.WriteHeader(http.StatusNoContent)
				}), h2, inline, func(f *HTTP) {
					var err error
					f.Requests, err = requestlimit.NewHTTP(&controlv1.ProjectHTTPApplicationLimits{
						Total: new(1), Concurrency: new(1), Rate: &controlv1.ProjectApplicationRate{Count: 1, Per: "1h"},
					})
					if err != nil {
						t.Fatal(err)
					}
					budget = f.Requests
					f.AdmitRequest = func(*http.Request) error { ownerChecks.Add(1); return nil }
					f.ReserveCapacity = func(context.Context) error { admissions.Add(1); return nil }
					control := serviceHTTPPreparationControl{work: func(context.Context, string) error {
						preparations.Add(1)
						return errors.New("unexpected preparation")
					}}
					f.Control = control
					f.preparations = make(chan struct{}, 16)
					f.browser = &httpaccess.Browser{Subject: f.Subject, Client: control, RunID: f.RunID, Number: f.Number, Token: f.Token}
				})
				client.Transport.(*http.Transport).DisableCompression = true
				client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
				visit := func(path string, fields int, credential bool) int {
					t.Helper()
					r, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "https://preview.example.test"+path, nil)
					if err != nil {
						t.Fatal(err)
					}
					// suppress implicit transport fields so the wire contains exactly
					// the field count under test, including duplicate field values.
					r.Header["User-Agent"] = nil
					if credential {
						r.Header.Set(httpaccess.VisitorTokenHeader, token.Reveal())
						fields--
					}
					if path == "/__tnl/team/session" {
						r.AddCookie(&http.Cookie{Name: httpaccess.BrowserCookieName, Value: visitorfixture.BrowserCookie})
						fields--
					}
					for range fields {
						r.Header.Add("X-Shape", "small")
					}
					response, err := client.Do(r)
					if err != nil {
						t.Fatal(err)
					}
					defer response.Body.Close()
					if _, err := io.Copy(io.Discard, response.Body); err != nil {
						t.Fatal(err)
					}
					if h2 && response.ProtoMajor != 2 {
						t.Fatal("shape test did not negotiate HTTP/2", response.Proto)
					}
					if response.StatusCode == http.StatusBadRequest && response.Header.Get("Tnl-Error-Code") != "TNL_REQUEST_REJECTED" {
						t.Fatal("shape rejection lost its diagnostic", response.Header)
					}
					return response.StatusCode
				}
				for _, test := range []struct {
					path       string
					credential bool
				}{{"/", false}, {"/", true}, {"/__tnl/team/session", false}, {"/__tnl/share/invalid", false}} {
					if status := visit(test.path, 101, test.credential); status != http.StatusBadRequest {
						t.Fatalf("101 fields at %s: status=%d, want 400", test.path, status)
					}
				}
				if forwarded.Load() != 0 || ownerChecks.Load() != 0 || admissions.Load() != 0 || preparations.Load() != 0 {
					t.Fatal("invalid shape reached authorization, ingress, target, or control", forwarded.Load(), ownerChecks.Load(), admissions.Load(), preparations.Load())
				}
				select {
				case <-budget.Completed():
					t.Fatal("invalid shape spent the application total")
				default:
				}
				if status := visit("/", 100, true); status != http.StatusNoContent {
					t.Fatal("100 fields were rejected or invalid requests spent total/rate budget", status)
				}
				serviceHTTPAwait(t, budget.Completed())
				if forwarded.Load() != 1 || ownerChecks.Load() != 1 || admissions.Load() != 1 {
					t.Fatal("shape gate did not preserve the one valid request", forwarded.Load(), ownerChecks.Load(), admissions.Load())
				}
			})
		}
	}
}

func TestServiceHTTPShapeRejectsConnectAndAbsoluteTargetsBeforeAdmission(t *testing.T) {
	for _, inline := range []bool{false, true} {
		t.Run(fmt.Sprintf("inline=%t", inline), func(t *testing.T) {
			var forwarded, admissions, ownerChecks atomic.Int32
			client, _, _, token := serviceHTTPConfiguredFixture(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				forwarded.Add(1)
				w.WriteHeader(http.StatusNoContent)
			}), true, inline, func(f *HTTP) {
				var err error
				f.Requests, err = requestlimit.NewHTTP(&controlv1.ProjectHTTPApplicationLimits{
					Total: new(1), Rate: &controlv1.ProjectApplicationRate{Count: 1, Per: "1h"},
				})
				if err != nil {
					t.Fatal(err)
				}
				f.AdmitRequest = func(*http.Request) error { ownerChecks.Add(1); return nil }
				f.ReserveCapacity = func(context.Context) error { admissions.Add(1); return nil }
			})
			transport := client.Transport.(*http.Transport)
			for _, line := range []string{
				"CONNECT preview.example.test:443 HTTP/1.1",
				"GET https://preview.example.test/ HTTP/1.1",
			} {
				raw, err := transport.DialContext(t.Context(), "tcp", "preview.example.test:443")
				if err != nil {
					t.Fatal(err)
				}
				_ = raw.SetDeadline(time.Now().Add(3 * time.Second))
				trust := transport.TLSClientConfig.Clone()
				trust.ServerName, trust.NextProtos = "preview.example.test", []string{"http/1.1"}
				connection := tls.Client(raw, trust)
				if _, err := fmt.Fprintf(connection, "%s\r\nHost: preview.example.test\r\n%s: %s\r\n\r\n", line, httpaccess.VisitorTokenHeader, token.Reveal()); err != nil {
					_ = connection.Close()
					t.Fatal(err)
				}
				response, err := http.ReadResponse(bufio.NewReader(connection), nil)
				if err != nil {
					_ = connection.Close()
					t.Fatal(err)
				}
				_, _ = io.Copy(io.Discard, response.Body)
				_ = response.Body.Close()
				_ = connection.Close()
				if response.StatusCode != http.StatusBadRequest || response.Header.Get("Tnl-Error-Code") != "TNL_REQUEST_REJECTED" {
					t.Fatal("HTTP/1 malformed target bypassed the shared shape gate", line, response.Status, response.Header)
				}
			}
			connect, err := http.NewRequestWithContext(t.Context(), http.MethodConnect, "https://preview.example.test/", nil)
			if err != nil {
				t.Fatal(err)
			}
			connect.Header.Set(httpaccess.VisitorTokenHeader, token.Reveal())
			if got := serviceHTTPDo(client, connect); got.err != nil || got.status != http.StatusBadRequest || got.protocol != 2 ||
				got.header.Get("Tnl-Error-Code") != "TNL_REQUEST_REJECTED" {
				t.Fatalf("HTTP/2 CONNECT bypassed the shared shape gate: %+v", got)
			}
			if forwarded.Load() != 0 || admissions.Load() != 0 || ownerChecks.Load() != 0 {
				t.Fatal("malformed target reached target or admission", forwarded.Load(), admissions.Load(), ownerChecks.Load())
			}
			serviceHTTPLimitedGet(t, client, token, false)
			if forwarded.Load() != 1 || admissions.Load() != 1 || ownerChecks.Load() != 1 {
				t.Fatal("shape rejection spent the ordinary request's total or rate budget", forwarded.Load(), admissions.Load(), ownerChecks.Load())
			}
		})
	}
}

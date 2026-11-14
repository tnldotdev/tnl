package service

import (
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/tnldotdev/tnl/internal/publisher/httpaccess"
	"github.com/tnldotdev/tnl/internal/transport/httpstream"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestServiceHTTPResponseHooksUseOnePreparedRunAndAdmittedRequests(t *testing.T) {
	for _, h2 := range []bool{false, true} {
		name := "http1"
		if h2 {
			name = "http2"
		}
		t.Run(name, func(t *testing.T) {
			cfg, control := lifecycleFixture(t)
			control.prep.ServiceId = "svc_" + strings.Repeat("A", 22)
			control.prep.ServiceRunId = "srun_" + strings.Repeat("R", 22)
			control.prep.RunNumber = 1
			control.prep.Hostname = "preview.example.test"
			control.prep.CertificatePlan = &controlv1.CertificatePlan{
				CacheKey: "service-http-hooks", Scope: control.prep.Hostname,
				Identifiers: []string{control.prep.Hostname}, ChallengeMethod: controlv1.Dns01,
			}
			cfg.ServiceID = control.prep.ServiceId
			approved, err := control.GetPublisherService(t.Context(), cfg.ServiceID, "")
			if err != nil {
				t.Fatal(err)
			}
			approved.Protocol, approved.Endpoint.Port = controlv1.ServiceProtocolHTTP, 443
			var built, observed atomic.Int32
			cfg.HTTPResponseHooks = func(run HTTPRun) httpstream.ResponseHooks {
				built.Add(1)
				if run != (HTTPRun{ServiceID: control.prep.ServiceId, RunID: control.prep.ServiceRunId, Number: control.prep.RunNumber, Hostname: control.prep.Hostname}) {
					t.Error("hooks received caller-derived or incomplete run facts", run)
				}
				return httpstream.ResponseHooks{Observe: func(response *http.Response) error {
					if response.Request.Host != "preview.example.test" || response.Request.URL.Host == response.Request.Host {
						t.Error("response observer lost admitted visitor authority or changed target identity")
					}
					observed.Add(1)
					return nil
				}}
			}
			prepared, err := newManagedPrepared(control.prep, approved, cfg)
			if err != nil {
				t.Fatal(err)
			}
			client, _, _, token := serviceHTTPConfiguredFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("Accept-Encoding") != "gzip" {
					t.Error("header observer changed target compression")
				}
				w.WriteHeader(http.StatusNoContent)
			}), h2, false, func(frontend *HTTP) {
				frontend.ResponseHooks = prepared.httpResponseHooks
				frontend.Requests = prepared.serviceHTTPRequests
			})
			for _, credential := range []bool{false, true, true} {
				request, err := http.NewRequestWithContext(t.Context(), "GET", "https://preview.example.test/", nil)
				if err != nil {
					t.Fatal(err)
				}
				request.Header.Set("Accept-Encoding", "gzip")
				if credential {
					request.Header.Set(httpaccess.VisitorTokenHeader, token.Reveal())
				}
				response, err := client.Do(request)
				if err != nil {
					t.Fatal(err)
				}
				_, err = io.Copy(io.Discard, response.Body)
				response.Body.Close()
				want := http.StatusForbidden
				if credential {
					want = http.StatusNoContent
				}
				if err != nil || response.StatusCode != want {
					t.Fatal("hooks changed service authorization", response.Status, err)
				}
			}
			if built.Load() != 1 || observed.Load() != 2 {
				t.Fatal("hooks were rebuilt per request or observed a denial", built.Load(), observed.Load())
			}
			// rejected preparation must not construct feature state.
			bad := control.prep
			bad.ServiceId = "svc_" + strings.Repeat("Z", 22)
			if _, err := newManagedPrepared(bad, approved, cfg); err == nil || built.Load() != 1 {
				t.Fatal("invalid preparation constructed response hooks")
			}
		})
	}
}

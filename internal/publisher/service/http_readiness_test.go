package service

import (
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/observability/serviceaudit"
	"github.com/tnldotdev/tnl/internal/publisher/httpaccess"
	publisherproxy "github.com/tnldotdev/tnl/internal/publisher/proxy"
	"github.com/tnldotdev/tnl/internal/publisher/requestlimit"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestServiceHTTPReadinessHasIndependentBoundedCapacity(t *testing.T) {
	for _, h2 := range []bool{false, true} {
		name := "http1"
		if h2 {
			name = "http2"
		}
		t.Run(name, func(t *testing.T) {
			entered, finish := make(chan struct{}, 4), make(chan struct{})
			var workers sync.WaitGroup
			// release and join even when an intermediate assertion fails.
			defer func() { close(finish); workers.Wait() }()
			var proof *httpaccess.ReadinessProof
			client, _, _, token := serviceHTTPConfiguredFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if publisherproxy.IsReadinessProbe(r) {
					entered <- struct{}{}
					select {
					case <-finish:
					case <-r.Context().Done():
					}
				}
				w.WriteHeader(http.StatusNoContent)
			}), h2, true, func(f *HTTP) {
				var err error
				proof, err = httpaccess.NewReadinessProof(httpaccess.ReadinessRun{Subject: f.Subject, ID: f.RunID, Number: uint64(f.Number), Hostname: f.Hostname}, "/health")
				if err != nil {
					t.Fatal(err)
				}
				f.ReadinessProof = proof
				f.Requests, err = requestlimit.NewHTTP(&controlv1.ProjectHTTPApplicationLimits{Total: new(1), Concurrency: new(1)})
				if err != nil {
					t.Fatal(err)
				}
				f.probes, err = requestlimit.NewHTTP(&controlv1.ProjectHTTPApplicationLimits{Concurrency: new(4)})
				if err != nil {
					t.Fatal(err)
				}
			})
			request := func(secret, credential string) (int, error) {
				r, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "https://preview.example.test/health", nil)
				if err != nil {
					return 0, err
				}
				r.Header.Set(publisherproxy.ReadinessProbeHeader, secret)
				if credential != "" {
					r.Header.Set(httpaccess.VisitorTokenHeader, credential)
				}
				response, err := client.Do(r)
				if err != nil {
					return 0, err
				}
				_, err = io.Copy(io.Discard, response.Body)
				err = errors.Join(err, response.Body.Close())
				return response.StatusCode, err
			}
			for range 4 {
				secret, err := proof.Renew()
				if err != nil {
					t.Fatal(err)
				}
				workers.Go(func() {
					status, err := request(secret, "")
					if err != nil || status != http.StatusNoContent {
						t.Error("admitted probe failed", status, err)
					}
				})
				select {
				case <-entered:
				case <-time.After(3 * time.Second):
					t.Fatal("probe did not enter the application")
				}
			}
			secret, err := proof.Renew()
			if err != nil {
				t.Fatal(err)
			}
			if status, err := request(secret, ""); err != nil || status != http.StatusServiceUnavailable {
				t.Fatal("probe capacity was unbounded", status, err)
			}
			if status, err := request("", token.Reveal()); err != nil || status != http.StatusNoContent {
				t.Fatal("probes spent application capacity", status, err)
			}
		})
	}
}

func TestServiceHTTPReadinessIsExactAndDoesNotSpendApplicationBudget(t *testing.T) {
	for _, h2 := range []bool{false, true} {
		name := "http1"
		if h2 {
			name = "http2"
		}
		t.Run(name, func(t *testing.T) {
			var proof *httpaccess.ReadinessProof
			var probes, applications atomic.Int32
			var stale atomic.Bool
			events := make(chan serviceaudit.Observation, 16)
			client, _, _, token := serviceHTTPConfiguredFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get(publisherproxy.ReadinessProbeHeader) != "" || r.Header.Get(httpaccess.VisitorTokenHeader) != "" ||
					r.Header.Get("Forwarded") != "" || r.Header.Get("X-Forwarded-Host") != "" || r.Header.Get("X-Real-IP") != "" {
					t.Error("target received a readiness or visitor credential, or untrusted forwarding metadata")
				}
				if publisherproxy.IsReadinessProbe(r) {
					probes.Add(1)
				} else {
					applications.Add(1)
				}
				w.WriteHeader(http.StatusNoContent)
			}), h2, true, func(f *HTTP) {
				var err error
				proof, err = httpaccess.NewReadinessProof(httpaccess.ReadinessRun{Subject: f.Subject, ID: f.RunID, Number: uint64(f.Number), Hostname: f.Hostname}, "/health")
				if err != nil {
					t.Fatal(err)
				}
				f.ReadinessProof = proof
				f.Requests, err = requestlimit.NewHTTP(&controlv1.ProjectHTTPApplicationLimits{Total: new(1), Concurrency: new(1), Rate: &controlv1.ProjectApplicationRate{Count: 1, Per: "1h"}})
				if err != nil {
					t.Fatal(err)
				}
				f.probes, err = requestlimit.NewHTTP(&controlv1.ProjectHTTPApplicationLimits{Concurrency: new(4)})
				if err != nil {
					t.Fatal(err)
				}
				f.AdmitRequest = func(*http.Request) error {
					if stale.Load() {
						return errors.New("registration replaced")
					}
					return nil
				}
				f.AuditSink = connectorAuditSink(func(o serviceaudit.Observation) bool { events <- o; return true })
			})
			request := func(method, path, secret, credential string, want int) {
				t.Helper()
				r, err := http.NewRequestWithContext(t.Context(), method, "https://preview.example.test"+path, nil)
				if err != nil {
					t.Fatal(err)
				}
				r.Header.Set(publisherproxy.ReadinessProbeHeader, secret)
				r.Header.Set("Forwarded", "for=private")
				r.Header.Set("X-Forwarded-Host", "private")
				r.Header.Set("X-Real-IP", "192.0.2.99")
				if credential != "" {
					r.Header.Set(httpaccess.VisitorTokenHeader, credential)
				}
				response, err := client.Do(r)
				if err != nil {
					t.Fatal(err)
				}
				_, _ = io.Copy(io.Discard, response.Body)
				_ = response.Body.Close()
				if response.StatusCode != want {
					t.Fatalf("%s %s: status=%d, want %d", method, path, response.StatusCode, want)
				}
			}
			secret := proof.HeaderValue()
			request(http.MethodPost, "/health", secret, "", http.StatusForbidden)
			request(http.MethodGet, "/health?query=private", secret, "", http.StatusForbidden)
			request(http.MethodGet, "/other", secret, "", http.StatusForbidden)
			request(http.MethodGet, "/health", secret, "", http.StatusNoContent)
			request(http.MethodGet, "/health", secret, "", http.StatusForbidden)
			// a forged probe with a valid visitor token is an ordinary request.
			request(http.MethodGet, "/app", "invalid-proof", token.Reveal(), http.StatusNoContent)
			request(http.MethodGet, "/app", "", token.Reveal(), http.StatusServiceUnavailable)
			next, err := proof.Renew()
			if err != nil {
				t.Fatal(err)
			}
			request(http.MethodGet, "/health", next, "", http.StatusNoContent)
			next, err = proof.Renew()
			if err != nil {
				t.Fatal(err)
			}
			stale.Store(true)
			request(http.MethodGet, "/health", next, "", http.StatusServiceUnavailable)
			if probes.Load() != 2 || applications.Load() != 1 {
				t.Fatal("owner probes crossed ownership or application budgets", probes.Load(), applications.Load())
			}
			// only the failed/ordinary requests claim visitor access decisions.
			if len(events) != 7 {
				t.Fatal("readiness probes claimed application access", len(events))
			}
			for len(events) != 0 {
				event := <-events
				if event.Validate() != nil || strings.Contains(event.Reason, next) || time.Since(event.OccurredAt) > time.Minute {
					t.Fatal("invalid or unsafe readiness audit")
				}
			}
		})
	}
}

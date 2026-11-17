package service

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/observability/serviceaudit"
	"github.com/tnldotdev/tnl/internal/publisher/httpaccess"
	"github.com/tnldotdev/tnl/internal/publisher/requestlimit"
	"github.com/tnldotdev/tnl/internal/transport/httpstream"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestServiceHTTPReadinessDeadlineReleasesOnlyItsProbe(t *testing.T) {
	for _, h2 := range []bool{false, true} {
		t.Run(map[bool]string{false: "http1", true: "http2"}[h2], func(t *testing.T) {
			t.Parallel()
			type work struct {
				deadline time.Time
				started  time.Time
				err      error
			}
			entered, stopped := make(chan work, 4), make(chan work, 4)
			siblingStarted, siblingFinish := make(chan struct{}), make(chan struct{})
			unblock := sync.OnceFunc(func() { close(siblingFinish) })
			defer unblock()
			var proof *httpaccess.ReadinessProof
			var budget *requestlimit.HTTP
			var first atomic.Bool
			first.Store(true)
			client, _, _, token := serviceHTTPConfiguredFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if httpstream.IsReadinessProbe(r) && first.Swap(false) {
					start := time.Now()
					deadline, _ := r.Context().Deadline()
					entered <- work{deadline: deadline, started: start}
					<-r.Context().Done()
					stopped <- work{deadline: deadline, started: start, err: r.Context().Err()}
				} else if r.URL.Path == "/sibling" {
					close(siblingStarted)
					select {
					case <-siblingFinish:
					case <-r.Context().Done():
						t.Error("probe deadline canceled an ordinary sibling", r.Context().Err())
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
				f.probes, err = requestlimit.NewHTTP(&controlv1.ProjectHTTPApplicationLimits{Concurrency: new(1)})
				if err != nil {
					t.Fatal(err)
				}
				f.Requests, err = requestlimit.NewHTTP(&controlv1.ProjectHTTPApplicationLimits{
					Total: new(1), Concurrency: new(1), Rate: &controlv1.ProjectApplicationRate{Count: 1, Per: "1h"},
				})
				if err != nil {
					t.Fatal(err)
				}
				budget = f.Requests
			})
			client.Timeout = 9 * time.Second
			request := func(path, secret, credential string) error {
				r, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "https://preview.example.test"+path, nil)
				if err != nil {
					return err
				}
				r.Header.Set(httpstream.ReadinessProbeHeader, secret)
				if credential != "" {
					r.Header.Set(httpaccess.VisitorTokenHeader, credential)
				}
				response, err := client.Do(r)
				if err != nil {
					return err
				}
				defer response.Body.Close()
				_, err = io.Copy(io.Discard, response.Body)
				if err == nil && (response.StatusCode != http.StatusNoContent || h2 && response.ProtoMajor != 2) {
					err = fmt.Errorf("unexpected response: %s %s", response.Proto, response.Status)
				}
				return err
			}
			probeDone, siblingDone := make(chan error, 1), make(chan error, 1)
			go func() { probeDone <- request("/health", proof.HeaderValue(), "") }()
			workStarted := serviceHTTPAwait(t, entered)
			if remaining := workStarted.deadline.Sub(workStarted.started); remaining < 4*time.Second || remaining > 5*time.Second {
				t.Fatalf("owner target work has no five-second deadline: %v", remaining)
			}
			go func() { siblingDone <- request("/sibling", "", token.Reveal()) }()
			serviceHTTPAwait(t, siblingStarted)
			select {
			case workStopped := <-stopped:
				if !errors.Is(workStopped.err, context.DeadlineExceeded) || time.Since(workStopped.started) < 4*time.Second {
					t.Fatal("owner probe stopped for something other than its target-work deadline", workStopped.err)
				}
			case <-time.After(7 * time.Second):
				t.Fatal("owner target work did not stop at its five-second deadline")
			}
			if err := serviceHTTPAwait(t, probeDone); err != nil {
				t.Fatal("timed-out inline probe did not finish", err)
			}
			select {
			case <-budget.Completed():
				t.Fatal("probe deadline spent or released ordinary sibling budget")
			case err := <-siblingDone:
				t.Fatal("probe deadline ended the ordinary sibling", err)
			default:
			}
			secret, err := proof.Renew()
			if err != nil {
				t.Fatal(err)
			}
			if err := request("/health", secret, ""); err != nil {
				t.Fatal("deadline did not release its probe slot", err)
			}
			unblock()
			if err := serviceHTTPAwait(t, siblingDone); err != nil {
				t.Fatal("ordinary sibling could not finish after probe expiry", err)
			}
			serviceHTTPAwait(t, budget.Completed())
		})
	}
}

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
				if httpstream.IsReadinessProbe(r) {
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
				r.Header.Set(httpstream.ReadinessProbeHeader, secret)
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
			var budget *requestlimit.HTTP
			var probes, applications, prepared, consumed atomic.Int32
			var stale atomic.Bool
			events := make(chan serviceaudit.Observation, 16)
			client, _, _, token := serviceHTTPConfiguredFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get(httpstream.ReadinessProbeHeader) != "" || r.Header.Get(httpaccess.VisitorTokenHeader) != "" ||
					r.Header.Get("Forwarded") != "" || r.Header.Get("X-Forwarded-Host") != "" || r.Header.Get("X-Real-IP") != "" {
					t.Error("target received a readiness or visitor credential, or untrusted forwarding metadata")
				}
				if httpstream.IsReadinessProbe(r) {
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
				budget = f.Requests
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
				f.PrepareRequest = func(*http.Request) (func(context.Context) error, error) {
					prepared.Add(1)
					return func(context.Context) error { consumed.Add(1); return nil }, nil
				}
				f.AuditSink = connectorAuditSink(func(o serviceaudit.Observation) bool { events <- o; return true })
			})
			request := func(method, path, secret, credential string, want int) {
				t.Helper()
				r, err := http.NewRequestWithContext(t.Context(), method, "https://preview.example.test"+path, nil)
				if err != nil {
					t.Fatal(err)
				}
				r.Header.Set(httpstream.ReadinessProbeHeader, secret)
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
			select {
			case <-budget.Completed():
				t.Fatal("readiness or rejected work completed the application budget")
			default:
			}
			// a forged probe with a valid visitor token is an ordinary request.
			request(http.MethodGet, "/app", "invalid-proof", token.Reveal(), http.StatusNoContent)
			serviceHTTPAwait(t, budget.Completed())
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
			if prepared.Load() != 6 || consumed.Load() != 1 {
				t.Fatal("owner readiness probes prepared or committed application claims", prepared.Load(), consumed.Load())
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

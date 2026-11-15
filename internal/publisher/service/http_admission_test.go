package service

import (
	"context"
	"errors"
	"io"
	"net/http"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/tnldotdev/tnl/internal/publisher/httpaccess"
	"github.com/tnldotdev/tnl/internal/publisher/requestlimit"
	"github.com/tnldotdev/tnl/internal/transport/httpstream"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestServiceHTTPWaitsForIngressAfterRequestAuthorization(t *testing.T) {
	for _, h2 := range []bool{false, true} {
		for _, inline := range []bool{false, true} {
			name := map[bool]string{false: "http1", true: "http2"}[h2] + "/" + map[bool]string{false: "target", true: "handler"}[inline]
			t.Run(name, func(t *testing.T) {
				waiting, promoted := make(chan struct{}), make(chan struct{})
				var calls, forwarded atomic.Int32
				client, _, _, token := serviceHTTPConfiguredFixture(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					forwarded.Add(1)
					w.WriteHeader(http.StatusNoContent)
				}), h2, inline, func(f *HTTP) {
					f.browser = &httpaccess.Browser{Subject: f.Subject, Client: serviceHTTPControl{}, RunID: f.RunID, Number: f.Number, Token: f.Token, ControlURL: "https://control.example.test"}
					f.ReserveCapacity = func(ctx context.Context) error {
						if calls.Add(1) == 1 {
							close(waiting)
						}
						select {
						case <-promoted:
							return nil
						case <-ctx.Done():
							return ctx.Err()
						}
					}
				})
				client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
				request := func(path, credential string) *http.Request {
					t.Helper()
					r, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "https://preview.example.test"+path, nil)
					if err != nil {
						t.Fatal(err)
					}
					if credential != "" {
						r.Header.Set(httpaccess.VisitorTokenHeader, credential)
					}
					return r
				}
				check := func(r *http.Request, want int) {
					t.Helper()
					response, err := client.Do(r)
					if err != nil {
						t.Fatal(err)
					}
					_, err = io.Copy(io.Discard, response.Body)
					err = errors.Join(err, response.Body.Close())
					if err != nil || response.StatusCode != want {
						t.Fatal("HTTP response changed", response.StatusCode, err)
					}
				}
				check(request("/", ""), http.StatusForbidden)
				check(request("/__tnl/unknown", token.Reveal()), http.StatusNotFound)
				check(request("/__tnl/team/login", ""), http.StatusSeeOther)
				navigation := request("/", "")
				navigation.Header.Set("Sec-Fetch-Mode", "navigate")
				navigation.Header.Set("Sec-Fetch-Dest", "document")
				check(navigation, http.StatusSeeOther)
				if calls.Load() != 0 {
					t.Fatal("denial or browser preparation authorized ingress capacity")
				}
				authorized := request("/", token.Reveal())
				replies := make(chan error, 1)
				go func() {
					response, err := client.Do(authorized)
					if err == nil {
						_, err = io.Copy(io.Discard, response.Body)
						err = errors.Join(err, response.Body.Close())
						if response.StatusCode != http.StatusNoContent {
							err = errors.Join(err, errors.New("admitted request failed"))
						}
					}
					replies <- err
				}()
				serviceHTTPAwait(t, waiting)
				if forwarded.Load() != 0 {
					t.Fatal("request reached the target before ingress acknowledgment")
				}
				close(promoted)
				if err := serviceHTTPAwait(t, replies); err != nil {
					t.Fatal(err)
				}
				check(request("/", token.Reveal()), http.StatusNoContent)
				check(request("/", "invalid"), http.StatusForbidden)
				if calls.Load() != 1 || forwarded.Load() != 2 {
					t.Fatal("connection admission was repeated or replaced per-request authorization", calls.Load(), forwarded.Load())
				}
			})
		}
	}
}

func TestServiceHTTPGuardStaysActiveWhileIngressAdmissionWaits(t *testing.T) {
	for _, h2 := range []bool{false, true} {
		t.Run(map[bool]string{false: "http1", true: "http2"}[h2], func(t *testing.T) {
			waiting, stopped := make(chan struct{}), make(chan struct{})
			var forwarded atomic.Int32
			client, policy, update, token := serviceHTTPConfiguredFixture(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
				forwarded.Add(1)
			}), h2, true, func(f *HTTP) {
				f.ReserveCapacity = func(ctx context.Context) error {
					close(waiting)
					<-ctx.Done()
					close(stopped)
					return ctx.Err()
				}
			})
			request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "https://preview.example.test/", nil)
			if err != nil {
				t.Fatal(err)
			}
			request.Header.Set(httpaccess.VisitorTokenHeader, token.Reveal())
			replies := make(chan error, 1)
			go func() {
				response, err := client.Do(request)
				if err == nil {
					_, err = io.Copy(io.Discard, response.Body)
					err = errors.Join(err, response.Body.Close())
				}
				replies <- err
			}()
			serviceHTTPAwait(t, waiting)
			update.Enabled = false
			update.View.VisitorPolicyRevision++
			update.View.ObservedAt = time.Now()
			update.View.ValidUntil = update.View.ObservedAt.Add(10 * time.Second)
			if err := policy.Apply(policy.Begin(), update); err != nil {
				t.Fatal(err)
			}
			serviceHTTPAwait(t, stopped)
			if err := serviceHTTPAwait(t, replies); err == nil || forwarded.Load() != 0 {
				t.Fatal("revoked request escaped its waiting policy guard", err, forwarded.Load())
			}
		})
	}
}

func TestServiceHTTPAdmissionKeepsOriginalHeaderDeadline(t *testing.T) {
	for _, h2 := range []bool{false, true} {
		t.Run(map[bool]string{false: "http1", true: "http2"}[h2], func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				started := make(chan struct{})
				var calls, forwarded atomic.Int32
				deadline := time.Now().Add(time.Second)
				client, _, _, token := serviceHTTPConfiguredFixture(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
					forwarded.Add(1)
				}), h2, true, func(f *HTTP) {
					f.Header.ExpiresAt = deadline
					f.ReserveCapacity = func(ctx context.Context) error {
						if until, ok := ctx.Deadline(); !ok || !until.Equal(deadline) {
							t.Error("capacity request lost the trusted header deadline")
						}
						if calls.Add(1) == 1 {
							close(started)
						}
						<-ctx.Done()
						// a late success must not extend the original setup deadline.
						return nil
					}
				})
				request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "https://preview.example.test/", nil)
				if err != nil {
					t.Fatal(err)
				}
				request.Header.Set(httpaccess.VisitorTokenHeader, token.Reveal())
				replies := make(chan error, 1)
				go func() {
					response, err := client.Do(request)
					if err == nil {
						_, err = io.Copy(io.Discard, response.Body)
						err = errors.Join(err, response.Body.Close())
						if response.StatusCode != http.StatusServiceUnavailable {
							err = errors.Join(err, errors.New("expired admission did not fail closed"))
						}
					}
					replies <- err
				}()
				serviceHTTPAwait(t, started)
				synctest.Wait()
				// advance the fake clock while the capacity request is waiting.
				time.Sleep(time.Second)
				synctest.Wait()
				if err := serviceHTTPAwait(t, replies); err != nil {
					t.Fatal(err)
				}
				count := calls.Load()
				if count != 1 {
					t.Fatal("capacity was requested more than once", count)
				}
				time.Sleep(time.Second)
				synctest.Wait()
				if calls.Load() != count || forwarded.Load() != 0 {
					t.Fatal("late success extended pending admission", calls.Load(), count, forwarded.Load())
				}
			})
		})
	}
}

func TestServiceHTTPAnonymousAndReadinessNeedIngressAcknowledgment(t *testing.T) {
	for _, readiness := range []bool{false, true} {
		t.Run(map[bool]string{false: "anonymous", true: "readiness"}[readiness], func(t *testing.T) {
			var calls, forwarded atomic.Int32
			var proof *httpaccess.ReadinessProof
			client, policy, update, _ := serviceHTTPConfiguredFixture(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
				forwarded.Add(1)
			}), false, true, func(f *HTTP) {
				f.ReserveCapacity = func(context.Context) error {
					calls.Add(1)
					return errors.New("ingress capacity denied")
				}
				if readiness {
					var err error
					proof, err = httpaccess.NewReadinessProof(httpaccess.ReadinessRun{Subject: f.Subject, ID: f.RunID, Number: uint64(f.Number), Hostname: f.Hostname}, "/health")
					if err != nil {
						t.Fatal(err)
					}
					f.ReadinessProof = proof
					f.probes, err = requestlimit.NewHTTP(&controlv1.ProjectHTTPApplicationLimits{Concurrency: new(4)})
					if err != nil {
						t.Fatal(err)
					}
				}
			})
			if !readiness {
				update.Anonymous = true
				if err := policy.Apply(policy.Begin(), update); err != nil {
					t.Fatal(err)
				}
			}
			request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "https://preview.example.test/health", nil)
			if err != nil {
				t.Fatal(err)
			}
			if readiness {
				request.Header.Set(httpstream.ReadinessProbeHeader, proof.HeaderValue())
			}
			response, err := client.Do(request)
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			if response.StatusCode != http.StatusServiceUnavailable || calls.Load() != 1 || forwarded.Load() != 0 {
				t.Fatal("anonymous or readiness request bypassed ingress acknowledgment", response.StatusCode, calls.Load(), forwarded.Load())
			}
		})
	}
}

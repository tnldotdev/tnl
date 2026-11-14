package service

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/tnldotdev/tnl/internal/publisher/httpaccess"
	publisherproxy "github.com/tnldotdev/tnl/internal/publisher/proxy"
	"github.com/tnldotdev/tnl/internal/publisher/requestlimit"
	"github.com/tnldotdev/tnl/internal/security/credentials"
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
					service, run, secret := f.Subject.ID, f.RunID, f.Token
					f.browser = &httpaccess.Browser{Subject: f.Subject, ControlURL: "https://control.example.test"}
					f.Control = serviceHTTPAdmissionControl{authorize: func(ctx context.Context, gotService, gotRun string, gotToken credentials.ServiceRunToken, input controlv1.AuthorizeServiceHTTPVisitorRequest) (controlv1.ServiceClientCertificateDecision, error) {
						if gotService != service || gotRun != run || gotToken != secret || input.RunNumber != 1 || input.VisitorConnectionId != "vc_"+strings.Repeat("V", 22) || input.SourceIp != "192.0.2.1" || input.DestinationPort != 443 {
							t.Error("HTTP admission lost its exact run or trusted forwarding facts")
						}
						call := calls.Add(1)
						if call == 1 {
							return controlv1.ServiceClientCertificateDecision{Allowed: true, ValidUntil: time.Now().Add(time.Minute)}, nil
						}
						if call == 2 {
							close(waiting)
						}
						select {
						case <-promoted:
							return controlv1.ServiceClientCertificateDecision{Allowed: true, Admitted: true, ValidUntil: time.Now().Add(time.Minute)}, nil
						case <-ctx.Done():
							return controlv1.ServiceClientCertificateDecision{}, ctx.Err()
						}
					}}
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
				if calls.Load() != 2 || forwarded.Load() != 2 {
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
				f.Control = serviceHTTPAdmissionControl{authorize: func(ctx context.Context, _, _ string, _ credentials.ServiceRunToken, _ controlv1.AuthorizeServiceHTTPVisitorRequest) (controlv1.ServiceClientCertificateDecision, error) {
					close(waiting)
					<-ctx.Done()
					close(stopped)
					return controlv1.ServiceClientCertificateDecision{}, ctx.Err()
				}}
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
					f.Control = serviceHTTPAdmissionControl{authorize: func(ctx context.Context, _, _ string, _ credentials.ServiceRunToken, _ controlv1.AuthorizeServiceHTTPVisitorRequest) (controlv1.ServiceClientCertificateDecision, error) {
						if until, ok := ctx.Deadline(); !ok || !until.Equal(deadline) {
							t.Error("admission RPC lost the trusted header deadline")
						}
						if calls.Add(1) == 1 {
							close(started)
						}
						return controlv1.ServiceClientCertificateDecision{Allowed: true, ValidUntil: time.Now().Add(time.Hour)}, nil
					}}
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
				// advance the fake clock after the first RPC is waiting to retry.
				time.Sleep(time.Second)
				synctest.Wait()
				if err := serviceHTTPAwait(t, replies); err != nil {
					t.Fatal(err)
				}
				count := calls.Load()
				if count < 2 {
					t.Fatal("fixture did not exercise newer pending validity windows", count)
				}
				time.Sleep(time.Second)
				synctest.Wait()
				if calls.Load() != count || forwarded.Load() != 0 {
					t.Fatal("new validity windows extended pending admission", calls.Load(), count, forwarded.Load())
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
				f.Control = serviceHTTPAdmissionControl{authorize: func(context.Context, string, string, credentials.ServiceRunToken, controlv1.AuthorizeServiceHTTPVisitorRequest) (controlv1.ServiceClientCertificateDecision, error) {
					calls.Add(1)
					return controlv1.ServiceClientCertificateDecision{Allowed: false, ValidUntil: time.Now()}, nil
				}}
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
				request.Header.Set(publisherproxy.ReadinessProbeHeader, proof.HeaderValue())
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

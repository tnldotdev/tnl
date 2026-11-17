package stream

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/publisher/requestlimit"
	"github.com/tnldotdev/tnl/internal/testutil/visitorfixture"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestHTTPStreamClosesEveryOwnedTargetSocket(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const hostname = "service.example.test"
		certificate := visitorfixture.Certificate(t, hostname)
		incoming, visitor := net.Pipe()
		defer incoming.Close()
		defer visitor.Close()
		closed := make(chan struct{}, 2)
		endpoint := Stream{Protocol: config.ProtocolHTTP, Hostname: hostname, Target: "127.0.0.1:3000",
			TLS: &tls.Config{Certificates: []tls.Certificate{certificate}},
			Visitor: HTTPVisitor{Frontend: visitorFrontendFunc(func(_ context.Context, _ *tls.Conn, target HTTPTarget) error {
				// application work can begin after visitor setup's deadline. that
				// finished setup must not close a newly selected target socket.
				time.Sleep(11 * time.Second)
				for range 2 {
					raw, backend := net.Pipe()
					go func() {
						defer backend.Close()
						_, _ = io.Copy(io.Discard, backend)
						closed <- struct{}{}
					}()
					socket := target.track(raw)
					if err := socket.SetWriteDeadline(time.Now().Add(time.Second)); err != nil {
						return err
					}
					if _, err := socket.Write([]byte("application")); err != nil {
						return err
					}
				}
				return nil
			})}}
		done := make(chan error, 1)
		go func() { done <- endpoint.Forward(t.Context(), incoming) }()
		client := tls.Client(visitor, &tls.Config{RootCAs: visitorfixture.Roots(t, certificate), ServerName: hostname})
		if err := client.HandshakeContext(t.Context()); err != nil {
			t.Fatal(err)
		}
		if err := <-done; err != nil {
			t.Fatal(err)
		}
		for range 2 {
			<-closed
		}
	})
}

func TestConnectorHTTPApplicationClaimsCommitAfterBudget(t *testing.T) {
	const hostname = "service.example.test"
	certificate := visitorfixture.Certificate(t, hostname)
	budget, err := requestlimit.NewHTTP(&controlv1.ProjectHTTPApplicationLimits{Concurrency: new(1)})
	if err != nil {
		t.Fatal(err)
	}
	held, ok := budget.Reserve(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "https://"+hostname+"/held", nil))
	if !ok {
		t.Fatal("did not reserve sole application slot")
	}
	defer held.Finish()
	var prepared, committed, applications atomic.Int32
	transport := &http.Transport{MaxConnsPerHost: 1,
		TLSClientConfig: &tls.Config{RootCAs: visitorfixture.Roots(t, certificate)},
		DialContext: func(context.Context, string, string) (net.Conn, error) {
			incoming, visitor := net.Pipe()
			stream := Stream{Protocol: config.ProtocolHTTP, Hostname: hostname, HTTPRequests: budget,
				TLS: &tls.Config{Certificates: []tls.Certificate{certificate}},
				Visitor: ConnectorVisitor{Admission: &AdmissionFixture{Check: func(context.Context) (Decision, error) {
					return Decision{Allowed: true, ValidUntil: time.Now().Add(time.Minute)}, nil
				}}},
				PrepareRequest: func(*http.Request) (func(context.Context) error, error) {
					prepared.Add(1)
					return func(context.Context) error { committed.Add(1); return nil }, nil
				},
				Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					applications.Add(1)
					w.WriteHeader(http.StatusNoContent)
				})}
			done := make(chan error, 1)
			go func() {
				defer incoming.Close()
				done <- stream.Forward(t.Context(), incoming)
			}()
			t.Cleanup(func() {
				_ = visitor.Close()
				select {
				case <-done:
				case <-time.After(5 * time.Second):
					t.Error("connector HTTP stream did not join")
				}
			})
			return visitor, nil
		}}
	t.Cleanup(transport.CloseIdleConnections)
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	visit := func(want int) {
		t.Helper()
		response, err := client.Get("https://" + hostname + "/callback")
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, response.Body)
		_ = response.Body.Close()
		if response.StatusCode != want {
			t.Fatal("connector request returned", response.StatusCode, "want", want)
		}
	}
	visit(http.StatusServiceUnavailable)
	if prepared.Load() != 1 || committed.Load() != 0 || applications.Load() != 0 {
		t.Fatal("rejected connector request committed application claim", prepared.Load(), committed.Load(), applications.Load())
	}
	held.Finish()
	visit(http.StatusNoContent)
	if prepared.Load() != 2 || committed.Load() != 1 || applications.Load() != 1 {
		t.Fatal("admitted connector request did not commit immediately before application", prepared.Load(), committed.Load(), applications.Load())
	}
}

type stoppedConnectorAdmission struct {
	AdmissionFixture
	stopped chan struct{}
}

func (a *stoppedConnectorAdmission) Stop() { close(a.stopped) }

func TestConnectorHTTPStreamJoinsTargetDialAfterHandlerReturns(t *testing.T) {
	for _, protocol := range []string{"http1", "http2"} {
		t.Run(protocol, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				const hostname = "service.example.test"
				certificate := visitorfixture.Certificate(t, hostname)
				incoming, visitor := net.Pipe()
				defer incoming.Close()
				defer visitor.Close()
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				entered, finished := make(chan struct{}), make(chan struct{})
				var dialContext context.Context
				releaseDial := make(chan struct{})
				release := sync.OnceFunc(func() { close(releaseDial) })
				defer release()
				type dialContextKey struct{}
				admission := &stoppedConnectorAdmission{
					stopped: make(chan struct{}),
					AdmissionFixture: AdmissionFixture{Check: func(ctx context.Context) (Decision, error) {
						if ctx.Value(dialContextKey{}) != nil {
							dialContext = ctx
							close(entered)
							defer close(finished)
							// net/http can return the canceled request while its target
							// dial is still running. hold that entered work before dialing.
							<-releaseDial
							return Decision{}, ErrEndpoint
						}
						return Decision{Allowed: true, ValidUntil: time.Now().Add(time.Minute)}, nil
					}},
				}
				stream := Stream{
					Protocol: config.ProtocolHTTP, Hostname: hostname, Target: "target.example.test:80",
					TLS:     &tls.Config{Certificates: []tls.Certificate{certificate}},
					Visitor: ConnectorVisitor{Admission: admission},
					AdmitRequest: func(r *http.Request) error {
						// mark only the request's target dial, after request authorization.
						*r = *r.WithContext(context.WithValue(r.Context(), dialContextKey{}, true))
						return nil
					},
				}
				done := make(chan error, 1)
				go func() { done <- stream.Forward(ctx, incoming) }()
				transport := &http.Transport{
					ForceAttemptHTTP2: protocol == "http2",
					TLSClientConfig:   &tls.Config{RootCAs: visitorfixture.Roots(t, certificate)},
					DialContext:       func(context.Context, string, string) (net.Conn, error) { return visitor, nil },
				}
				defer transport.CloseIdleConnections()
				replied := make(chan struct{})
				go func() {
					defer close(replied)
					request, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+hostname+"/", nil)
					if err != nil {
						t.Error(err)
						return
					}
					response, err := transport.RoundTrip(request)
					if err == nil {
						response.Body.Close()
					}
				}()
				<-entered
				cancel()
				<-replied
				// the request has returned and the dial's owner is canceled, but
				// cancellation alone cannot release an independently blocked dial.
				<-dialContext.Done()
				synctest.Wait()
				select {
				case err := <-done:
					t.Fatal("connector stream returned before its target dial joined", err)
				default:
				}
				release()
				if err := <-done; !failure.Only(err, context.Canceled) {
					t.Fatal("aborted HTTP forwarding lost cancellation or acquired an independent failure", err)
				}
				select {
				case <-admission.stopped:
				default:
					t.Fatal("connector stream returned before stopping admission")
				}
				select {
				case <-finished:
				default:
					t.Fatal("connector stream left target work running")
				}
			})
		})
	}
}

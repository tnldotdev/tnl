package stream

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/testutil/visitorfixture"
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
				if err := <-done; err != nil {
					t.Fatal(err)
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

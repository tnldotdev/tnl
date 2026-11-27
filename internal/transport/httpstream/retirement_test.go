package httpstream_test

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/tnldotdev/tnl/internal/testutil/visitorfixture"
	"github.com/tnldotdev/tnl/internal/transport/httpstream"
)

func TestRetirementBoundsStalledHTTP1TLSResponse(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		certificate := visitorfixture.Certificate(t, "visitor.example.test")
		raw, visitor := net.Pipe()
		defer raw.Close()
		defer visitor.Close()
		entered, finished := make(chan struct{}), make(chan struct{})
		served := make(chan error, 1)
		go func() {
			secure := tls.Server(raw, &tls.Config{Certificates: []tls.Certificate{certificate}, NextProtos: []string{"http/1.1"}})
			served <- httpstream.ServeHandler(t.Context(), secure, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				defer close(finished)
				httpstream.RetireConnection(w, r, time.Now().Add(time.Second))
				close(entered)
				// the visitor never reads the response, including TLS framing.
				_, _ = io.WriteString(w, strings.Repeat("response", 1024))
			}), httpstream.Drain{}, 0)
		}()
		secure := tls.Client(visitor, &tls.Config{RootCAs: visitorfixture.Roots(t, certificate), ServerName: "visitor.example.test", NextProtos: []string{"http/1.1"}})
		if err := secure.Handshake(); err != nil {
			t.Fatal(err)
		}
		if _, err := io.WriteString(secure, "GET / HTTP/1.1\r\nHost: visitor.example.test\r\n\r\n"); err != nil {
			t.Fatal(err)
		}
		<-entered
		synctest.Wait()
		select {
		case err := <-served:
			t.Fatal("retirement skipped its pending response", err)
		default:
		}
		time.Sleep(time.Second)
		if err := <-served; !errors.Is(err, context.DeadlineExceeded) {
			t.Fatal("stalled TLS response lost its retirement deadline", err)
		}
		select {
		case <-finished:
		default:
			t.Fatal("retirement did not join the stalled response handler")
		}
	})
}

func TestHTTP2RetirementDrainsSiblingsAndJoinsBoundedCleanup(t *testing.T) {
	for _, mode := range []string{"finish", "connection-deadline", "earlier-run-deadline"} {
		t.Run(mode, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				certificate := visitorfixture.Certificate(t, "visitor.example.test")
				client, server := net.Pipe()
				defer client.Close()
				defer server.Close()
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				released, canceled := make(chan struct{}), make(chan struct{})
				release := sync.OnceFunc(func() { close(released) })
				defer release()
				draining := make(chan struct{})
				until := time.Now().Add(time.Second)
				var entered atomic.Int32
				served := make(chan error, 1)
				go func() {
					secure := tls.Server(server, &tls.Config{Certificates: []tls.Certificate{certificate}, NextProtos: []string{"h2"}})
					served <- httpstream.ServeHandler(ctx, secure, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						entered.Add(1)
						w.Header().Set("Trailer", "X-Final")
						if r.URL.Path == "/retire" {
							deadline := until
							if mode == "earlier-run-deadline" {
								deadline = time.Now().Add(time.Hour)
							}
							httpstream.RetireConnection(w, r, deadline)
							// repeated callers cannot extend a previously published bound.
							httpstream.RetireConnection(w, r, time.Now().Add(2*time.Hour))
							_, _ = io.WriteString(w, "denied")
							w.Header().Set("X-Final", "retired")
							return
						}
						_, _ = io.WriteString(w, "first-")
						_ = http.NewResponseController(w).Flush()
						if mode != "finish" {
							<-r.Context().Done()
							close(canceled)
						}
						<-released
						_, _ = io.WriteString(w, "last")
						w.Header().Set("X-Final", "complete")
					}), httpstream.Drain{Started: draining, Deadline: func() time.Time { return until }}, 0)
				}()
				protocols := new(http.Protocols)
				protocols.SetHTTP2(true)
				transport := &http.Transport{Protocols: protocols,
					TLSClientConfig: &tls.Config{RootCAs: visitorfixture.Roots(t, certificate)},
					DialContext:     func(context.Context, string, string) (net.Conn, error) { return client, nil }}
				connection, err := transport.NewClientConn(ctx, "https", "visitor.example.test:443")
				if err != nil {
					t.Fatal(err)
				}
				defer connection.Close()
				request := func(path string) *http.Request {
					r, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://visitor.example.test"+path, nil)
					if err != nil {
						t.Fatal(err)
					}
					return r
				}
				held, err := connection.RoundTrip(request("/held"))
				if err != nil {
					t.Fatal(err)
				}
				defer held.Body.Close()
				denied, err := connection.RoundTrip(request("/retire"))
				if err != nil {
					t.Fatal(err)
				}
				body, readErr := io.ReadAll(denied.Body)
				if err := errors.Join(readErr, denied.Body.Close()); err != nil || string(body) != "denied" ||
					denied.Trailer.Get("X-Final") != "retired" || denied.Header.Get("Connection") != "" {
					t.Fatal("retirement lost response framing or sent an HTTP/1 connection header", string(body), err)
				}
				synctest.Wait()
				if mode == "earlier-run-deadline" {
					close(draining)
				}
				if mode != "finish" {
					time.Sleep(time.Until(until))
					<-canceled
					synctest.Wait()
				}
				select {
				case err := <-served:
					t.Fatal("retirement returned before its sibling handler joined", err)
				default:
				}
				if response, err := connection.RoundTrip(request("/late")); err == nil {
					_ = response.Body.Close()
					t.Fatal("retired HTTP/2 connection accepted another request")
				}
				release()
				body, readErr = io.ReadAll(held.Body)
				err = <-served
				if mode == "finish" {
					if err != nil || readErr != nil || string(body) != "first-last" || held.Trailer.Get("X-Final") != "complete" {
						t.Fatal("retirement interrupted its admitted sibling", err, readErr, string(body))
					}
				} else if !errors.Is(err, context.DeadlineExceeded) {
					t.Fatal("retirement lost its earliest deadline", err)
				}
				if entered.Load() != 2 {
					t.Fatal("retirement admitted new application work", entered.Load())
				}
			})
		})
	}
}

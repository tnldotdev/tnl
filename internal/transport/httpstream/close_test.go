package httpstream_test

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"testing"
	"testing/synctest"
	"time"

	"github.com/tnldotdev/tnl/internal/testutil/visitorfixture"
	"github.com/tnldotdev/tnl/internal/transport/httpstream"
)

func TestHandlerCloseReleasesHTTP1AndHTTP2VisitorConnections(t *testing.T) {
	for _, h2 := range []bool{false, true} {
		for _, owned := range []bool{false, true} {
			t.Run(fmt.Sprintf("http2=%t/owned=%t", h2, owned), func(t *testing.T) {
				synctest.Test(t, func(t *testing.T) {
					certificate := visitorfixture.Certificate(t, "visitor.example.test")
					client, server := net.Pipe()
					ctx, cancel := context.WithCancel(t.Context())
					defer cancel()
					defer client.Close()
					defer server.Close()
					served := make(chan error, 1)
					go func() {
						secure := tls.Server(server, &tls.Config{Certificates: []tls.Certificate{certificate}, NextProtos: []string{"h2", "http/1.1"}})
						served <- httpstream.ServeHandler(ctx, secure, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
							if owned {
								httpstream.RetireConnection(w, r, time.Now().Add(5*time.Second))
							} else {
								w.Header().Set("Connection", "close")
							}
							_, _ = io.WriteString(w, "finite")
						}), httpstream.Drain{}, 0)
					}()
					transport := &http.Transport{
						ForceAttemptHTTP2: h2,
						TLSClientConfig:   &tls.Config{RootCAs: visitorfixture.Roots(t, certificate)},
						DialContext:       func(context.Context, string, string) (net.Conn, error) { return client, nil },
					}
					defer transport.CloseIdleConnections()
					response, err := (&http.Client{Transport: transport}).Get("https://visitor.example.test/")
					if err != nil {
						t.Fatal(err)
					}
					body, err := io.ReadAll(response.Body)
					_ = response.Body.Close()
					if err != nil || string(body) != "finite" || (response.ProtoMajor == 2) != h2 {
						t.Fatal("response did not finish on the intended protocol", string(body), err, response.Proto)
					}
					if owned && !h2 {
						if !response.Close {
							t.Fatal("HTTP/1 retirement did not announce its close before flushing")
						}
						// net.Pipe cannot buffer simultaneous TLS close_notify
						// writes. finish the visitor's announced HTTP/1 close.
						_ = client.Close()
					}
					select {
					case err := <-served:
						if err != nil {
							t.Fatal("finite response failed cleanup", err)
						}
					case <-time.After(6 * time.Second):
						cancel()
						<-served
						t.Fatal("finite response retained its visitor connection")
					}
				})
			})
		}
	}
}

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
		t.Run(fmt.Sprintf("http2=%t", h2), func(t *testing.T) {
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
					served <- httpstream.ServeHandler(ctx, secure, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
						w.Header().Set("Connection", "close")
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

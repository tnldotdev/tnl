package httpstream_test

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/httpstream"
	"github.com/tnldotdev/tnl/internal/localproxy"
	"github.com/tnldotdev/tnl/internal/observability"
	"github.com/tnldotdev/tnl/internal/testutil"
)

func observedProxyAddress(t *testing.T, kind, backend string, m *observability.Metrics) (string, *tls.Config) {
	t.Helper()
	ctx, cancel := context.WithCancel(observability.WithMetrics(t.Context(), m))
	t.Cleanup(cancel)
	if kind == "localproxy" {
		handler, err := localproxy.NewWithMounts(backend, "proxy.example.test", 1, nil)
		if err != nil {
			t.Fatal(err)
		}
		server := httptest.NewUnstartedServer(observability.PublisherHTTP(handler))
		server.Config.BaseContext = func(net.Listener) context.Context { return ctx }
		root, certificate := testutil.TLSCertificate(t, []string{"proxy.example.test"}, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth})
		roots := x509.NewCertPool()
		roots.AppendCertsFromPEM(root)
		server.TLS = &tls.Config{Certificates: []tls.Certificate{certificate}}
		server.StartTLS()
		t.Cleanup(server.Close)
		return server.Listener.Addr().String(), &tls.Config{ServerName: "proxy.example.test", RootCAs: roots}
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	target, err := url.Parse(backend)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_ = httpstream.Serve(ctx, conn, target, func(ctx context.Context) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "tcp", target.Host)
		}, nil)
	}()
	t.Cleanup(func() {
		cancel()
		_ = listener.Close()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("HTTP stream worker did not stop")
		}
	})
	return listener.Addr().String(), nil
}

func observedMetric(t *testing.T, m *observability.Metrics, name string, labels map[string]string) float64 {
	t.Helper()
	families, err := m.Gather()
	if err != nil {
		t.Fatal(err)
	}
	var value float64
	for _, family := range families {
		if family.GetName() != name {
			continue
		}
		for _, point := range family.Metric {
			attrs := map[string]string{}
			for _, label := range point.Label {
				attrs[label.GetName()] = label.GetValue()
			}
			match := true
			for key, want := range labels {
				match = match && attrs[key] == want
			}
			if !match {
				continue
			}
			if point.Histogram != nil {
				value += float64(point.GetHistogram().GetSampleCount())
			} else if point.Counter != nil {
				value += point.GetCounter().GetValue()
			} else {
				value += point.GetGauge().GetValue()
			}
		}
	}
	return value
}

func awaitHTTPCompletion(t *testing.T, m *observability.Metrics, status, outcome string) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	labels := map[string]string{"http_response_status_code": status, "tnl_outcome": outcome, "tnl_response_origin": "local_service"}
	for {
		if observedMetric(t, m, "tnl_publisher_http_request_duration_seconds", labels) == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("HTTP completion has wrong outcome", status, outcome)
		}
		time.Sleep(time.Millisecond)
	}
	if observedMetric(t, m, "tnl_publisher_http_requests_active", nil) != 0 {
		t.Fatal("HTTP active count leaked")
	}
}

func TestNativeProxyHEADAndInformationalHeadersHaveNoInventedBody(t *testing.T) {
	for _, kind := range []string{"localproxy", "httpstream"} {
		t.Run(kind, func(t *testing.T) {
			target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != "HEAD" {
					t.Error("HEAD changed")
				}
				w.WriteHeader(103)
				w.Header().Set("Content-Length", "123")
				w.WriteHeader(200)
			}))
			defer target.Close()
			m := observability.New("publisher")
			defer m.Shutdown(context.Background())
			address, verifier := observedProxyAddress(t, kind, target.URL, m)
			scheme := "http"
			if verifier != nil {
				scheme = "https"
			}
			request, _ := http.NewRequestWithContext(t.Context(), "HEAD", scheme+"://"+address+"/secret", nil)
			// keep the connection open through the completion observation; closing
			// it first races this framing assertion with visitor cancellation.
			request.Host = "proxy.example.test"
			transport := &http.Transport{TLSClientConfig: verifier}
			defer transport.CloseIdleConnections()
			client := &http.Client{Timeout: time.Second, Transport: transport}
			response, err := client.Do(request)
			if err != nil {
				t.Fatal(err)
			}
			body, err := io.ReadAll(response.Body)
			_ = response.Body.Close()
			if err != nil || response.StatusCode != 200 || len(body) != 0 || response.ContentLength != 123 {
				t.Fatal("HEAD framing changed", response.StatusCode, len(body), err)
			}
			awaitHTTPCompletion(t, m, "200", "success")
			if observedMetric(t, m, "tnl_publisher_http_response_headers_duration_seconds", map[string]string{"http_response_status_code": "200"}) != 1 || observedMetric(t, m, "tnl_publisher_forwarded_bytes_total", nil) != 0 {
				t.Fatal("informational headers or HEAD invented target body bytes")
			}
		})
	}
}

func TestNativeProxyUpgradeHalfCloseAndSocketFailuresAreObserved(t *testing.T) {
	for _, kind := range []string{"localproxy", "httpstream"} {
		for _, fault := range []string{"half_close", "backend_reset", "visitor_reset"} {
			t.Run(kind+"/"+fault, func(t *testing.T) {
				reset := make(chan struct{})
				targetDone := make(chan struct{})
				target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					defer close(targetDone)
					conn, rw, err := http.NewResponseController(w).Hijack()
					if err != nil {
						t.Error(err)
						return
					}
					defer conn.Close()
					_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
					_, _ = io.WriteString(rw, "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n")
					if err := rw.Flush(); err != nil {
						t.Error(err)
						return
					}
					if fault == "backend_reset" {
						<-reset
						_ = conn.(*net.TCPConn).SetLinger(0)
						return
					}
					payload, err := io.ReadAll(conn)
					if fault == "half_close" {
						if err != nil || string(payload) != "payload" {
							t.Error("upgrade request half-close changed", string(payload), err)
							return
						}
						_, _ = io.WriteString(conn, "ack:payload")
						_ = conn.(*net.TCPConn).CloseWrite()
					}
				}))
				defer target.Close()
				m := observability.New("publisher")
				defer m.Shutdown(context.Background())
				address, verifier := observedProxyAddress(t, kind, target.URL, m)
				raw, err := net.DialTimeout("tcp", address, time.Second)
				if err != nil {
					t.Fatal(err)
				}
				defer raw.Close()
				client := raw
				if verifier != nil {
					secured := tls.Client(raw, verifier)
					if err := secured.HandshakeContext(t.Context()); err != nil {
						t.Fatal(err)
					}
					client = secured
				}
				defer client.Close()
				_ = client.SetDeadline(time.Now().Add(3 * time.Second))
				_, _ = fmt.Fprint(client, "GET /secret HTTP/1.1\r\nHost: proxy.example.test\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n")
				reader := bufio.NewReader(client)
				response, err := http.ReadResponse(reader, &http.Request{Method: "GET"})
				if err != nil || response.StatusCode != 101 {
					t.Fatal("upgrade failed", err)
				}
				outcome := "error"
				switch fault {
				case "half_close":
					_, _ = io.WriteString(client, "payload")
					if err := client.(interface{ CloseWrite() error }).CloseWrite(); err != nil {
						t.Fatal(err)
					}
					body, err := io.ReadAll(reader)
					if err != nil || string(body) != "ack:payload" {
						t.Fatal("upgrade response half-close changed", string(body), err)
					}
					outcome = "success"
				case "backend_reset":
					close(reset)
					_, _ = io.ReadAll(reader)
				case "visitor_reset":
					_ = raw.(*net.TCPConn).SetLinger(0)
					_ = raw.Close()
				}
				awaitHTTPCompletion(t, m, "101", outcome)
				select {
				case <-targetDone:
				case <-time.After(time.Second):
					t.Fatal("upgrade backend copy did not finish")
				}
				if fault == "half_close" {
					for direction, want := range map[string]float64{"visitor_to_target": 7, "target_to_visitor": 11} {
						if got := observedMetric(t, m, "tnl_publisher_forwarded_bytes_total", map[string]string{"tnl_direction": direction}); got != want {
							t.Fatal("upgrade bytes counted twice or included headers", direction, got)
						}
					}
				}
			})
		}
	}
}

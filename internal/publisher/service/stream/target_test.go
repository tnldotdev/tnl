package stream_test

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/observability/inspection"
	servicestream "github.com/tnldotdev/tnl/internal/publisher/service/stream"
	"github.com/tnldotdev/tnl/internal/transport/httpstream"
)

func TestManagedHTTPBaseTargetPreservesTLSMinimum(t *testing.T) {
	certificates := serviceCertificates(t)
	const hostname = "web.production.storefront.example.test"
	const targetHostname = "backend.production.storefront.example.test"
	for _, test := range []struct {
		name    string
		version uint16
	}{
		{"tls12-rejected", tls.VersionTLS12},
		{"tls13-client-certificate", tls.VersionTLS13},
	} {
		t.Run(test.name, func(t *testing.T) {
			var requests atomic.Int32
			target := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				if r.TLS == nil || r.TLS.Version != tls.VersionTLS13 || r.TLS.ServerName != targetHostname {
					t.Error("base target lost its configured TLS minimum or server identity")
				}
				if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 || !bytes.Equal(r.TLS.PeerCertificates[0].Raw, certificates.client.Certificate[0]) {
					t.Error("base target lost its supplied client certificate")
				}
				_, _ = io.WriteString(w, "target TLS preserved")
			}))
			target.TLS = &tls.Config{Certificates: []tls.Certificate{certificates.server}, MinVersion: test.version, MaxVersion: test.version}
			if test.version == tls.VersionTLS13 {
				target.TLS.ClientAuth, target.TLS.ClientCAs = tls.RequireAndVerifyClientCert, certificates.roots
			}
			target.StartTLS()
			defer target.Close()
			server := servicestream.Stream{
				Protocol: config.ProtocolHTTP, Hostname: hostname, Target: target.Listener.Addr().String(),
				TLS: &tls.Config{Certificates: []tls.Certificate{certificates.server}},
				TargetTLS: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: certificates.roots, ServerName: targetHostname,
					Certificates: []tls.Certificate{certificates.client}},
				Visitor: servicestream.ConnectorVisitor{Admission: servicestream.AdmissionFixture{Check: func(context.Context) (servicestream.Decision, error) {
					return servicestream.Decision{Allowed: true, ValidUntil: time.Now().Add(time.Minute)}, nil
				}}},
			}
			address := managedPublisherListener(t, server)
			transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: certificates.roots, ServerName: hostname}}
			defer transport.CloseIdleConnections()
			client := &http.Client{Transport: transport, Timeout: 3 * time.Second}
			request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "https://"+address+"/", nil)
			if err != nil {
				t.Fatal(err)
			}
			response, err := client.Do(request)
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			body, err := io.ReadAll(response.Body)
			if err != nil {
				t.Fatal(err)
			}
			if test.version == tls.VersionTLS12 {
				if response.StatusCode != http.StatusBadGateway || requests.Load() != 0 {
					t.Fatal("TLS-1.2-only backend bypassed the supplied TLS 1.3 minimum", response.Status, requests.Load())
				}
				return
			}
			if response.StatusCode != http.StatusOK || string(body) != "target TLS preserved" || requests.Load() != 1 {
				t.Fatal("same certificate could not serve TLS 1.3 with the supplied client identity", response.Status, string(body), requests.Load())
			}
		})
	}
}

func TestManagedVisitorTLSWithPlaintextHTTPTarget(t *testing.T) {
	for _, h2 := range []bool{false, true} {
		name := "http1"
		if h2 {
			name = "http2"
		}
		t.Run(name, func(t *testing.T) { testManagedVisitorTLSWithPlaintextHTTPTarget(t, h2) })
	}
}

func testManagedVisitorTLSWithPlaintextHTTPTarget(t *testing.T, h2 bool) {
	certificates := serviceCertificates(t)
	const host = "web.production.storefront.example.test"
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS != nil {
			t.Error("plaintext target unexpectedly used TLS")
		}
		if r.Header.Get(httpstream.ReadinessProbeHeader) != "" || httpstream.IsReadinessProbe(r) {
			t.Error("connector request supplied an owner readiness proof")
		}
		_, _ = io.WriteString(w, "plaintext backend")
	}))
	defer target.Close()
	summaries := make(chan inspection.Summary, 2)
	var observed atomic.Int32
	var replaced atomic.Bool
	server := servicestream.Stream{Protocol: config.ProtocolHTTP, Hostname: host, Target: strings.TrimPrefix(target.URL, "http://"),
		InspectionMode: inspection.SummaryMode, ObserveSummary: func(summary inspection.Summary) { summaries <- summary },
		HTTPResponseHooks: httpstream.ResponseHooks{Observe: func(response *http.Response) error {
			if response.Request.Host != host || response.Request.URL.Host != target.Listener.Addr().String() {
				t.Error("connector hooks lost the admitted hostname or changed target identity")
			}
			observed.Add(1)
			return nil
		}},
		AdmitRequest: func(*http.Request) error {
			if replaced.Load() {
				return errors.New("app owner replaced")
			}
			return nil
		},
		TLS: &tls.Config{Certificates: []tls.Certificate{certificates.server}},
		Visitor: servicestream.ConnectorVisitor{Admission: servicestream.AdmissionFixture{Check: func(context.Context) (servicestream.Decision, error) {
			return servicestream.Decision{Allowed: true, ValidUntil: time.Now().Add(time.Minute)}, nil
		}}}}
	address := managedPublisherListener(t, server)
	transport := &http.Transport{ForceAttemptHTTP2: h2, TLSClientConfig: &tls.Config{RootCAs: certificates.roots, ServerName: host}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 3 * time.Second}
	request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "https://"+address+"/observed?token=private", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set(httpstream.ReadinessProbeHeader, "forged-owner-proof")
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	wantProtocol := 1
	if h2 {
		wantProtocol = 2
	}
	if err != nil || string(body) != "plaintext backend" || response.ProtoMajor != wantProtocol {
		t.Fatalf("verified visitor to plaintext target: %q %v", body, err)
	}
	if observed.Load() != 1 {
		t.Fatal("connector HTTP bypassed run response hooks", observed.Load())
	}
	select {
	case summary := <-summaries:
		if summary.Protocol != inspection.HTTP || summary.Origin != "local_service" || summary.Path != "/observed" ||
			summary.Status != http.StatusOK || summary.Result != inspection.ResultOK {
			t.Fatal("connector HTTP lost the body-free response summary", summary)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("connector HTTP did not emit its request summary")
	}
	replaced.Store(true)
	denied, err := client.Get("https://" + address + "/after-replacement")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, denied.Body)
	_ = denied.Body.Close()
	if denied.StatusCode != http.StatusServiceUnavailable {
		t.Fatal("connector request crossed application owner replacement", denied.Status)
	}
	// omitting target TLS never admits a plaintext visitor.
	plain, err := net.DialTimeout("tcp", address, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer plain.Close()
	_ = plain.SetDeadline(time.Now().Add(time.Second))
	_, _ = io.WriteString(plain, "GET / HTTP/1.1\r\nHost: "+host+"\r\n\r\n")
	if _, err := http.ReadResponse(bufio.NewReader(plain), &http.Request{Method: "GET"}); err == nil {
		t.Fatal("omitting target.tls disabled managed visitor TLS")
	}
}

type httpFrontendFunc func(context.Context, *tls.Conn, servicestream.HTTPTarget) error

func (f httpFrontendFunc) Forward(ctx context.Context, visitor *tls.Conn, target servicestream.HTTPTarget) error {
	return f(ctx, visitor, target)
}

func TestPublicHTTPFrontendIsCalledOnlyAfterNativeTLS(t *testing.T) {
	certificates := serviceCertificates(t)
	const host = "web.production.storefront.example.test"
	var called atomic.Int64
	frontend := httpFrontendFunc(func(_ context.Context, visitor *tls.Conn, target servicestream.HTTPTarget) error {
		if !visitor.ConnectionState().HandshakeComplete || target.Transport.Protocol != config.ProtocolHTTP {
			t.Error("HTTP frontend bypassed native TLS or protocol ownership")
		}
		// a frontend must read the request before replying. an unsolicited
		// response can race net/http assigning the newly handshaken connection.
		request, err := http.ReadRequest(bufio.NewReader(visitor))
		if err != nil {
			return err
		}
		defer request.Body.Close()
		called.Add(1)
		_, err = io.WriteString(visitor, "HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
		return err
	})
	server := servicestream.Stream{Protocol: config.ProtocolHTTP, Hostname: host, Target: "127.0.0.1:1", TLS: &tls.Config{Certificates: []tls.Certificate{certificates.server}}, Visitor: servicestream.HTTPVisitor{Frontend: frontend}}
	address := managedPublisherListener(t, server)
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: certificates.roots, ServerName: host}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: time.Second}
	response, err := client.Get("https://" + address)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != 503 || called.Load() != 1 {
		t.Fatal("typed HTTP frontend was not used")
	}
	plain, err := net.DialTimeout("tcp", address, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	_ = plain.SetDeadline(time.Now().Add(time.Second))
	_, _ = io.WriteString(plain, "GET / HTTP/1.1\r\nHost: "+host+"\r\n\r\n")
	_, _ = io.ReadAll(plain)
	_ = plain.Close()
	if called.Load() != 1 {
		t.Fatal("plaintext reached the HTTP frontend")
	}
	server.Visitor = servicestream.HTTPVisitor{}
	if response, err := client.Get("https://" + managedPublisherListener(t, server)); err == nil {
		_ = response.Body.Close()
		t.Fatal("missing HTTP frontend became a target fallback")
	}
}

func TestConnectorHTTPInlineHandlerUsesAdmittedTLSStream(t *testing.T) {
	for _, h2 := range []bool{false, true} {
		name := "http1"
		if h2 {
			name = "http2"
		}
		t.Run(name, func(t *testing.T) {
			certificates := serviceCertificates(t)
			const hostname = "web.production.storefront.example.test"
			var called atomic.Int64
			var revoked atomic.Bool
			server := servicestream.Stream{
				Protocol: config.ProtocolHTTP, Hostname: hostname,
				TLS: &tls.Config{Certificates: []tls.Certificate{certificates.server}},
				Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					called.Add(1)
					if r.Host != "127.0.0.1:8443" || r.TLS == nil || r.TLS.ServerName != hostname {
						t.Error("connector HTTP handler lost local authority or TLS identity")
					}
					_, _ = io.WriteString(w, "inline connector")
				}),
				Visitor: servicestream.ConnectorVisitor{Admission: servicestream.AdmissionFixture{Check: func(context.Context) (servicestream.Decision, error) {
					return servicestream.Decision{Allowed: !revoked.Load(), ValidUntil: time.Now().Add(time.Minute)}, nil
				}}},
			}
			address := managedPublisherListener(t, server)
			transport := &http.Transport{ForceAttemptHTTP2: h2, TLSClientConfig: &tls.Config{RootCAs: certificates.roots, ServerName: hostname}}
			defer transport.CloseIdleConnections()
			client := &http.Client{Transport: transport, Timeout: 3 * time.Second}
			request, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, "https://"+address+"/", nil)
			request.Host = "127.0.0.1:8443"
			response, err := client.Do(request)
			if err != nil {
				t.Fatal(err)
			}
			body, err := io.ReadAll(response.Body)
			response.Body.Close()
			wantProtocol := 1
			if h2 {
				wantProtocol = 2
			}
			if err != nil || response.StatusCode != http.StatusOK || string(body) != "inline connector" || response.ProtoMajor != wantProtocol || called.Load() != 1 {
				t.Fatal("inline connector HTTP changed", response.Status, response.Proto, string(body), err)
			}
			revoked.Store(true)
			request, _ = http.NewRequestWithContext(t.Context(), http.MethodGet, "https://"+address+"/after-revocation", nil)
			request.Host = "127.0.0.1:8443"
			if response, err := client.Do(request); err == nil {
				_, _ = io.Copy(io.Discard, response.Body)
				response.Body.Close()
				if response.StatusCode < 400 {
					t.Fatal("revoked connector reached the inline application")
				}
			}
			if called.Load() != 1 {
				t.Fatal("revoked connector invoked the HTTP handler", called.Load())
			}
		})
	}
}

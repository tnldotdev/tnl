package publisher_test

import (
	"bufio"
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/publisher"
)

func TestManagedVisitorTLSWithPlaintextHTTPTarget(t *testing.T) {
	certificates := serviceCertificates(t)
	const host = "web.production.storefront.example.test"
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS != nil {
			t.Error("plaintext target unexpectedly used TLS")
		}
		_, _ = io.WriteString(w, "plaintext backend")
	}))
	defer target.Close()
	server := publisher.ServiceStream{Protocol: config.ProtocolHTTP, Hostname: host, Target: strings.TrimPrefix(target.URL, "http://"),
		TLS: &tls.Config{Certificates: []tls.Certificate{certificates.server}},
		Visitor: publisher.NativeVisitor{Admission: publisher.NativeAdmissionFixture{Check: func(context.Context) (publisher.ServiceVisitorDecision, error) {
			return publisher.ServiceVisitorDecision{Allowed: true, ValidUntil: time.Now().Add(time.Minute)}, nil
		}}}}
	address := managedPublisherListener(t, server)
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: certificates.roots, ServerName: host}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 3 * time.Second}
	response, err := client.Get("https://" + address)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil || string(body) != "plaintext backend" {
		t.Fatalf("verified visitor to plaintext target: %q %v", body, err)
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

type httpFrontendFunc func(context.Context, *tls.Conn, publisher.ServiceHTTPTarget) error

func (f httpFrontendFunc) Forward(ctx context.Context, visitor *tls.Conn, target publisher.ServiceHTTPTarget) error {
	return f(ctx, visitor, target)
}

func TestPublicHTTPFrontendIsCalledOnlyAfterNativeTLS(t *testing.T) {
	certificates := serviceCertificates(t)
	const host = "web.production.storefront.example.test"
	var called atomic.Int64
	frontend := httpFrontendFunc(func(_ context.Context, visitor *tls.Conn, target publisher.ServiceHTTPTarget) error {
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
	server := publisher.ServiceStream{Protocol: config.ProtocolHTTP, Hostname: host, Target: "127.0.0.1:1", TLS: &tls.Config{Certificates: []tls.Certificate{certificates.server}}, Visitor: publisher.PublicHTTPVisitor{Frontend: frontend}}
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
	server.Visitor = publisher.PublicHTTPVisitor{}
	if response, err := client.Get("https://" + managedPublisherListener(t, server)); err == nil {
		_ = response.Body.Close()
		t.Fatal("missing HTTP frontend became a target fallback")
	}
}

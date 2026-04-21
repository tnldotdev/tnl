package controltls

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/0xcadams/tnl/internal/testutil/integrationtest"
	"golang.org/x/crypto/acme"
)

func TestAutomaticCertificate(t *testing.T) {
	config, err := New(Config{
		Hostname: "control.example", StateDir: t.TempDir(),
		DirectoryURL: "https://acme.example/directory", Email: "operator@example.com", AcceptTerms: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if config.GetCertificate == nil {
		t.Fatal("automatic certificate callback is missing")
	}
	foundACME := false
	for _, protocol := range config.NextProtos {
		foundACME = foundACME || protocol == acme.ALPNProto
	}
	if !foundACME {
		t.Fatal("automatic certificate TLS-ALPN support is missing")
	}
}

func TestACMEHTTPClientRestoresOrderLocation(t *testing.T) {
	var origin string
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/order":
			response.Header().Set("Location", origin+"/order/1")
			response.WriteHeader(http.StatusCreated)
			_, _ = io.WriteString(response, `{"finalize":"`+origin+`/finalize"}`)
		case "/finalize":
			_, _ = io.WriteString(response, `{"status":"processing"}`)
		default:
			http.NotFound(response, request)
		}
	}))
	defer server.Close()
	origin = server.URL
	client := acmeHTTPClient(server.Client())

	created, err := client.Post(origin+"/order", "application/json", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(io.Discard, created.Body); err != nil {
		t.Fatal(err)
	}
	if err := created.Body.Close(); err != nil {
		t.Fatal(err)
	}
	finalized, err := client.Post(origin+"/finalize", "application/json", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer finalized.Body.Close()
	if location := finalized.Header.Get("Location"); location != origin+"/order/1" {
		t.Fatalf("finalize Location = %q", location)
	}
}

func TestIntegrationAutomaticControlCertificate(t *testing.T) {
	pebblePath := integrationtest.RequirePebble(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	dnsAddress := integrationtest.StartChallengeDNS(t)
	pebble := integrationtest.StartPebble(
		t, pebblePath, listener.Addr().(*net.TCPAddr).Port, dnsAddress,
	)
	tlsConfig, err := New(Config{
		Hostname: "control.tnl.test", StateDir: t.TempDir(), DirectoryURL: pebble.DirectoryURL(),
		Email: "operator@example.com", AcceptTerms: true, HTTPClient: pebble.HTTPClient(),
	})
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{
		Handler: http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
			_, _ = io.WriteString(response, "ready")
		}),
		TLSConfig: tlsConfig,
	}
	done := make(chan error, 1)
	go func() { done <- server.ServeTLS(listener, "", "") }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := server.Shutdown(ctx); err != nil {
			t.Error(err)
		}
		if err := <-done; !errors.Is(err, http.ErrServerClosed) {
			t.Errorf("serve control TLS: %v", err)
		}
	})

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: pebble.IssuerRoots(t), MinVersion: tls.VersionTLS13},
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return new(net.Dialer).DialContext(ctx, network, listener.Addr().String())
		},
	}
	t.Cleanup(transport.CloseIdleConnections)
	client := &http.Client{Transport: transport, Timeout: 30 * time.Second}
	response, err := client.Get("https://control.tnl.test/")
	if err != nil {
		t.Fatalf("request control API: %v; Pebble logs:\n%s", err, pebble.Logs())
	}
	body, readErr := io.ReadAll(response.Body)
	closeErr := response.Body.Close()
	if err := errors.Join(readErr, closeErr); err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK || string(body) != "ready" {
		t.Fatalf("control response = %s %q", response.Status, body)
	}
}

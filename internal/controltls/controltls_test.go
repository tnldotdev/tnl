package controltls

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
)

func TestAutomaticCertificateConfiguration(t *testing.T) {
	cache := newMemoryCache()
	source, err := New(Config{
		Hostname: "control.example", Cache: cache, DirectoryURL: "https://acme.example/directory",
		AdditionalHostnames: []string{"relay.example"},
		Email:               "operator@example.com", AcceptTerms: true, AccountKey: testAccountKey(t),
		RunLeader: func(ctx context.Context, run func(context.Context) error) error { return run(ctx) },
	})
	if err != nil {
		t.Fatal(err)
	}
	config := source.TLSConfig()
	if config.GetCertificate == nil || config.MinVersion != tls.VersionTLS13 || !slices.Contains(config.NextProtos, acme.ALPNProto) {
		t.Fatalf("automatic TLS config = %#v", config)
	}
	if source.Ready(time.Now()) {
		t.Fatal("source is ready without a certificate")
	}
	if err := cache.Put(t.Context(), "control.example", testCertificate(t, "control.example")); err != nil {
		t.Fatal(err)
	}
	if source.Ready(time.Now()) {
		t.Fatal("source is ready without every certificate")
	}
	if err := cache.Put(t.Context(), "relay.example", testCertificate(t, "relay.example")); err != nil {
		t.Fatal(err)
	}
	if !source.Ready(time.Now()) {
		t.Fatal("source is not ready with a certificate")
	}
	certificate, err := source.GetCertificate(&tls.ClientHelloInfo{ServerName: "control.example"})
	if err != nil || certificate.Leaf == nil || certificate.Leaf.DNSNames[0] != "control.example" {
		t.Fatalf("certificate = %#v, %v", certificate, err)
	}
	if _, err := source.GetCertificate(&tls.ClientHelloInfo{ServerName: "other.example"}); err == nil {
		t.Fatal("unexpected SNI was accepted")
	}
	mixedCaseCertificate, err := source.GetCertificate(&tls.ClientHelloInfo{ServerName: "CONTROL.EXAMPLE"})
	if err != nil || mixedCaseCertificate != certificate {
		t.Fatalf("mixed-case certificate = %#v, %v", mixedCaseCertificate, err)
	}
	relayCertificate, err := source.GetCertificate(&tls.ClientHelloInfo{ServerName: "relay.example"})
	if err != nil || relayCertificate.Leaf == nil || relayCertificate.Leaf.DNSNames[0] != "relay.example" {
		t.Fatalf("relay certificate = %#v, %v", relayCertificate, err)
	}
}

func TestACMEHTTPClientRestoresOrderLocation(t *testing.T) {
	for _, supplied := range []bool{false, true} {
		t.Run(fmt.Sprintf("server location %v", supplied), func(t *testing.T) {
			var origin string
			server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
				switch request.URL.Path {
				case "/order":
					response.Header().Set("Location", origin+"/order/1")
					response.WriteHeader(http.StatusCreated)
					_, _ = io.WriteString(response, `{"finalize":"`+origin+`/finalize"}`)
				case "/finalize":
					if supplied {
						response.Header().Set("Location", origin+"/order/1")
					}
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
			_, _ = io.Copy(io.Discard, created.Body)
			_ = created.Body.Close()
			finalized, err := client.Post(origin+"/finalize", "application/json", nil)
			if err != nil {
				t.Fatal(err)
			}
			defer finalized.Body.Close()
			if location := finalized.Header.Get("Location"); location != origin+"/order/1" {
				t.Fatalf("finalize Location = %q", location)
			}
		})
	}
}

func TestACMEHTTPClientRejectsOversizedOrder(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.Header().Set("Location", "https://acme.example/order/1")
		response.WriteHeader(http.StatusCreated)
		_, _ = io.WriteString(response, strings.Repeat("x", maximumACMEOrderResponseBytes+1))
	}))
	defer server.Close()
	client := acmeHTTPClient(server.Client())
	response, err := client.Post(server.URL, "application/json", nil)
	if response != nil {
		_ = response.Body.Close()
	}
	if err == nil {
		t.Fatal("oversized ACME order response was accepted")
	}
}

type memoryCache struct {
	mu      sync.Mutex
	entries map[string][]byte
}

func newMemoryCache() *memoryCache { return &memoryCache{entries: make(map[string][]byte)} }

func (c *memoryCache) Get(_ context.Context, key string) ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	data, ok := c.entries[key]
	if !ok {
		return nil, autocert.ErrCacheMiss
	}
	return bytes.Clone(data), nil
}

func (c *memoryCache) Put(_ context.Context, key string, data []byte) error {
	c.mu.Lock()
	c.entries[key] = bytes.Clone(data)
	c.mu.Unlock()
	return nil
}

func (c *memoryCache) Delete(_ context.Context, key string) error {
	c.mu.Lock()
	delete(c.entries, key)
	c.mu.Unlock()
	return nil
}

func testAccountKey(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	data, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func testCertificate(t *testing.T, hostname string) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{}, DNSNames: []string{hostname},
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	certificateDER, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return append(
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificateDER})...,
	)
}

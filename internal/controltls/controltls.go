// Package controltls configures TLS for the control API.
package controltls

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"sync"
	"time"

	"github.com/0xcadams/tnl/internal/naming"
	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
)

type Config struct {
	Hostname     string
	StateDir     string
	DirectoryURL string
	Email        string
	AcceptTerms  bool
	CertFile     string
	KeyFile      string
	HTTPClient   *http.Client
}

// New returns control TLS configured for either a manual keypair or managed ACME.
func New(config Config) (*tls.Config, error) {
	hostname, err := naming.CanonicalizeHostname(config.Hostname)
	if err != nil || hostname != config.Hostname {
		return nil, errors.New("controltls: hostname must be canonical")
	}
	if config.CertFile == "" != (config.KeyFile == "") {
		return nil, errors.New("controltls: certificate and key files must be configured together")
	}
	if config.CertFile != "" {
		certificate, err := tls.LoadX509KeyPair(config.CertFile, config.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("controltls: load certificate: %w", err)
		}
		leaf, err := x509.ParseCertificate(certificate.Certificate[0])
		if err != nil {
			return nil, fmt.Errorf("controltls: parse certificate: %w", err)
		}
		if err := leaf.VerifyHostname(hostname); err != nil {
			return nil, fmt.Errorf("controltls: certificate does not match hostname: %w", err)
		}
		if leaf.NotBefore.After(time.Now().Add(5*time.Minute)) || !leaf.NotAfter.After(time.Now()) {
			return nil, errors.New("controltls: certificate is not currently valid")
		}
		certificate.Leaf = leaf
		return &tls.Config{
			Certificates: []tls.Certificate{certificate},
			MinVersion:   tls.VersionTLS13,
			NextProtos:   []string{"h2", "http/1.1"},
		}, nil
	}
	if config.StateDir == "" || config.DirectoryURL == "" || config.Email == "" {
		return nil, errors.New("controltls: state, ACME directory, and email are required")
	}
	directoryHash := sha256.Sum256([]byte(config.DirectoryURL))
	manager := &autocert.Manager{
		Prompt:     func(string) bool { return config.AcceptTerms },
		Cache:      autocert.DirCache(filepath.Join(config.StateDir, "control-acme", hex.EncodeToString(directoryHash[:]))),
		HostPolicy: autocert.HostWhitelist(hostname),
		Email:      config.Email,
		Client: &acme.Client{
			DirectoryURL: config.DirectoryURL,
			HTTPClient:   acmeHTTPClient(config.HTTPClient),
			UserAgent:    "tnld/1",
		},
	}
	tlsConfig := manager.TLSConfig()
	tlsConfig.MinVersion = tls.VersionTLS13
	return tlsConfig, nil
}

func acmeHTTPClient(client *http.Client) *http.Client {
	if client == nil {
		client = new(http.Client)
	}
	clone := *client
	transport := client.Transport
	if transport == nil {
		transport = http.DefaultTransport
	}
	clone.Transport = &orderLocationTransport{base: transport, orders: make(map[string]string)}
	return &clone
}

// x/crypto/acme expects finalization responses to repeat the order Location,
// although RFC 8555 only requires it when the order is created.
type orderLocationTransport struct {
	base http.RoundTripper

	mu     sync.Mutex
	orders map[string]string
}

func (t *orderLocationTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	response, err := t.base.RoundTrip(request)
	if err != nil {
		return nil, err
	}
	if response.Header.Get("Location") == "" {
		t.mu.Lock()
		location := t.orders[request.URL.String()]
		delete(t.orders, request.URL.String())
		t.mu.Unlock()
		if location != "" {
			response.Header.Set("Location", location)
		}
	}
	if response.StatusCode != http.StatusCreated || response.Header.Get("Location") == "" {
		return response, nil
	}

	body, err := io.ReadAll(response.Body)
	closeErr := response.Body.Close()
	if err != nil || closeErr != nil {
		return nil, errors.Join(err, closeErr)
	}
	response.Body = io.NopCloser(bytes.NewReader(body))
	var order struct {
		Finalize string `json:"finalize"`
	}
	if json.Unmarshal(body, &order) == nil && order.Finalize != "" {
		t.mu.Lock()
		t.orders[order.Finalize] = response.Header.Get("Location")
		t.mu.Unlock()
	}
	return response, nil
}

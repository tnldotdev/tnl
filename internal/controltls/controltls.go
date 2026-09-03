// Package controltls configures TLS for the control API.
package controltls

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"sync"

	"github.com/tnldotdev/tnl/internal/naming"
	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
)

type Config struct {
	Hostname     string
	Cache        autocert.Cache
	DirectoryURL string
	Email        string
	AcceptTerms  bool
	HTTPClient   *http.Client
}

// New returns control TLS configured with managed ACME.
func New(config Config) (*tls.Config, error) {
	hostname, err := naming.CanonicalizeHostname(config.Hostname)
	if err != nil || hostname != config.Hostname {
		return nil, errors.New("controltls: hostname must be canonical")
	}
	if config.Cache == nil || config.DirectoryURL == "" || config.Email == "" {
		return nil, errors.New("controltls: state, ACME directory, and email are required")
	}
	manager := &autocert.Manager{
		Prompt:     func(string) bool { return config.AcceptTerms },
		Cache:      config.Cache,
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
	t.mu.Lock()
	location, finalization := t.orders[request.URL.String()]
	if finalization {
		delete(t.orders, request.URL.String())
	}
	t.mu.Unlock()
	if finalization && response.Header.Get("Location") == "" {
		response.Header.Set("Location", location)
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

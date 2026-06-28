// Package controltls configures automatic public TLS for the control API.
package controltls

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/tnldotdev/tnl/internal/naming"
	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
)

const (
	certificateRefreshInterval    = 5 * time.Minute
	maximumACMEOrderResponseBytes = 1 << 20
)

type Config struct {
	Hostname            string
	AdditionalHostnames []string
	Cache               autocert.Cache
	DirectoryURL        string
	Email               string
	AcceptTerms         bool
	AccountKey          []byte
	HTTPClient          *http.Client
	RunLeader           func(context.Context, func(context.Context) error) error
	Report              func(error)
}

type Source struct {
	hostnames []string
	hostSet   map[string]struct{}
	cache     autocert.Cache
	manager   *autocert.Manager
	runLeader func(context.Context, func(context.Context) error) error
	report    func(error)
	tlsConfig *tls.Config

	mu           sync.RWMutex
	certificates map[string]*tls.Certificate
	refreshAt    map[string]time.Time
}

func New(config Config) (*Source, error) {
	hostnames := append([]string{config.Hostname}, config.AdditionalHostnames...)
	hostSet := make(map[string]struct{}, len(hostnames))
	for _, hostname := range hostnames {
		canonical, err := naming.CanonicalizeHostname(hostname)
		if err != nil || canonical != hostname {
			return nil, errors.New("controltls: hostnames must be canonical")
		}
		if _, exists := hostSet[hostname]; exists {
			return nil, errors.New("controltls: hostnames must be distinct")
		}
		hostSet[hostname] = struct{}{}
	}
	if config.Cache == nil || config.DirectoryURL == "" || config.Email == "" || config.RunLeader == nil {
		return nil, errors.New("controltls: cache, ACME directory, email, and leader coordination are required")
	}
	key, err := accountKey(config.AccountKey)
	if err != nil {
		return nil, err
	}
	manager := &autocert.Manager{
		Prompt:     func(string) bool { return config.AcceptTerms },
		Cache:      config.Cache,
		HostPolicy: autocert.HostWhitelist(hostnames...),
		Email:      config.Email,
		Client: &acme.Client{
			DirectoryURL: config.DirectoryURL,
			HTTPClient:   acmeHTTPClient(config.HTTPClient),
			Key:          key,
			UserAgent:    "tnld/1",
		},
	}
	tlsConfig := manager.TLSConfig()
	source := &Source{
		hostnames: hostnames, hostSet: hostSet, cache: config.Cache, manager: manager,
		runLeader: config.RunLeader, report: config.Report,
		certificates: make(map[string]*tls.Certificate, len(hostnames)), refreshAt: make(map[string]time.Time, len(hostnames)),
	}
	tlsConfig.MinVersion = tls.VersionTLS13
	tlsConfig.GetCertificate = source.GetCertificate
	source.tlsConfig = tlsConfig
	return source, nil
}

func (s *Source) TLSConfig() *tls.Config { return s.tlsConfig.Clone() }

func (s *Source) Ready(now time.Time) bool {
	for _, hostname := range s.hostnames {
		s.mu.RLock()
		certificate := s.certificates[hostname]
		ready := certificate != nil && certificate.Leaf != nil && !now.Before(certificate.Leaf.NotBefore) &&
			certificate.Leaf.NotAfter.After(now)
		s.mu.RUnlock()
		if !ready {
			if _, err := s.loadCertificate(hostname, now); err != nil {
				return false
			}
		}
	}
	return true
}

func (s *Source) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	if hello == nil {
		return nil, errors.New("controltls: unexpected server name")
	}
	hostname, err := naming.CanonicalizeHostname(hello.ServerName)
	if err != nil {
		return nil, errors.New("controltls: unexpected server name")
	}
	if _, ok := s.hostSet[hostname]; !ok {
		return nil, errors.New("controltls: unexpected server name")
	}
	if len(hello.SupportedProtos) == 1 && hello.SupportedProtos[0] == acme.ALPNProto {
		return s.manager.GetCertificate(hello)
	}
	now := time.Now()
	s.mu.RLock()
	certificate, refreshAt := s.certificates[hostname], s.refreshAt[hostname]
	s.mu.RUnlock()
	if certificate != nil && certificate.Leaf != nil && !now.Before(certificate.Leaf.NotBefore) &&
		certificate.Leaf.NotAfter.After(now) && refreshAt.After(now) {
		return certificate, nil
	}
	return s.loadCertificate(hostname, now)
}

func (s *Source) Run(ctx context.Context) error {
	return s.runLeader(ctx, func(ctx context.Context) error {
		for {
			var issuanceErr error
			for _, hostname := range s.hostnames {
				_, err := s.manager.GetCertificate(&tls.ClientHelloInfo{
					ServerName:       hostname,
					SupportedCurves:  []tls.CurveID{tls.CurveP256},
					SignatureSchemes: []tls.SignatureScheme{tls.ECDSAWithP256AndSHA256},
					CipherSuites:     []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
				})
				issuanceErr = errors.Join(issuanceErr, err)
			}
			if issuanceErr == nil {
				<-ctx.Done()
				return nil
			}
			if s.report != nil && ctx.Err() == nil {
				s.report(issuanceErr)
			}
			timer := time.NewTimer(time.Minute)
			select {
			case <-ctx.Done():
				timer.Stop()
				return nil
			case <-timer.C:
			}
		}
	})
}

func (s *Source) loadCertificate(hostname string, now time.Time) (*tls.Certificate, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	data, err := s.cache.Get(ctx, hostname)
	if err != nil {
		return nil, fmt.Errorf("controltls: load certificate: %w", err)
	}
	certificate, err := tls.X509KeyPair(data, data)
	if err != nil || len(certificate.Certificate) == 0 {
		return nil, errors.New("controltls: cached certificate is invalid")
	}
	leaf, err := x509.ParseCertificate(certificate.Certificate[0])
	if err != nil || leaf.VerifyHostname(hostname) != nil || now.Before(leaf.NotBefore) || !now.Before(leaf.NotAfter) {
		return nil, errors.New("controltls: cached certificate is not valid for the requested hostname")
	}
	certificate.Leaf = leaf
	refreshAt := now.Add(certificateRefreshInterval)
	if refreshAt.After(leaf.NotAfter) {
		refreshAt = leaf.NotAfter
	}
	s.mu.Lock()
	s.certificates[hostname] = &certificate
	s.refreshAt[hostname] = refreshAt
	s.mu.Unlock()
	return &certificate, nil
}

func accountKey(data []byte) (*ecdsa.PrivateKey, error) {
	key, err := x509.ParsePKCS8PrivateKey(data)
	if err != nil {
		return nil, errors.New("controltls: ACME account key is invalid")
	}
	privateKey, ok := key.(*ecdsa.PrivateKey)
	if !ok || privateKey.Curve != elliptic.P256() {
		return nil, errors.New("controltls: ACME account key is not ECDSA")
	}
	return privateKey, nil
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

	body, err := io.ReadAll(io.LimitReader(response.Body, maximumACMEOrderResponseBytes+1))
	closeErr := response.Body.Close()
	if err != nil || closeErr != nil {
		return nil, errors.Join(err, closeErr)
	}
	if len(body) > maximumACMEOrderResponseBytes {
		return nil, errors.New("controltls: ACME order response is too large")
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

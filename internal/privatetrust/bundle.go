// package privatetrust captures public CA material for publisher-to-target TLS.
// no publisher private key or database credential is included in a snapshot.
package privatetrust

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/tcptarget"
)

const maxBundleBytes = 1 << 20
const cacheLifetime = 5 * time.Minute

var ErrInvalidBundle = errors.New("private service CA bundle is invalid")
var ErrFetchBundle = errors.New("private service CA bundle could not be fetched over HTTPS")

// SourceError retains a typed cause without exposing local paths, remote URLs,
// or query credentials in messages. errors.Is and errors.As retain the cause.
type SourceError struct{ reason, cause error }

func (e *SourceError) Error() string    { return e.reason.Error() }
func (e *SourceError) Unwrap() []error  { return []error{e.reason, e.cause} }
func (e *SourceError) GoString() string { return e.Error() }

type HTTPStatusError struct{ StatusCode int }

func (e *HTTPStatusError) Error() string {
	return fmt.Sprintf("CA bundle source returned HTTP %d", e.StatusCode)
}

// Snapshot is the public, bounded trust material shared with authorized
// visitors. the digest includes the TLS hostname, so a changed identity also
// changes the service trust configuration. paths and source URLs stay local.
type Snapshot struct {
	Hostname string
	System   bool
	PEM      []byte
	Digest   string
}

// CapturePEM validates publisher-discovered CA-only material through the same
// canonicalization and digest boundary used by project target.tls settings.
func CapturePEM(hostname string, data []byte) (Snapshot, error) {
	if !config.ValidTLSIdentity(hostname) {
		return Snapshot{}, ErrInvalidBundle
	}
	_, canonical, err := decodeBundle(data)
	if err != nil {
		return Snapshot{}, err
	}
	snapshot := Snapshot{Hostname: canonicalHostname(hostname), PEM: canonical}
	snapshot.Digest = snapshot.digest()
	return snapshot, nil
}

type cachedBundle struct {
	data    []byte
	expires time.Time
}

// Cache holds validated HTTPS bundles. an expired entry cannot be used after
// a failed refresh; approval must explicitly publish a newly captured digest.
type Cache struct {
	mu      sync.Mutex
	entries map[string]cachedBundle
	client  *http.Client
	now     func() time.Time
}

func NewCache(client *http.Client) *Cache {
	if client == nil {
		client = http.DefaultClient
	}
	copy := *client
	if transport, ok := copy.Transport.(*http.Transport); ok {
		transport = transport.Clone()
		if transport.TLSClientConfig != nil {
			transport.TLSClientConfig = transport.TLSClientConfig.Clone()
			transport.TLSClientConfig.InsecureSkipVerify = false
		}
		copy.Transport = transport
	} else if copy.Transport == nil {
		copy.Transport = http.DefaultTransport.(*http.Transport).Clone()
	}
	copy.Timeout = 10 * time.Second
	copy.CheckRedirect = func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }
	return &Cache{client: &copy, entries: make(map[string]cachedBundle), now: time.Now}
}

// Capture resolves a service's configured trust once. an omitted TLS block is
// handled by the caller as opaque pass-through, never as a snapshot.
func (c *Cache) Capture(ctx context.Context, root, target string, setting config.TrustSource) (Snapshot, error) {
	if err := ctx.Err(); err != nil {
		return Snapshot{}, err
	}
	if c == nil || c.client == nil || setting.CA == "" {
		return Snapshot{}, ErrInvalidBundle
	}
	if err := config.ValidateTrustSource(setting); err != nil {
		return Snapshot{}, &SourceError{reason: ErrInvalidBundle, cause: err}
	}
	host, err := tcptarget.Host(target)
	if err != nil {
		return Snapshot{}, fmt.Errorf("private service TLS target: %w", err)
	}
	if setting.Hostname != nil {
		host = *setting.Hostname
	}
	if !config.ValidTLSIdentity(host) {
		return Snapshot{}, ErrInvalidBundle
	}
	host = canonicalHostname(host)
	snapshot := Snapshot{Hostname: host, System: setting.CA == "system"}
	if !snapshot.System {
		var data []byte
		if strings.HasPrefix(setting.CA, "https://") {
			data, err = c.fetch(ctx, setting.CA)
		} else {
			data, err = readProjectBundle(root, setting.CA)
		}
		if err != nil {
			var source *SourceError
			if errors.As(err, &source) {
				return Snapshot{}, err
			}
			return Snapshot{}, &SourceError{reason: ErrInvalidBundle, cause: err}
		}
		_, canonical, err := decodeBundle(data)
		if err != nil {
			return Snapshot{}, err
		}
		snapshot.PEM = canonical
	}
	snapshot.Digest = snapshot.digest()
	return snapshot, nil
}

func (s Snapshot) digest() string {
	mode := "pem"
	if s.System {
		mode = "system"
	}
	digest := sha256.New()
	_, _ = digest.Write([]byte(s.Hostname + "\x00" + mode + "\x00"))
	_, _ = digest.Write(s.PEM)
	return hex.EncodeToString(digest.Sum(nil))
}

func readProjectBundle(root, name string) ([]byte, error) {
	if config.ValidateTrustSource(config.TrustSource{CA: name}) != nil || name == "system" || strings.Contains(name, "://") {
		return nil, ErrInvalidBundle
	}
	project, err := os.OpenRoot(root)
	if err != nil {
		return nil, err
	}
	defer project.Close()
	info, err := project.Stat(name)
	if err != nil || !info.Mode().IsRegular() || info.Size() > maxBundleBytes {
		return nil, ErrInvalidBundle
	}
	opened, err := openProjectFile(project, name)
	if err != nil {
		return nil, err
	}
	defer opened.Close()
	info, err = opened.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > maxBundleBytes {
		return nil, ErrInvalidBundle
	}
	return readBounded(opened)
}

func (c *Cache) fetch(ctx context.Context, location string) ([]byte, error) {
	if !strings.HasPrefix(location, "https://") {
		return nil, ErrInvalidBundle
	}
	if err := config.ValidateTrustSource(config.TrustSource{CA: location}); err != nil {
		return nil, &SourceError{reason: ErrInvalidBundle, cause: err}
	}
	c.mu.Lock()
	if entry, ok := c.entries[location]; ok && c.now().Before(entry.expires) {
		data := append([]byte(nil), entry.data...)
		c.mu.Unlock()
		return data, nil
	}
	c.mu.Unlock()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, location, nil)
	if err != nil {
		return nil, &SourceError{reason: ErrInvalidBundle, cause: err}
	}
	response, err := c.client.Do(request)
	if err != nil {
		return nil, &SourceError{reason: ErrFetchBundle, cause: err}
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, &SourceError{reason: ErrFetchBundle, cause: &HTTPStatusError{StatusCode: response.StatusCode}}
	}
	data, err := readBounded(response.Body)
	if err != nil {
		return nil, &SourceError{reason: ErrFetchBundle, cause: err}
	}
	if _, err := parseBundle(data); err != nil {
		return nil, err
	}
	c.mu.Lock()
	if len(c.entries) >= 128 {
		clear(c.entries)
	}
	c.entries[location] = cachedBundle{data: append([]byte(nil), data...), expires: c.now().Add(cacheLifetime)}
	c.mu.Unlock()
	return data, nil
}

func readBounded(reader io.Reader) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(reader, maxBundleBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) == 0 || len(data) > maxBundleBytes {
		return nil, ErrInvalidBundle
	}
	return data, nil
}

func parseBundle(data []byte) (*x509.CertPool, error) {
	pool, _, err := decodeBundle(data)
	return pool, err
}

func decodeBundle(data []byte) (*x509.CertPool, []byte, error) {
	if len(data) == 0 || len(data) > maxBundleBytes {
		return nil, nil, ErrInvalidBundle
	}
	pool := x509.NewCertPool()
	certificates := []*x509.Certificate{}
	count := 0
	data = bytes.TrimSpace(data)
	for len(data) > 0 {
		// pem.Decode otherwise skips arbitrary garbage before a valid block.
		const begin = "-----BEGIN CERTIFICATE-----"
		const end = "-----END CERTIFICATE-----"
		boundary := bytes.Index(data, []byte(end))
		if !bytes.HasPrefix(data, []byte(begin)) || boundary < 0 {
			return nil, nil, ErrInvalidBundle
		}
		boundary += len(end)
		if bytes.Count(data[:boundary], []byte("-----BEGIN ")) != 1 {
			return nil, nil, ErrInvalidBundle
		}
		block, extra := pem.Decode(data[:boundary])
		if block == nil || len(bytes.TrimSpace(extra)) != 0 || block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			return nil, nil, ErrInvalidBundle
		}
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, nil, &SourceError{reason: ErrInvalidBundle, cause: err}
		}
		if !certificate.BasicConstraintsValid || !certificate.IsCA || certificate.KeyUsage != 0 && certificate.KeyUsage&x509.KeyUsageCertSign == 0 {
			return nil, nil, ErrInvalidBundle
		}
		pool.AddCert(certificate)
		certificates = append(certificates, certificate)
		count++
		if count > 32 {
			return nil, nil, ErrInvalidBundle
		}
		data = bytes.TrimSpace(data[boundary:])
	}
	if count == 0 {
		return nil, nil, ErrInvalidBundle
	}
	// normalize encoding, order, and duplicate CAs before approval. equivalent
	// source formatting does not create a new trust digest or revision.
	slices.SortFunc(certificates, func(a, b *x509.Certificate) int { return bytes.Compare(a.Raw, b.Raw) })
	var canonical []byte
	for index, certificate := range certificates {
		if index != 0 && bytes.Equal(certificate.Raw, certificates[index-1].Raw) {
			continue
		}
		canonical = append(canonical, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Raw})...)
	}
	if len(canonical) > maxBundleBytes {
		return nil, nil, ErrInvalidBundle
	}
	return pool, canonical, nil
}

func canonicalHostname(host string) string {
	if address, err := netip.ParseAddr(host); err == nil {
		return address.String()
	}
	return strings.ToLower(host)
}

// Verifier builds publisher-to-target trust. custom CA-only bundles add to
// system roots; neither selection permits plaintext or unverified fallback.
func (s Snapshot) Verifier() (*tls.Config, error) {
	if !s.valid() {
		return nil, ErrInvalidBundle
	}
	roots, err := x509.SystemCertPool()
	if err != nil {
		return nil, &SourceError{reason: ErrInvalidBundle, cause: err}
	}
	if roots == nil {
		return nil, ErrInvalidBundle
	}
	if !s.System {
		if _, err := parseBundle(s.PEM); err != nil {
			return nil, err
		}
		if !roots.AppendCertsFromPEM(s.PEM) {
			return nil, ErrInvalidBundle
		}
	}
	return &tls.Config{MinVersion: tls.VersionTLS12, ServerName: s.Hostname, RootCAs: roots}, nil
}

// CAVerifier restricts an explicit CA snapshot to its cluster roots. a system
// selection still uses WebPKI; a custom cluster CA cannot fall back to WebPKI.
func (s Snapshot) CAVerifier() (*tls.Config, error) {
	if s.System {
		return s.Verifier()
	}
	if !s.valid() {
		return nil, ErrInvalidBundle
	}
	roots, err := parseBundle(s.PEM)
	if err != nil {
		return nil, err
	}
	return &tls.Config{MinVersion: tls.VersionTLS12, ServerName: s.Hostname, RootCAs: roots}, nil
}

func (s Snapshot) valid() bool {
	return config.ValidTLSIdentity(s.Hostname) && s.Hostname == canonicalHostname(s.Hostname) && s.Digest == s.digest() && s.System != (len(s.PEM) != 0)
}

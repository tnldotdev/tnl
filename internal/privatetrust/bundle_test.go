package privatetrust

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/config"
)

func testCA(t *testing.T) ([]byte, tls.Certificate) {
	t.Helper()
	now := time.Now()
	rootPublic, rootKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	root := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test root"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign}
	rootDER, err := x509.CreateCertificate(rand.Reader, root, root, rootPublic, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	root, err = x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatal(err)
	}
	leafPublic, leafKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		DNSNames: []string{"db.example"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	leafDER, err := x509.CreateCertificate(rand.Reader, leaf, root, leafPublic, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER}), tls.Certificate{Certificate: [][]byte{leafDER, rootDER}, PrivateKey: leafKey}
}

func testTLS(t *testing.T, cert tls.Certificate) *httptest.Server {
	t.Helper()
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{cert}}
	server.StartTLS()
	t.Cleanup(server.Close)
	return server
}

func verify(t *testing.T, address string, snapshot Snapshot) error {
	t.Helper()
	config, err := snapshot.Verifier()
	if err != nil {
		return err
	}
	connection, err := tls.DialWithDialer(&net.Dialer{Timeout: time.Second}, "tcp", address, config)
	if err == nil {
		_ = connection.Close()
	}
	return err
}

func TestCaptureFileVerifiesDatabaseIdentityAndRejectsEscape(t *testing.T) {
	root, cert := testCA(t)
	server := testTLS(t, cert)
	directory := t.TempDir()
	file := filepath.Join(directory, "provider.pem")
	if err := os.WriteFile(file, root, 0600); err != nil {
		t.Fatal(err)
	}
	host := "db.example"
	cache := NewCache(nil)
	snapshot, err := cache.Capture(t.Context(), directory, server.Listener.Addr().String(), config.TrustSource{CA: "provider.pem", Hostname: &host})
	if err != nil || snapshot.System || len(snapshot.PEM) == 0 || snapshot.Digest == "" {
		t.Fatalf("captured provider root: %#v, %v", snapshot, err)
	}
	if err := verify(t, server.Listener.Addr().String(), snapshot); err != nil {
		t.Fatalf("correct provider certificate rejected: %v", err)
	}
	wrongName := snapshot
	wrongName.Hostname = "other.example"
	wrongName.Digest = wrongName.digest()
	if err := verify(t, server.Listener.Addr().String(), wrongName); err == nil {
		t.Fatal("wrong database hostname was accepted")
	}
	otherRoot, _ := testCA(t)
	wrongCA := snapshot
	wrongCA.PEM = otherRoot
	wrongCA.Digest = wrongCA.digest()
	if err := verify(t, server.Listener.Addr().String(), wrongCA); err == nil {
		t.Fatal("wrong provider CA was accepted")
	}
	outside := filepath.Join(t.TempDir(), "external.pem")
	if err := os.WriteFile(outside, root, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(directory, "escape.pem")); err != nil {
		t.Fatal(err)
	}
	if _, err := cache.Capture(t.Context(), directory, server.Listener.Addr().String(), config.TrustSource{CA: "escape.pem"}); err == nil {
		t.Fatal("CA symlink escaped the project")
	}
}

func TestHTTPSBundleRefreshNeverFallsBackToStaleOrPlaintext(t *testing.T) {
	first, providerCertificate := testCA(t)
	provider := testTLS(t, providerCertificate)
	second, _ := testCA(t)
	var mu sync.Mutex
	current, status := first, http.StatusOK
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		w.WriteHeader(status)
		_, _ = w.Write(current)
	}))
	defer server.Close()
	cache := NewCache(server.Client())
	clock := time.Now()
	cache.now = func() time.Time { return clock }
	setting := config.TrustSource{CA: server.URL}
	firstSnapshot, err := cache.Capture(context.Background(), t.TempDir(), "127.0.0.1:5432", setting)
	if err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	current = second
	mu.Unlock()
	cached, err := cache.Capture(context.Background(), t.TempDir(), "127.0.0.1:5432", setting)
	if err != nil || cached.Digest != firstSnapshot.Digest {
		t.Fatalf("bundle changed before refresh: %v", err)
	}
	clock = clock.Add(cacheLifetime + time.Second)
	updated, err := cache.Capture(context.Background(), t.TempDir(), "127.0.0.1:5432", setting)
	if err != nil || updated.Digest == firstSnapshot.Digest {
		t.Fatalf("rotated CA did not advance trust digest: %v", err)
	}
	if err := verify(t, provider.Listener.Addr().String(), firstSnapshot); err != nil {
		t.Fatalf("URL refresh mutated an earlier approved snapshot: %v", err)
	}
	if err := verify(t, provider.Listener.Addr().String(), updated); err == nil {
		t.Fatal("new CA snapshot unexpectedly reused the earlier trust")
	}
	mu.Lock()
	status = http.StatusServiceUnavailable
	mu.Unlock()
	clock = clock.Add(cacheLifetime + time.Second)
	if _, err := cache.Capture(context.Background(), t.TempDir(), "127.0.0.1:5432", setting); err == nil {
		t.Fatal("failed CA URL refresh reused expired trust")
	}
}

func TestCaptureRejectsNonCAAndOversizedBundles(t *testing.T) {
	ca, leaf := testCA(t)
	directory := t.TempDir()
	file := filepath.Join(directory, "invalid.pem")
	for _, data := range [][]byte{
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Certificate[0]}),
		make([]byte, maxBundleBytes+1),
		append([]byte("garbage\n"), ca...),
		append(bytes.Clone(ca), []byte("garbage\n")...),
		append(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("secret")}), ca...),
		append(bytes.Clone(ca), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("secret")})...),
		append([]byte("-----BEGIN CERTIFICATE-----\ninvalid\n-----END CERTIFICATE-----\n"), ca...),
		append([]byte("-----BEGIN CERTIFICATE-----\ninvalid prefix\n"), ca...),
		bytes.Repeat(ca, 33),
	} {
		if err := os.WriteFile(file, data, 0600); err != nil {
			t.Fatal(err)
		}
		_, err := NewCache(nil).Capture(t.Context(), directory, "127.0.0.1:5432", config.TrustSource{CA: "invalid.pem"})
		if !errors.Is(err, ErrInvalidBundle) {
			t.Fatalf("invalid bundle accepted: %v", err)
		}
	}
}

func TestSnapshotCanonicalizationKeepsEquivalentMetadataDigest(t *testing.T) {
	first, _ := testCA(t)
	second, _ := testCA(t)
	directory := t.TempDir()
	file := filepath.Join(directory, "ca.pem")
	name := "DB.Example"
	setting := config.TrustSource{CA: "ca.pem", Hostname: &name}
	cache := NewCache(nil)
	var baseline Snapshot
	for index, data := range [][]byte{
		append(bytes.Clone(first), second...),
		append(append(bytes.Clone(second), first...), first...),
		bytes.ReplaceAll(append(append([]byte("\n\t"), first...), second...), []byte("\n"), []byte("\r\n")),
	} {
		if err := os.WriteFile(file, data, 0600); err != nil {
			t.Fatal(err)
		}
		snapshot, err := cache.Capture(t.Context(), directory, "127.0.0.1:5432", setting)
		if err != nil {
			t.Fatal(err)
		}
		if index == 0 {
			baseline = snapshot
		}
		if snapshot.Hostname != "db.example" || snapshot.Digest != baseline.Digest || !bytes.Equal(snapshot.PEM, baseline.PEM) {
			t.Fatal("equivalent CA material created a different approval digest")
		}
		digest := sha256.Sum256([]byte(snapshot.Hostname + "\x00pem\x00" + string(snapshot.PEM)))
		if snapshot.Digest != hex.EncodeToString(digest[:]) {
			t.Fatal("snapshot digest does not match the public metadata encoding")
		}
		if _, err := snapshot.Verifier(); err != nil {
			t.Fatal(err)
		}
	}
}

type failingSourceTransport struct{ err error }

func (transport failingSourceTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, transport.err
}

func TestCASourceErrorsKeepTypedCausesAndHideSourceCredentials(t *testing.T) {
	const secret = "private-source-token"
	location := "https://example.com/%invalid?token=" + secret
	_, err := NewCache(nil).Capture(t.Context(), t.TempDir(), "db.example:5432", config.TrustSource{CA: location})
	var source *SourceError
	var setting *config.CAURLError
	var parsed *url.Error
	if !errors.Is(err, ErrInvalidBundle) || !errors.As(err, &source) || !errors.As(err, &setting) || !errors.As(err, &parsed) {
		t.Fatalf("lost typed malformed-URL cause: %v", err)
	}
	if strings.Contains(err.Error(), secret) || strings.Contains(err.Error(), location) {
		t.Fatal("source URL leaked into the error message")
	}
	broken := errors.New("provider failed at ?token=" + secret)
	cache := NewCache(&http.Client{Transport: failingSourceTransport{err: broken}})
	_, err = cache.Capture(t.Context(), t.TempDir(), "db.example:5432", config.TrustSource{CA: "https://example.com/ca.pem?token=" + secret})
	if !errors.Is(err, ErrFetchBundle) || !errors.Is(err, broken) || !errors.As(err, &source) || !errors.As(err, &parsed) {
		t.Fatalf("lost typed fetch cause: %v", err)
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatal("fetch source credential leaked into the error message")
	}
}

func TestSystemSnapshotUsesVisitorMachineRootsWithoutPublisherBundle(t *testing.T) {
	_, cert := testCA(t)
	server := testTLS(t, cert)
	cache := NewCache(nil)
	snapshot, err := cache.Capture(t.Context(), t.TempDir(), server.Listener.Addr().String(), config.TrustSource{CA: "system"})
	if err != nil || !snapshot.System || len(snapshot.PEM) != 0 {
		t.Fatalf("system snapshot: %v", err)
	}
	verifier, err := snapshot.Verifier()
	if err != nil || verifier.InsecureSkipVerify || verifier.ServerName != "127.0.0.1" {
		t.Fatalf("system verifier: %v", err)
	}
	roots, err := x509.SystemCertPool()
	if err != nil || !verifier.RootCAs.Equal(roots) {
		t.Fatalf("visitor machine roots not selected: %v", err)
	}
	if err := verify(t, server.Listener.Addr().String(), snapshot); err == nil {
		t.Fatal("system selection trusted an uninstalled publisher root")
	}
	for _, host := range []string{"", "db/path", "*.example", "bad..example", "[::1]", "fe80::1%lo0", "xn--a.example"} {
		if _, err := cache.Capture(t.Context(), t.TempDir(), "127.0.0.1:5432", config.TrustSource{CA: "system", Hostname: &host}); err == nil {
			t.Fatalf("invalid certificate hostname accepted: %q", host)
		}
	}
}

func TestHTTPSBundleRejectsUnverifiedTransportRedirectsAndInvalidBodies(t *testing.T) {
	root, _ := testCA(t)
	var body = root
	var redirect bool
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if redirect {
			http.Redirect(w, r, "/root.pem", http.StatusFound)
			return
		}
		_, _ = w.Write(body)
	}))
	defer server.Close()
	setting := config.TrustSource{CA: server.URL}
	if _, err := NewCache(nil).Capture(t.Context(), t.TempDir(), "db.example:5432", setting); err == nil {
		t.Fatal("untrusted HTTPS CA source accepted")
	}
	redirect = true
	if _, err := NewCache(server.Client()).Capture(t.Context(), t.TempDir(), "db.example:5432", setting); err == nil {
		t.Fatal("CA URL redirect accepted")
	}
	redirect = false
	body = bytes.Repeat([]byte("x"), maxBundleBytes+1)
	if _, err := NewCache(server.Client()).Capture(t.Context(), t.TempDir(), "db.example:5432", setting); err == nil {
		t.Fatal("oversized HTTPS bundle accepted")
	}
	body = []byte("not a CA bundle")
	if _, err := NewCache(server.Client()).Capture(t.Context(), t.TempDir(), "db.example:5432", setting); err == nil {
		t.Fatal("invalid HTTPS bundle accepted")
	}
	for _, ca := range []string{"https://user:secret@example.com/ca", "https://example.com:0/ca", "https://example.com:65536/ca", "https://example.com:/ca", "https://bad..example/ca", "https://example.com/#fragment", "http://example.com/ca", "../ca.pem"} {
		if _, err := NewCache(nil).Capture(t.Context(), t.TempDir(), "db.example:5432", config.TrustSource{CA: ca}); err == nil {
			t.Fatalf("invalid CA source accepted: %q", ca)
		}
	}
}

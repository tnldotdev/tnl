package integrationtest

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/letsencrypt/challtestsrv"
	"golang.org/x/crypto/acme"
)

const IntegrationEnv = "TNL_TEST_INTEGRATION"

type Pebble struct {
	directoryURL  string
	managementURL string
	httpClient    *http.Client
	logs          *lockedBuffer
}

func RequirePebble(t testing.TB) string {
	t.Helper()
	if os.Getenv(IntegrationEnv) != "1" {
		t.Skipf("set %s=1 to run integration tests", IntegrationEnv)
	}
	path, err := exec.LookPath("pebble")
	if err != nil {
		t.Fatal("pebble is not installed; run mise install")
	}
	return path
}

func StartChallengeDNS(t testing.TB) string {
	t.Helper()
	address := unusedLocalAddress(t)
	server, err := challtestsrv.New(challtestsrv.Config{
		DNSAddrs: []string{address}, Log: log.New(io.Discard, "", 0),
	})
	if err != nil {
		t.Fatal(err)
	}
	server.SetDefaultDNSIPv4("127.0.0.1")
	server.SetDefaultDNSIPv6("")
	server.Run()
	t.Cleanup(server.Shutdown)
	waitForTCP(t, address, nil)
	return address
}

func StartPebble(t testing.TB, executable string, validationPort int, dnsAddress string) *Pebble {
	t.Helper()
	directoryListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	managementListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		directoryListener.Close()
		t.Fatal(err)
	}
	directoryAddress := directoryListener.Addr().String()
	managementAddress := managementListener.Addr().String()

	directory := t.TempDir()
	certificatePath, keyPath, roots := writeTLSCredentials(t, directory)
	profile := map[string]any{"description": "tnl integration test", "validityPeriod": 3600}
	config := map[string]any{"pebble": map[string]any{
		"listenAddress": directoryAddress, "managementListenAddress": managementAddress,
		"certificate": certificatePath, "privateKey": keyPath, "httpPort": 5002,
		"tlsPort": validationPort, "keyAlgorithm": "ecdsa",
		"retryAfter": map[string]int{"authz": 0, "order": 0},
		"profiles":   map[string]any{"default": profile, "tlsserver": profile},
	}}
	encodedConfig, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(directory, "pebble.json")
	if err := os.WriteFile(configPath, encodedConfig, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := directoryListener.Close(); err != nil {
		t.Fatal(err)
	}
	if err := managementListener.Close(); err != nil {
		t.Fatal(err)
	}

	processContext, cancel := context.WithCancel(context.Background())
	logs := new(lockedBuffer)
	command := exec.CommandContext(processContext, executable, "-config", configPath, "-dnsserver", dnsAddress)
	command.Env = append(os.Environ(),
		"PEBBLE_VA_ALWAYS_VALID=0", "PEBBLE_VA_NOSLEEP=1", "PEBBLE_WFE_NONCEREJECT=0", "PEBBLE_AUTHZREUSE=0",
	)
	command.Stdout, command.Stderr = logs, logs
	if err := command.Start(); err != nil {
		cancel()
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- command.Wait() }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			_ = command.Process.Kill()
			<-done
		}
	})

	transport := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots}}
	t.Cleanup(transport.CloseIdleConnections)
	pebble := &Pebble{
		directoryURL: "https://" + directoryAddress + "/dir", managementURL: "https://" + managementAddress,
		httpClient: &http.Client{Transport: transport, Timeout: 10 * time.Second}, logs: logs,
	}
	waitForTCP(t, directoryAddress, pebble.Logs)
	return pebble
}

func (p *Pebble) DirectoryURL() string     { return p.directoryURL }
func (p *Pebble) HTTPClient() *http.Client { return p.httpClient }
func (p *Pebble) Logs() string             { return p.logs.String() }

func (p *Pebble) ACMEClient(accountKey *ecdsa.PrivateKey, kid acme.KeyID) *acme.Client {
	return &acme.Client{
		Key: accountKey, KID: kid, DirectoryURL: p.directoryURL, HTTPClient: p.httpClient,
		UserAgent: "tnl-pebble-integration",
	}
}

func (p *Pebble) IssuerRoots(t testing.TB) *x509.CertPool {
	t.Helper()
	response, err := p.httpClient.Get(p.managementURL + "/roots/0")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("Pebble root response = %s; logs:\n%s", response.Status, p.Logs())
	}
	rootPEM, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(rootPEM) {
		t.Fatal("Pebble root response contained no certificate")
	}
	return roots
}

func writeTLSCredentials(t testing.TB, directory string) (string, string, *x509.CertPool) {
	t.Helper()
	now := time.Now()
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rootTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "tnl Pebble test root"},
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour),
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature, BasicConstraintsValid: true, IsCA: true,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, rootKey.Public(), rootKey)
	if err != nil {
		t.Fatal(err)
	}
	root, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatal(err)
	}
	serverKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serverTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "localhost"},
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true, DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
	}
	serverDER, err := x509.CreateCertificate(rand.Reader, serverTemplate, root, serverKey.Public(), rootKey)
	if err != nil {
		t.Fatal(err)
	}
	privateKey, err := x509.MarshalPKCS8PrivateKey(serverKey)
	if err != nil {
		t.Fatal(err)
	}
	certificatePath := filepath.Join(directory, "pebble-cert.pem")
	keyPath := filepath.Join(directory, "pebble-key.pem")
	if err := os.WriteFile(certificatePath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: serverDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateKey}), 0o600); err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(root)
	return certificatePath, keyPath, roots
}

func unusedLocalAddress(t testing.TB) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	packet, err := net.ListenPacket("udp", address)
	if err != nil {
		listener.Close()
		t.Fatal(err)
	}
	packet.Close()
	listener.Close()
	return address
}

func waitForTCP(t testing.TB, address string, diagnostics func() string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		connection, err := net.DialTimeout("tcp", address, 100*time.Millisecond)
		if err == nil {
			connection.Close()
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	if diagnostics == nil {
		t.Fatalf("timed out waiting for %s", address)
	}
	t.Fatalf("timed out waiting for %s; logs:\n%s", address, diagnostics())
}

type lockedBuffer struct {
	mu sync.Mutex
	bytes.Buffer
}

func (b *lockedBuffer) Write(contents []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.Buffer.Write(contents)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.Buffer.String()
}

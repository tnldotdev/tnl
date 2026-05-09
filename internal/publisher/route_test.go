package publisher

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/proxyproto"
	"github.com/tnldotdev/tnl/internal/tlschallenge"
	"golang.org/x/crypto/acme"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

func TestRouteTerminatesTLSAndProxiesLoopbackHTTP(t *testing.T) {
	forwarded := make(chan string, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		forwarded <- request.Header.Get("X-Forwarded-For")
		_, _ = response.Write([]byte("local response"))
	}))
	defer upstream.Close()
	route, err := NewRoute(RouteConfig{
		Hostname:      "route.example",
		Target:        upstream.URL,
		Certificate:   routeTestCertificate(t, "route.example"),
		AllowedClient: key.NewNode().Public(),
		RelayRegion:   "test",
		Regions: map[string]*tailcfg.DERPRegion{"test": {
			RegionID: 1, Nodes: []*tailcfg.DERPNode{{RegionID: 1, HostName: "derp.example"}},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	route.mu.Lock()
	route.started = true
	route.mu.Unlock()
	route.startHTTP()
	t.Cleanup(func() { _ = route.Close() })

	ingress, agentConnection := net.Pipe()
	handled := make(chan struct{})
	go func() {
		route.handle(agentConnection)
		close(handled)
	}()
	header, err := proxyproto.Encode(proxyproto.Header{
		Source:      netip.MustParseAddrPort("192.0.2.10:1234"),
		Destination: netip.MustParseAddrPort("127.0.0.1:443"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ingress.Write(header); err != nil {
		t.Fatal(err)
	}
	client := tls.Client(ingress, &tls.Config{
		ServerName: "route.example", MinVersion: tls.VersionTLS12,
		InsecureSkipVerify: true, // The test route certificate is self-signed.
	})
	if err := client.HandshakeContext(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := fmt.Fprint(client, "GET / HTTP/1.1\r\nHost: route.example\r\nConnection: close\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	response, err := http.ReadResponse(bufio.NewReader(client), nil)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK || string(body) != "local response" {
		t.Fatalf("response = %d %q", response.StatusCode, body)
	}
	if got := <-forwarded; got != "192.0.2.10" {
		t.Fatalf("X-Forwarded-For = %q", got)
	}
	_ = client.Close()
	select {
	case <-handled:
	case <-time.After(time.Second):
		t.Fatal("route handler did not close")
	}
}

func TestRouteSelectsChallengeAndInstalledCertificate(t *testing.T) {
	route, err := NewRoute(RouteConfig{
		Hostname: "route.example", Target: "http://127.0.0.1:3000", AllowedClient: key.NewNode().Public(),
		RelayRegion: "test", Regions: map[string]*tailcfg.DERPRegion{"test": {
			RegionID: 1, Nodes: []*tailcfg.DERPNode{{RegionID: 1, HostName: "derp.example"}},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = route.Close() })
	if _, err := route.getCertificate(&tls.ClientHelloInfo{
		ServerName: "route.example", SupportedProtos: []string{"http/1.1"},
	}); err == nil {
		t.Fatal("ordinary certificate was available before installation")
	}
	digest := sha256.Sum256([]byte("key authorization"))
	challenge := tlschallenge.TLSALPNChallenge{
		ID: "challenge", Hostname: "route.example", Digest: digest, ExpiresAt: time.Now().Add(time.Hour),
	}
	if err := route.InstallChallenge(challenge); err != nil {
		t.Fatal(err)
	}
	selected, err := route.getCertificate(&tls.ClientHelloInfo{
		ServerName: "route.example", SupportedProtos: []string{acme.ALPNProto},
	})
	if err != nil || selected.Leaf == nil || selected.Leaf.DNSNames[0] != "route.example" {
		t.Fatalf("challenge certificate = %#v, %v", selected, err)
	}
	if !route.RemoveChallenge(challenge.ID) {
		t.Fatal("challenge was not removed")
	}
	application := routeTestCertificate(t, "route.example")
	if err := route.InstallCertificate(application); err != nil {
		t.Fatal(err)
	}
	selected, err = route.getCertificate(&tls.ClientHelloInfo{
		ServerName: "route.example", SupportedProtos: []string{"http/1.1"},
	})
	if err != nil || selected.Leaf == nil || selected.Leaf.SerialNumber.Cmp(application.Leaf.SerialNumber) != 0 {
		t.Fatalf("application certificate = %#v, %v", selected, err)
	}
}

func TestManualCertificateRetainsStandardTLSCompatibility(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), DNSNames: []string{"*.example", "other.invalid"},
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, privateKey.Public(), privateKey)
	if err != nil {
		t.Fatal(err)
	}
	certificate := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: privateKey}
	if err := validateCertificate(certificate, "route.example", false); err != nil {
		t.Fatalf("manual certificate rejected: %v", err)
	}
	if err := validateCertificate(certificate, "route.example", true); err == nil {
		t.Fatal("automatic certificate policy accepted a wildcard RSA certificate")
	}
}

func routeTestCertificate(t *testing.T, hostname string) tls.Certificate {
	t.Helper()
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: hostname}, DNSNames: []string{hostname},
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, privateKey.Public(), privateKey)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: privateKey, Leaf: leaf}
}

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
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"testing/synctest"
	"time"

	"github.com/tnldotdev/tnl/internal/certificateidentity"
	"github.com/tnldotdev/tnl/internal/muxsession"
	"github.com/tnldotdev/tnl/internal/proxyproto"
	"github.com/tnldotdev/tnl/internal/tlschallenge"
	"github.com/tnldotdev/tnl/internal/tunnel"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
	"golang.org/x/crypto/acme"
)

func TestRouteServerTerminatesTLSAndProxiesLocalHTTP(t *testing.T) {
	forwarded := make(chan string, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		forwarded <- request.Header.Get("X-Forwarded-For")
		_, _ = response.Write([]byte("local response"))
	}))
	defer upstream.Close()
	route := startHTTPTestRouteServer(t, upstream.URL)
	handled := make(chan struct{})
	ingress, err := openHTTPTestRouteServer(route, handled)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ingress.Close(); awaitPublisherTest(t, handled) })
	client := tls.Client(ingress, &tls.Config{
		ServerName: "ROUTE.EXAMPLE", MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS12,
		InsecureSkipVerify: true, // The test public URL certificate is self-signed.
	})
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	if err := client.HandshakeContext(ctx); err != nil {
		t.Fatal(err)
	}
	if client.ConnectionState().Version != tls.VersionTLS12 {
		t.Fatalf("TLS version = %x, want TLS 1.2", client.ConnectionState().Version)
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
	if got := awaitPublisherTest(t, forwarded); got != "192.0.2.10" {
		t.Fatalf("X-Forwarded-For = %q", got)
	}
	_ = client.Close()
	select {
	case <-handled:
	case <-time.After(time.Second):
		t.Fatal("route handler did not close")
	}
}

func TestRouteServerClosesStreamAfterMalformedProxyHeader(t *testing.T) {
	publisher, relay := net.Pipe()
	_ = relay.SetDeadline(time.Now().Add(5 * time.Second))
	handled := make(chan struct{})
	go func() {
		new(PublicURLServer).handle(publisher)
		close(handled)
	}()
	t.Cleanup(func() { _ = relay.Close(); _ = publisher.Close(); awaitPublisherTest(t, handled) })
	if _, err := relay.Write([]byte("not-a-proxy-head")); err != nil {
		t.Fatal(err)
	}
	select {
	case <-handled:
	case <-time.After(time.Second):
		t.Fatal("route did not reject malformed PROXY metadata")
	}
	if err := relay.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		return
	}
	var buffer [1]byte
	if _, err := relay.Read(buffer[:]); err == nil {
		t.Fatal("malformed visitor stream remained open")
	} else if networkError, ok := err.(net.Error); ok && networkError.Timeout() {
		t.Fatal("malformed visitor stream was not closed")
	}
}

func TestRouteServerServesTransportNeutralPublisherConnection(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	forwarded := make(chan string, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		forwarded <- request.Header.Get("X-Forwarded-For")
		_, _ = response.Write([]byte("local response"))
	}))
	defer upstream.Close()

	publicURLCertificate := publicURLTestCertificate(t, "route.example")
	route, err := NewPublicURLServer(PublicURLServerConfig{
		Hostname: "route.example", Target: upstream.URL, Certificate: publicURLCertificate,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := route.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = route.Close() })

	transportCertificate := publicURLTestCertificate(t, "relay.example")
	roots := x509.NewCertPool()
	roots.AddCert(transportCertificate.Leaf)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	type accepted struct {
		session *tunnel.Session
		err     error
	}
	relayResult := make(chan accepted, 1)
	relayDone := make(chan struct{})
	go func() {
		defer close(relayDone)
		connection, err := listener.Accept()
		if err != nil {
			relayResult <- accepted{err: err}
			return
		}
		defer connection.Close()
		stop := context.AfterFunc(ctx, func() { _ = connection.Close() })
		defer stop()
		transport, err := muxsession.AcceptTLSYamux(ctx, connection, &tls.Config{
			Certificates: []tls.Certificate{transportCertificate},
		}, muxsession.TLSYamuxConfig{})
		if err != nil {
			relayResult <- accepted{err: err}
			return
		}
		defer transport.Close()
		session, _, err := tunnel.Accept(ctx, transport, func(context.Context, tunnelv1.Message) error {
			return nil
		})
		relayResult <- accepted{session: session, err: err}
		if err == nil {
			defer session.Close()
			select {
			case <-ctx.Done():
			case <-session.Done():
			}
		}
	}()
	t.Cleanup(func() {
		cancel()
		_ = listener.Close()
		awaitPublisherTest(t, relayDone)
	})

	ref := tunnelv1.PublisherConnectionRef{
		PublishRunID: "publish_run_1", PublicURLID: "public_url_1", PublishRunNumber: 1,
		PublisherConnectionID: "connection_1", ConnectionSlot: 0,
		ConnectionAssignmentRevision: 1, RelayServiceID: "relay_service_1",
	}
	publisherTransport, err := (muxsession.TLSYamuxConnector{TLSConfig: &tls.Config{RootCAs: roots}}).Connect(
		ctx,
		muxsession.Endpoint{Address: listener.Addr().String(), ServerName: "relay.example"},
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = publisherTransport.Close() })
	publisherSession, err := tunnel.Dial(ctx, publisherTransport, tunnelv1.Message{
		Type: tunnelv1.Hello, ProtocolVersion: tunnelv1.Version, Role: tunnelv1.Publisher,
		Credential: "credential", PublisherConnection: &ref,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = publisherSession.Close() })
	acceptedRelay := awaitPublisherTest(t, relayResult)
	if acceptedRelay.err != nil {
		t.Fatal(acceptedRelay.err)
	}
	t.Cleanup(func() { _ = acceptedRelay.session.Close() })
	serveContext, stopServing := context.WithCancel(ctx)
	serveDone := make(chan error, 1)
	go func() { serveDone <- route.ServePublisherConnection(serveContext, publisherSession, ref) }()
	t.Cleanup(func() {
		stopServing()
		_ = publisherSession.Close()
		awaitPublisherTest(t, serveDone)
	})

	stream, err := acceptedRelay.session.OpenVisitorStream(ctx, tunnelv1.VisitorStreamHeader{
		ProtocolVersion: tunnelv1.Version, Kind: tunnelv1.VisitorStream,
		VisitorConnectionID: "visitor_connection_1", PublicURLID: ref.PublicURLID,
		PublishRunID: ref.PublishRunID, PublishRunNumber: ref.PublishRunNumber,
		PublisherConnectionID:        ref.PublisherConnectionID,
		ConnectionAssignmentRevision: ref.ConnectionAssignmentRevision,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = stream.Close() })
	if err := stream.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	header, err := proxyproto.Encode(proxyproto.Header{
		Source:      netip.MustParseAddrPort("192.0.2.10:1234"),
		Destination: netip.MustParseAddrPort("127.0.0.1:443"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := stream.Write(header); err != nil {
		t.Fatal(err)
	}
	client := tls.Client(stream, &tls.Config{
		ServerName: "route.example", MinVersion: tls.VersionTLS13,
		RootCAs: rootsForCertificate(t, publicURLCertificate),
	})
	if _, err := fmt.Fprint(client, "GET / HTTP/1.1\r\nHost: route.example\r\nConnection: close\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	response, err := http.ReadResponse(bufio.NewReader(client), nil)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(response.Body)
	_ = response.Body.Close()
	_ = client.Close()
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK || string(body) != "local response" {
		t.Fatalf("response = %d %q", response.StatusCode, body)
	}
	if got := awaitPublisherTest(t, forwarded); got != "192.0.2.10" {
		t.Fatalf("X-Forwarded-For = %q", got)
	}
}

func TestRouteServerNegotiatesHTTP2AndProxiesLocalHTTP(t *testing.T) {
	upstreamProtocol := make(chan int, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		upstreamProtocol <- request.ProtoMajor
		_, _ = response.Write([]byte("local response"))
	}))
	defer upstream.Close()
	route := startHTTPTestRouteServer(t, upstream.URL)
	handled := make(chan struct{})
	transport := &http.Transport{
		ForceAttemptHTTP2: true,
		TLSClientConfig: &tls.Config{
			ServerName: "route.example", MinVersion: tls.VersionTLS13,
			InsecureSkipVerify: true, // The test public URL certificate is self-signed.
		},
		DialContext: func(context.Context, string, string) (net.Conn, error) {
			return openHTTPTestRouteServer(route, handled)
		},
	}
	t.Cleanup(transport.CloseIdleConnections)
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	response, err := client.Get("https://route.example/")
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if response.ProtoMajor != 2 || response.TLS == nil {
		t.Fatalf("public response protocol = %s, TLS = %#v", response.Proto, response.TLS)
	}
	if response.TLS.Version != tls.VersionTLS13 {
		t.Fatalf("public TLS version = %#x, want TLS 1.3", response.TLS.Version)
	}
	if string(body) != "local response" {
		t.Fatalf("response body = %q", body)
	}
	if protocol := awaitPublisherTest(t, upstreamProtocol); protocol != 1 {
		t.Fatalf("local service HTTP version = %d, want 1", protocol)
	}
	transport.CloseIdleConnections()
	select {
	case <-handled:
	case <-time.After(time.Second):
		t.Fatal("route handler did not close")
	}
}

func startHTTPTestRouteServer(t *testing.T, target string) *PublicURLServer {
	t.Helper()
	route, err := NewPublicURLServer(PublicURLServerConfig{
		Hostname: "route.example", Target: target, Certificate: publicURLTestCertificate(t, "route.example"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := route.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = route.Close() })
	return route
}

func openHTTPTestRouteServer(route *PublicURLServer, handled chan struct{}) (net.Conn, error) {
	ingress, publisher := net.Pipe()
	_ = ingress.SetDeadline(time.Now().Add(5 * time.Second))
	go func() {
		route.handle(publisher)
		close(handled)
	}()
	header, err := proxyproto.Encode(proxyproto.Header{
		Source:      netip.MustParseAddrPort("192.0.2.10:1234"),
		Destination: netip.MustParseAddrPort("127.0.0.1:443"),
	})
	if err == nil {
		_, err = ingress.Write(header)
	}
	if err != nil {
		_ = ingress.Close()
		return nil, err
	}
	return ingress, nil
}

// Every real-I/O test wait has a local bound, including cleanup after Fatal.
func awaitPublisherTest[T any](t *testing.T, result <-chan T) T {
	t.Helper()
	select {
	case value := <-result:
		return value
	case <-time.After(5 * time.Second):
		t.Fatal("publisher test operation did not finish")
		var zero T
		return zero
	}
}

func TestRouteServerSelectsChallengeAndInstalledCertificate(t *testing.T) {
	route, err := NewPublicURLServer(PublicURLServerConfig{
		Hostname: "route.example", Target: "http://127.0.0.1:3000",
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
	application := publicURLTestCertificate(t, "route.example")
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
	route, err := NewPublicURLServer(PublicURLServerConfig{Hostname: "route.example", Target: "http://127.0.0.1:3000", Certificate: certificate})
	if err != nil {
		t.Fatalf("manual certificate rejected: %v", err)
	}
	defer route.Close()
	if _, err := certificateidentity.ValidateCertificate(certificate, "route.example", []string{"route.example"}); err == nil {
		t.Fatal("automatic certificate policy accepted a wildcard RSA certificate")
	}
}

func TestAutomaticCertificateDoesNotTrustSuppliedLeaf(t *testing.T) {
	certificate := publicURLTestCertificate(t, "other.example")
	certificate.Leaf = publicURLTestCertificate(t, "route.example").Leaf
	if _, err := certificateidentity.ValidateCertificate(certificate, "route.example", []string{"route.example"}); err == nil {
		t.Fatal("a supplied Leaf concealed a different certificate identity")
	}
}

func TestManualCertificateExpires(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		certificate := publicURLTestCertificate(t, "route.example")
		route, err := NewPublicURLServer(PublicURLServerConfig{
			Hostname: "route.example", Target: "http://127.0.0.1:3000", Certificate: certificate,
		})
		if err != nil {
			t.Fatal(err)
		}
		defer route.Close()

		<-route.certificateExpiration()
		if _, err := route.getCertificate(&tls.ClientHelloInfo{
			ServerName: "route.example", SupportedProtos: []string{"http/1.1"},
		}); !errors.Is(err, errCertificateExpired) {
			t.Fatalf("certificate selection after expiry = %v", err)
		}
	})
}

func TestCertificateReplacementAndExpirationAreAtomic(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		first := publicURLTestCertificateUntil(t, "route.example", time.Now().Add(time.Hour))
		route, err := NewPublicURLServer(PublicURLServerConfig{
			Hostname: "route.example", Target: "http://127.0.0.1:3000", Certificate: first,
		})
		if err != nil {
			t.Fatal(err)
		}
		defer route.Close()

		time.Sleep(30 * time.Minute)
		replacement := publicURLTestCertificateUntil(t, "route.example", time.Now().Add(2*time.Hour))
		if err := route.InstallCertificate(replacement); err != nil {
			t.Fatal(err)
		}
		time.Sleep(31 * time.Minute)
		select {
		case <-route.certificateExpiration():
			t.Fatal("replaced certificate's old timer expired the route")
		default:
		}
		<-route.certificateExpiration()
		if err := route.InstallCertificate(publicURLTestCertificate(t, "route.example")); !errors.Is(err, errCertificateExpired) {
			t.Fatalf("replacement after expiration = %v", err)
		}
	})
}

func TestReadyCallbackIsNotCalledAfterCertificateExpiry(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		route, err := NewPublicURLServer(PublicURLServerConfig{
			Hostname: "route.example", Target: "http://127.0.0.1:3000",
			Certificate: publicURLTestCertificate(t, "route.example"),
		})
		if err != nil {
			t.Fatal(err)
		}
		defer route.Close()
		<-route.certificateExpiration()
		calls := 0
		err = route.withValidCertificate(func() error {
			calls++
			return nil
		})
		if !errors.Is(err, errCertificateExpired) || calls != 0 {
			t.Fatalf("ready after expiration = %v, calls = %d", err, calls)
		}
	})
}

func publicURLTestCertificate(t *testing.T, hostname string) tls.Certificate {
	return publicURLTestCertificateUntil(t, hostname, time.Now().Add(time.Hour))
}

func publicURLTestCertificateUntil(t *testing.T, hostname string, notAfter time.Time) tls.Certificate {
	t.Helper()
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: hostname}, DNSNames: []string{hostname},
		NotBefore: time.Now().Add(-time.Minute), NotAfter: notAfter,
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

func rootsForCertificate(t *testing.T, certificate tls.Certificate) *x509.CertPool {
	t.Helper()
	if certificate.Leaf == nil {
		leaf, err := x509.ParseCertificate(certificate.Certificate[0])
		if err != nil {
			t.Fatal(err)
		}
		certificate.Leaf = leaf
	}
	roots := x509.NewCertPool()
	roots.AddCert(certificate.Leaf)
	return roots
}

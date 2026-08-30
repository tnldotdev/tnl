package tailtransport

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/0xcadams/tnl/internal/agent"
	"github.com/0xcadams/tnl/internal/proxyproto"
	"github.com/0xcadams/tnl/internal/router"
	"github.com/0xcadams/tnl/internal/testutil/integrationtest"
	"golang.org/x/crypto/acme"
	"tailscale.com/types/key"
)

var testACMEIdentifierOID = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 31}

func TestIntegrationTLSALPNThroughTailcat(t *testing.T) {
	pebblePath := integrationtest.RequirePebble(t)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	hostname := "route.tnl.test"

	publicListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = publicListener.Close() })
	dnsAddress := integrationtest.StartChallengeDNS(t)
	pebble := integrationtest.StartPebble(t, pebblePath, publicListener.Addr().(*net.TCPAddr).Port, dnsAddress)

	region := runTestDERP(t)
	ingressKey := key.NewNode()
	proxyErrors := make(chan error, 1)

	firstChallenges := new(agent.TLSALPNChallenges)
	firstServer, firstEndpoint, err := startTestServer(ctx, region, ingressKey.Public(), tlsALPNHandler(firstChallenges, proxyErrors))
	if err != nil {
		t.Fatalf("start first agent: %v", err)
	}
	firstDialer, err := startTestDialer(ctx, region, firstEndpoint, ingressKey)
	if err != nil {
		firstServer.Close()
		t.Fatalf("start first ingress dialer: %v", err)
	}
	ingress := startTLSALPNIngress(t, publicListener, hostname, firstDialer)
	t.Cleanup(func() {
		ingress.Close()
		firstDialer.Close()
		firstServer.Close()
	})

	accountKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	client := pebble.ACMEClient(accountKey, "")
	account, err := client.Register(ctx, new(acme.Account), acme.AcceptTOS)
	if err != nil {
		t.Fatalf("register ACME account: %v", err)
	}
	order, err := client.AuthorizeOrder(ctx, acme.DomainIDs(hostname))
	if err != nil {
		t.Fatalf("create ACME order: %v", err)
	}
	if len(order.AuthzURLs) != 1 {
		t.Fatalf("authorization URLs = %v; want one", order.AuthzURLs)
	}
	authorization, err := client.GetAuthorization(ctx, order.AuthzURLs[0])
	if err != nil {
		t.Fatalf("get authorization: %v", err)
	}
	challenge := tlsALPNChallenge(t, authorization)
	keyAuthorization, err := client.HTTP01ChallengeResponse(challenge.Token)
	if err != nil {
		t.Fatalf("derive key authorization: %v", err)
	}
	expiresAt := authorization.Expires
	if expiresAt.IsZero() {
		expiresAt = order.Expires
	}
	if !expiresAt.After(time.Now()) {
		t.Fatalf("authorization expiry = %s; want future time", expiresAt)
	}
	command := agent.TLSALPNChallenge{
		ID:        challenge.URI,
		Hostname:  hostname,
		Digest:    sha256.Sum256([]byte(keyAuthorization)),
		ExpiresAt: expiresAt,
	}
	if err := firstChallenges.Install(command); err != nil {
		t.Fatalf("install first challenge: %v", err)
	}
	if err := probeTLSALPN(publicListener.Addr().String(), hostname, command.Digest); err != nil {
		t.Fatalf("first routed probe: %v", err)
	}

	// Prepare replacement endpoints while the order remains pending. The
	// challenge command is replayed without sharing its private key.
	secondChallenges := new(agent.TLSALPNChallenges)
	if err := secondChallenges.Install(command); err != nil {
		t.Fatalf("reinstall challenge: %v", err)
	}
	secondServer, secondEndpoint, err := startTestServer(ctx, region, ingressKey.Public(), tlsALPNHandler(secondChallenges, proxyErrors))
	if err != nil {
		t.Fatalf("restart agent: %v", err)
	}
	secondDialer, err := startTestDialer(ctx, region, secondEndpoint, ingressKey)
	if err != nil {
		secondServer.Close()
		t.Fatalf("restart ingress dialer: %v", err)
	}
	t.Cleanup(func() {
		secondDialer.Close()
		secondServer.Close()
	})
	client = pebble.ACMEClient(accountKey, acme.KeyID(account.URI))
	validationStarted, releaseValidation := ingress.GateValidation()
	defer releaseValidation()
	if _, err := client.Accept(ctx, challenge); err != nil {
		t.Fatalf("accept challenge: %v", err)
	}
	select {
	case <-validationStarted:
	case <-ctx.Done():
		t.Fatalf("wait for validation: %v", ctx.Err())
	}

	// Swap the active route after Pebble's validation ClientHello arrives.
	ingress.SetDialer(secondDialer)
	if err := firstDialer.Close(); err != nil {
		t.Fatalf("close first dialer: %v", err)
	}
	if err := firstServer.Close(); err != nil {
		t.Fatalf("close first server: %v", err)
	}
	releaseValidation()
	if _, err := client.WaitAuthorization(ctx, authorization.URI); err != nil {
		t.Fatalf("wait for authorization: %v", err)
	}
	if err := probeTLSALPN(publicListener.Addr().String(), hostname, command.Digest); err != nil {
		t.Fatalf("terminal challenge probe: %v", err)
	}
	if !secondChallenges.Remove(command.ID) {
		t.Fatal("remove terminal challenge: challenge was not installed")
	}
	if err := probeTLSALPN(publicListener.Addr().String(), hostname, command.Digest); err == nil {
		t.Fatal("TLS-ALPN probe succeeded after challenge cleanup")
	}

	client = pebble.ACMEClient(accountKey, acme.KeyID(account.URI))
	readyOrder, err := client.WaitOrder(ctx, order.URI)
	if err != nil {
		t.Fatalf("wait for ready order: %v", err)
	}
	finalizeURL := readyOrder.FinalizeURL
	if finalizeURL == "" {
		finalizeURL = order.FinalizeURL
	}
	if finalizeURL == "" {
		t.Fatal("ACME order has no finalize URL")
	}
	applicationKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{DNSNames: []string{hostname}}, applicationKey)
	if err != nil {
		t.Fatal(err)
	}
	chain, err := finalizeOrder(ctx, client, order.URI, finalizeURL, csr)
	if err != nil {
		t.Fatalf("finalize order: %v; Pebble logs:\n%s", err, pebble.Logs())
	}
	verifyIssuedCertificate(t, pebble, hostname, applicationKey, chain)
	select {
	case err := <-proxyErrors:
		t.Fatalf("agent PROXY protocol: %v", err)
	default:
	}
	select {
	case err := <-ingress.Errors():
		t.Fatalf("ingress: %v", err)
	default:
	}
}

func finalizeOrder(ctx context.Context, client *acme.Client, orderURL, finalizeURL string, csr []byte) ([][]byte, error) {
	chain, _, err := client.CreateOrderCert(ctx, finalizeURL, csr, true)
	if err == nil {
		return chain, nil
	}

	// Reconcile the known order URL before repeating an ambiguous mutation.
	// x/crypto/acme cannot poll Pebble's asynchronous finalize response because
	// that response does not repeat the order's Location header.
	order, reconcileErr := client.WaitOrder(ctx, orderURL)
	if reconcileErr != nil || order.Status != acme.StatusValid || order.CertURL == "" {
		return nil, fmt.Errorf("submit CSR: %w; reconcile order: %v", err, reconcileErr)
	}
	chain, fetchErr := client.FetchCert(ctx, order.CertURL, true)
	if fetchErr != nil {
		return nil, fmt.Errorf("fetch reconciled certificate: %w", fetchErr)
	}
	return chain, nil
}

func tlsALPNChallenge(t *testing.T, authorization *acme.Authorization) *acme.Challenge {
	t.Helper()
	for _, challenge := range authorization.Challenges {
		if challenge.Type == "tls-alpn-01" {
			return challenge
		}
	}
	t.Fatalf("authorization has no TLS-ALPN-01 challenge: %+v", authorization.Challenges)
	return nil
}

func tlsALPNHandler(challenges *agent.TLSALPNChallenges, proxyErrors chan<- error) func(net.Conn) {
	return func(conn net.Conn) {
		_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
		_, replay, err := proxyproto.Decode(conn)
		if err != nil {
			select {
			case proxyErrors <- err:
			default:
			}
			return
		}
		tlsConn := tls.Server(&readerConn{Conn: conn, reader: replay}, &tls.Config{
			MinVersion:             tls.VersionTLS12,
			NextProtos:             []string{acme.ALPNProto},
			GetCertificate:         challenges.GetCertificate,
			SessionTicketsDisabled: true,
		})
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		_ = tlsConn.HandshakeContext(ctx)
	}
}

type readerConn struct {
	net.Conn
	reader io.Reader
}

func (c *readerConn) Read(destination []byte) (int, error) {
	return c.reader.Read(destination)
}

type tlsALPNIngress struct {
	listener net.Listener
	hostname string

	mu     sync.RWMutex
	dialer *Dialer
	gate   *tlsALPNGate
	errors chan error
	done   chan struct{}
	active sync.WaitGroup
}

type tlsALPNGate struct {
	started chan struct{}
	proceed chan struct{}
	once    sync.Once
}

func startTLSALPNIngress(t *testing.T, listener net.Listener, hostname string, dialer *Dialer) *tlsALPNIngress {
	t.Helper()
	ingress := &tlsALPNIngress{
		listener: listener,
		hostname: hostname,
		dialer:   dialer,
		errors:   make(chan error, 8),
		done:     make(chan struct{}),
	}
	go ingress.serve()
	return ingress
}

func (i *tlsALPNIngress) serve() {
	defer close(i.done)
	for {
		conn, err := i.listener.Accept()
		if err != nil {
			if !errors.Is(err, net.ErrClosed) {
				i.report(err)
			}
			return
		}
		i.active.Add(1)
		go func() {
			defer i.active.Done()
			i.handle(conn)
		}()
	}
}

func (i *tlsALPNIngress) handle(public net.Conn) {
	defer public.Close()
	hello, err := router.InspectClientHello(public)
	if err != nil {
		i.report(err)
		return
	}
	if hello.ServerName != i.hostname || !hello.ACMETLSALPN {
		return
	}

	i.mu.RLock()
	gate := i.gate
	i.mu.RUnlock()
	if gate != nil {
		gate.once.Do(func() { close(gate.started) })
		<-gate.proceed
	}

	i.mu.RLock()
	dialer := i.dialer
	i.mu.RUnlock()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	stream, err := dialer.Open(ctx)
	if err != nil {
		i.report(err)
		return
	}
	defer stream.Close()
	_ = stream.SetDeadline(time.Now().Add(20 * time.Second))
	source, err := connectionAddrPort(public.RemoteAddr())
	if err != nil {
		i.report(err)
		return
	}
	destination, err := connectionAddrPort(public.LocalAddr())
	if err != nil {
		i.report(err)
		return
	}
	header, err := proxyproto.Encode(proxyproto.Header{Source: source, Destination: destination})
	if err != nil {
		i.report(err)
		return
	}
	if _, err := io.Copy(stream, bytes.NewReader(header)); err != nil {
		i.report(err)
		return
	}
	deadline := time.Now().Add(20 * time.Second)
	_ = public.SetDeadline(deadline)
	_ = stream.SetDeadline(deadline)

	var relays sync.WaitGroup
	relays.Add(2)
	go func() {
		defer relays.Done()
		_, _ = io.Copy(stream, hello.Replay)
		closeWrite(stream)
	}()
	go func() {
		defer relays.Done()
		_, _ = io.Copy(public, stream)
		closeWrite(public)
	}()
	relays.Wait()
}

func (i *tlsALPNIngress) SetDialer(dialer *Dialer) {
	i.mu.Lock()
	i.dialer = dialer
	i.mu.Unlock()
}

func (i *tlsALPNIngress) GateValidation() (<-chan struct{}, func()) {
	gate := &tlsALPNGate{started: make(chan struct{}), proceed: make(chan struct{})}
	i.mu.Lock()
	i.gate = gate
	i.mu.Unlock()
	return gate.started, sync.OnceFunc(func() {
		i.mu.Lock()
		if i.gate == gate {
			i.gate = nil
		}
		i.mu.Unlock()
		close(gate.proceed)
	})
}

func (i *tlsALPNIngress) Errors() <-chan error {
	return i.errors
}

func (i *tlsALPNIngress) Close() {
	i.listener.Close()
	<-i.done
	i.active.Wait()
}

func (i *tlsALPNIngress) report(err error) {
	select {
	case i.errors <- err:
	default:
	}
}

func closeWrite(conn net.Conn) {
	if closer, ok := conn.(interface{ CloseWrite() error }); ok {
		_ = closer.CloseWrite()
	}
}

func connectionAddrPort(address net.Addr) (netip.AddrPort, error) {
	endpoint, err := netip.ParseAddrPort(address.String())
	if err != nil {
		return netip.AddrPort{}, err
	}
	return endpoint, nil
}

func probeTLSALPN(address, hostname string, digest [sha256.Size]byte) error {
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	conn, err := tls.DialWithDialer(dialer, "tcp", address, &tls.Config{
		ServerName:         hostname,
		NextProtos:         []string{acme.ALPNProto},
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: true, // The RFC 8737 challenge certificate is self-signed.
	})
	if err != nil {
		return err
	}
	defer conn.Close()
	state := conn.ConnectionState()
	if state.NegotiatedProtocol != acme.ALPNProto || len(state.PeerCertificates) != 1 {
		return fmt.Errorf("unexpected TLS-ALPN state: protocol=%q certificates=%d", state.NegotiatedProtocol, len(state.PeerCertificates))
	}
	if len(state.PeerCertificates[0].DNSNames) != 1 || state.PeerCertificates[0].DNSNames[0] != hostname {
		return fmt.Errorf("unexpected challenge names: %v", state.PeerCertificates[0].DNSNames)
	}
	for _, extension := range state.PeerCertificates[0].Extensions {
		if !extension.Id.Equal(testACMEIdentifierOID) || !extension.Critical {
			continue
		}
		var actual []byte
		rest, err := asn1.Unmarshal(extension.Value, &actual)
		if err != nil || len(rest) != 0 || !bytes.Equal(actual, digest[:]) {
			return errors.New("unexpected ACME identifier digest")
		}
		return nil
	}
	return errors.New("missing critical ACME identifier extension")
}

func verifyIssuedCertificate(t *testing.T, pebble *integrationtest.Pebble, hostname string, key *ecdsa.PrivateKey, chain [][]byte) {
	t.Helper()
	if len(chain) < 2 {
		t.Fatalf("issued chain length = %d; want at least 2", len(chain))
	}
	leaf, err := x509.ParseCertificate(chain[0])
	if err != nil {
		t.Fatal(err)
	}
	if leaf.IsCA || len(leaf.DNSNames) != 1 || leaf.DNSNames[0] != hostname ||
		len(leaf.IPAddresses) != 0 || len(leaf.EmailAddresses) != 0 || len(leaf.URIs) != 0 {
		t.Fatalf("unexpected issued leaf names: IsCA=%v DNS=%v IP=%v email=%v URI=%v", leaf.IsCA, leaf.DNSNames, leaf.IPAddresses, leaf.EmailAddresses, leaf.URIs)
	}
	spki, err := x509.MarshalPKIXPublicKey(key.Public())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(leaf.RawSubjectPublicKeyInfo, spki) {
		t.Fatal("issued leaf SPKI does not match the CSR key")
	}

	roots := pebble.IssuerRoots(t)
	intermediates := x509.NewCertPool()
	for _, der := range chain[1:] {
		certificate, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		intermediates.AddCert(certificate)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{
		DNSName:       hostname,
		Roots:         roots,
		Intermediates: intermediates,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}); err != nil {
		t.Fatalf("verify issued chain: %v", err)
	}
}

package publisher

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/tnldotdev/tnl/internal/localproxy"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/proxyproto"
	"github.com/tnldotdev/tnl/internal/sourceauth"
	"github.com/tnldotdev/tnl/internal/tailtransport"
	"github.com/tnldotdev/tnl/internal/tlschallenge"
	"golang.org/x/crypto/acme"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
)

type RouteConfig struct {
	Hostname          string
	Target            string
	Certificate       tls.Certificate
	StrictCertificate bool
	SourceKey         [32]byte
	AllowedIPPrefixes []string
	AllowedClient     key.NodePublic
	RelayRegion       string
	Regions           map[string]*tailcfg.DERPRegion
	Logf              logger.Logf
}

type Route struct {
	hostname          string
	strictCertificate bool
	tls               *tls.Config
	certificate       atomic.Pointer[tls.Certificate]
	challenges        tlschallenge.TLSALPNChallenges
	queue             *routeListener
	http              *http.Server
	tailcat           *tailtransport.Server
	sourceKey         [32]byte
	allowedIPPrefixes []netip.Prefix

	mu        sync.Mutex
	started   bool
	closed    bool
	httpDone  chan error
	closeOnce sync.Once
}

func NewRoute(config RouteConfig) (*Route, error) {
	hostname, err := naming.CanonicalizeHostname(config.Hostname)
	if err != nil || hostname != config.Hostname {
		return nil, errors.New("publisher: route hostname must be canonical")
	}
	handler, err := localproxy.New(config.Target, hostname)
	if err != nil {
		return nil, err
	}
	if config.SourceKey == [32]byte{} {
		return nil, errors.New("publisher: source authentication key is required")
	}
	allowedIPPrefixes := make([]netip.Prefix, len(config.AllowedIPPrefixes))
	for index, value := range config.AllowedIPPrefixes {
		prefix, err := netip.ParsePrefix(value)
		if err != nil || prefix.String() != value {
			return nil, errors.New("publisher: allowed IP prefix must be canonical")
		}
		allowedIPPrefixes[index] = prefix
	}
	queue := newRouteListener()
	route := &Route{
		hostname:          hostname,
		strictCertificate: config.StrictCertificate,
		sourceKey:         config.SourceKey,
		allowedIPPrefixes: allowedIPPrefixes,
		queue:             queue,
		tls: &tls.Config{
			MinVersion:             tls.VersionTLS12,
			NextProtos:             []string{"http/1.1", acme.ALPNProto},
			SessionTicketsDisabled: true,
		},
		http: &http.Server{
			Handler:           handler,
			ReadHeaderTimeout: 10 * time.Second,
			IdleTimeout:       2 * time.Minute,
			MaxHeaderBytes:    64 << 10,
			ErrorLog:          log.New(io.Discard, "", 0),
		},
		httpDone: make(chan error, 1),
	}
	route.tls.GetCertificate = route.getCertificate
	if len(config.Certificate.Certificate) != 0 || config.Certificate.PrivateKey != nil {
		if err := route.InstallCertificate(config.Certificate); err != nil {
			return nil, err
		}
	}
	tailcat, err := tailtransport.NewServer(tailtransport.ServerConfig{
		AllowedClient: config.AllowedClient,
		RelayRegion:   config.RelayRegion,
		Regions:       config.Regions,
		Handler:       route.handle,
		Logf:          config.Logf,
	})
	if err != nil {
		return nil, err
	}
	route.tailcat = tailcat
	return route, nil
}

func (r *Route) InstallChallenge(challenge tlschallenge.TLSALPNChallenge) error {
	if challenge.Hostname != r.hostname {
		return errors.New("publisher: TLS-ALPN challenge hostname does not match route")
	}
	return r.challenges.Install(challenge)
}

func (r *Route) RemoveChallenge(id string) bool { return r.challenges.Remove(id) }

func (r *Route) InstallCertificate(certificate tls.Certificate) error {
	if err := validateCertificate(certificate, r.hostname, r.strictCertificate); err != nil {
		return err
	}
	copy := certificate
	r.certificate.Store(&copy)
	return nil
}

func (r *Route) VerifyCertificate(expected tls.Certificate) error {
	if len(expected.Certificate) == 0 {
		return errors.New("publisher: expected application certificate is empty")
	}
	serverConnection, clientConnection := net.Pipe()
	defer serverConnection.Close()
	defer clientConnection.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	serverResult := make(chan error, 1)
	go func() {
		server := tls.Server(serverConnection, r.tls.Clone())
		serverResult <- server.HandshakeContext(ctx)
	}()
	client := tls.Client(clientConnection, &tls.Config{
		ServerName: r.hostname, MinVersion: tls.VersionTLS12, NextProtos: []string{"http/1.1"},
		InsecureSkipVerify: true, // This probes selection and key usability; the server validated the chain.
	})
	clientErr := client.HandshakeContext(ctx)
	serverErr := <-serverResult
	peers := client.ConnectionState().PeerCertificates
	if clientErr != nil || serverErr != nil {
		return fmt.Errorf("publisher: verify installed application certificate handshake: %w", errors.Join(clientErr, serverErr))
	}
	if len(peers) == 0 || !bytes.Equal(peers[0].Raw, expected.Certificate[0]) {
		return errors.New("publisher: installed application certificate does not match expected leaf")
	}
	return nil
}

func (r *Route) getCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	if hello == nil || hello.ServerName != r.hostname {
		return nil, errors.New("publisher: TLS SNI does not match route")
	}
	if len(hello.SupportedProtos) == 1 && hello.SupportedProtos[0] == acme.ALPNProto {
		return r.challenges.GetCertificate(hello)
	}
	certificate := r.certificate.Load()
	if certificate == nil {
		return nil, errors.New("publisher: application certificate is not installed")
	}
	return certificate, nil
}

func (r *Route) Start(ctx context.Context) (tailtransport.Endpoint, error) {
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return tailtransport.Endpoint{}, net.ErrClosed
	}
	if r.started {
		r.mu.Unlock()
		return tailtransport.Endpoint{}, errors.New("publisher: route already started")
	}
	r.started = true
	r.mu.Unlock()
	r.startHTTP()
	endpoint, err := r.tailcat.Start(ctx)
	if err != nil {
		_ = r.Close()
		return tailtransport.Endpoint{}, err
	}
	return endpoint, nil
}

func (r *Route) Drain(ctx context.Context) error {
	tailcatDone := make(chan error, 1)
	go func() { tailcatDone <- r.tailcat.Drain(ctx) }()
	httpErr := r.http.Shutdown(ctx)
	return errors.Join(<-tailcatDone, httpErr)
}

func (r *Route) Close() error {
	var result error
	r.closeOnce.Do(func() {
		r.mu.Lock()
		r.closed = true
		started := r.started
		r.mu.Unlock()
		result = errors.Join(r.http.Close(), r.queue.Close(), r.tailcat.Close())
		if started {
			result = errors.Join(result, <-r.httpDone)
		}
	})
	return result
}

func (r *Route) startHTTP() {
	go func() {
		err := r.http.Serve(r.queue)
		if errors.Is(err, http.ErrServerClosed) || errors.Is(err, net.ErrClosed) {
			err = nil
		}
		r.httpDone <- err
		close(r.httpDone)
	}()
}

func (r *Route) handle(connection net.Conn) {
	_ = connection.SetDeadline(time.Now().Add(10 * time.Second))
	claim, err := sourceauth.Server(connection, r.sourceKey)
	if err != nil {
		return
	}
	if claim.Purpose == sourceauth.PurposeApplication && !routeIPAllowed(claim.Header.Source.Addr(), r.allowedIPPrefixes) {
		return
	}
	metadata := &metadataConn{Conn: connection, header: claim.Header}
	tracked := newDoneConn(metadata)
	secured := tls.Server(tracked, r.tls)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	err = secured.HandshakeContext(ctx)
	cancel()
	if err != nil {
		_ = secured.Close()
		return
	}
	_ = secured.SetDeadline(time.Time{})
	challenge := secured.ConnectionState().NegotiatedProtocol == acme.ALPNProto
	if challenge != (claim.Purpose == sourceauth.PurposeACME) {
		_ = secured.Close()
		return
	}
	if challenge {
		_ = tracked.Close()
		return
	}
	if !r.queue.enqueue(secured) {
		_ = secured.Close()
		return
	}
	<-tracked.done
}

func validateCertificate(certificate tls.Certificate, hostname string, strict bool) error {
	if len(certificate.Certificate) == 0 || certificate.PrivateKey == nil {
		return errors.New("publisher: application certificate and private key are required")
	}
	leaf := certificate.Leaf
	if leaf == nil {
		var err error
		leaf, err = x509.ParseCertificate(certificate.Certificate[0])
		if err != nil {
			return fmt.Errorf("publisher: parse application certificate: %w", err)
		}
	}
	if err := leaf.VerifyHostname(hostname); err != nil {
		return fmt.Errorf("publisher: application certificate does not match route: %w", err)
	}
	if !strict {
		return nil
	}
	if len(leaf.DNSNames) != 1 || leaf.DNSNames[0] != hostname || len(leaf.EmailAddresses) != 0 ||
		len(leaf.IPAddresses) != 0 || len(leaf.URIs) != 0 || leaf.IsCA ||
		leaf.NotBefore.After(time.Now().Add(5*time.Minute)) || !leaf.NotAfter.After(time.Now()) {
		return errors.New("publisher: application certificate identity or validity is invalid")
	}
	serverAuth := false
	for _, usage := range leaf.ExtKeyUsage {
		serverAuth = serverAuth || usage == x509.ExtKeyUsageServerAuth || usage == x509.ExtKeyUsageAny
	}
	if !serverAuth {
		return errors.New("publisher: application certificate is not valid for TLS servers")
	}
	privateKey, ok := certificate.PrivateKey.(*ecdsa.PrivateKey)
	if !ok || privateKey.Curve != elliptic.P256() {
		return errors.New("publisher: application certificate requires an ECDSA P-256 key")
	}
	publicDER, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil || !bytes.Equal(publicDER, leaf.RawSubjectPublicKeyInfo) {
		return errors.New("publisher: application certificate key does not match leaf")
	}
	return nil
}

type routeListener struct {
	connections chan net.Conn
	closed      chan struct{}
	mu          sync.Mutex
	isClosed    bool
	once        sync.Once
}

func newRouteListener() *routeListener {
	return &routeListener{connections: make(chan net.Conn, 64), closed: make(chan struct{})}
}

func (l *routeListener) Accept() (net.Conn, error) {
	select {
	case connection := <-l.connections:
		return connection, nil
	case <-l.closed:
		return nil, net.ErrClosed
	}
}

func (l *routeListener) Close() error {
	l.once.Do(func() {
		l.mu.Lock()
		l.isClosed = true
		close(l.closed)
		for {
			select {
			case connection := <-l.connections:
				_ = connection.Close()
			default:
				l.mu.Unlock()
				return
			}
		}
	})
	return nil
}

func (*routeListener) Addr() net.Addr { return routeAddress("tnl-route") }

func (l *routeListener) enqueue(connection net.Conn) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.isClosed {
		return false
	}
	select {
	case l.connections <- connection:
		return true
	default:
		return false
	}
}

type routeAddress string

func (routeAddress) Network() string  { return "tailcat" }
func (a routeAddress) String() string { return string(a) }

type metadataConn struct {
	net.Conn
	header proxyproto.Header
}

func routeIPAllowed(source netip.Addr, prefixes []netip.Prefix) bool {
	if len(prefixes) == 0 {
		return true
	}
	source = source.Unmap()
	for _, prefix := range prefixes {
		if prefix.Contains(source) {
			return true
		}
	}
	return false
}

func (c *metadataConn) RemoteAddr() net.Addr { return tcpAddress(c.header.Source) }
func (c *metadataConn) LocalAddr() net.Addr  { return tcpAddress(c.header.Destination) }

func tcpAddress(endpoint netip.AddrPort) net.Addr {
	return &net.TCPAddr{IP: net.IP(endpoint.Addr().AsSlice()), Port: int(endpoint.Port())}
}

type doneConn struct {
	net.Conn
	done chan struct{}
	once sync.Once
}

func newDoneConn(connection net.Conn) *doneConn {
	return &doneConn{Conn: connection, done: make(chan struct{})}
}

func (c *doneConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(func() { close(c.done) })
	return err
}

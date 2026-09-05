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
	"github.com/tnldotdev/tnl/internal/tlschallenge"
	"github.com/tnldotdev/tnl/internal/tunnel"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
	"golang.org/x/crypto/acme"
)

// RouteConfig configures publisher TLS termination and local HTTP forwarding.
type RouteConfig struct {
	Hostname          string
	Target            string
	Certificate       tls.Certificate
	StrictCertificate bool
}

type Route struct {
	hostname           string
	strictCertificate  bool
	tls                *tls.Config
	certificate        atomic.Pointer[tls.Certificate]
	certificateTimer   *time.Timer
	certificateExpired chan struct{}
	challenges         tlschallenge.TLSALPNChallenges
	queue              *routeListener
	http               *http.Server
	mu                 sync.Mutex
	started            bool
	closed             bool
	httpDone           chan error
	closeOnce          sync.Once
}

// NewRoute creates a publisher route served by publisher connections.
func NewRoute(config RouteConfig) (*Route, error) {
	hostname, err := naming.CanonicalizeHostname(config.Hostname)
	if err != nil || hostname != config.Hostname {
		return nil, errors.New("publisher: route hostname must be canonical")
	}
	handler, err := localproxy.New(config.Target, hostname)
	if err != nil {
		return nil, err
	}
	queue := newRouteListener()
	route := &Route{
		hostname:          hostname,
		strictCertificate: config.StrictCertificate,
		queue:             queue,
		tls: &tls.Config{
			MinVersion:             tls.VersionTLS12,
			NextProtos:             []string{"h2", "http/1.1", acme.ALPNProto},
			SessionTicketsDisabled: true,
		},
		http: &http.Server{
			Handler:           handler,
			ReadHeaderTimeout: 10 * time.Second,
			IdleTimeout:       2 * time.Minute,
			MaxHeaderBytes:    64 << 10,
			ErrorLog:          log.New(io.Discard, "", 0),
		},
		httpDone:           make(chan error, 1),
		certificateExpired: make(chan struct{}),
	}
	route.tls.GetCertificate = route.getCertificate
	if len(config.Certificate.Certificate) != 0 || config.Certificate.PrivateKey != nil {
		if err := route.InstallCertificate(config.Certificate); err != nil {
			_ = route.Close()
			return nil, err
		}
	}
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
	if copy.Leaf == nil {
		var err error
		copy.Leaf, err = x509.ParseCertificate(copy.Certificate[0])
		if err != nil {
			return fmt.Errorf("publisher: parse application certificate: %w", err)
		}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return net.ErrClosed
	}
	select {
	case <-r.certificateExpired:
		return errCertificateExpired
	default:
	}
	if r.certificateTimer != nil {
		r.certificateTimer.Stop()
	}
	installed := &copy
	r.certificate.Store(installed)
	r.certificateTimer = time.AfterFunc(max(time.Until(copy.Leaf.NotAfter), 0), func() {
		r.mu.Lock()
		r.expireCertificateLocked(installed)
		r.mu.Unlock()
	})
	return nil
}

func (r *Route) certificateExpiration() <-chan struct{} { return r.certificateExpired }

func (r *Route) withValidCertificate(call func() error) error {
	r.mu.Lock()
	certificate := r.certificate.Load()
	if certificate == nil {
		r.mu.Unlock()
		return errors.New("publisher: application certificate is not installed")
	}
	select {
	case <-r.certificateExpired:
		r.mu.Unlock()
		return errCertificateExpired
	default:
	}
	if !certificate.Leaf.NotAfter.After(time.Now()) {
		if r.certificateTimer != nil {
			r.certificateTimer.Stop()
		}
		r.expireCertificateLocked(certificate)
		r.mu.Unlock()
		return errCertificateExpired
	}
	r.mu.Unlock()
	return call()
}

func (r *Route) expireCertificateLocked(certificate *tls.Certificate) {
	if r.closed || r.certificate.Load() != certificate {
		return
	}
	select {
	case <-r.certificateExpired:
		return
	default:
		r.certificateTimer = nil
		close(r.certificateExpired)
	}
}

func (r *Route) getCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	if hello == nil {
		return nil, errors.New("publisher: TLS SNI does not match route")
	}
	hostname, err := naming.CanonicalizeHostname(hello.ServerName)
	if err != nil || hostname != r.hostname {
		return nil, errors.New("publisher: TLS SNI does not match route")
	}
	if len(hello.SupportedProtos) == 1 && hello.SupportedProtos[0] == acme.ALPNProto {
		return r.challenges.GetCertificate(hello)
	}
	certificate := r.certificate.Load()
	if certificate == nil {
		return nil, errors.New("publisher: application certificate is not installed")
	}
	if !certificate.Leaf.NotAfter.After(time.Now()) {
		return nil, errCertificateExpired
	}
	return certificate, nil
}

// Start starts publisher TLS termination and local HTTP forwarding.
func (r *Route) Start() error {
	return r.start()
}

func (r *Route) start() error {
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return net.ErrClosed
	}
	if r.started {
		r.mu.Unlock()
		return errors.New("publisher: route already started")
	}
	r.started = true
	r.mu.Unlock()
	r.startHTTP()
	return nil
}

// ServePublisherConnection accepts visitor streams for one exact publisher
// connection. The caller owns the session and closes it to end active streams.
func (r *Route) ServePublisherConnection(
	ctx context.Context,
	session *tunnel.Session,
	ref tunnelv1.PublisherConnectionRef,
) error {
	if session == nil {
		return errors.New("publisher: tunnel session is required")
	}
	if err := ref.Validate(); err != nil {
		return err
	}
	for {
		incoming, err := session.AcceptPublisherStream(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		code := r.validateIncomingRoute(incoming.Header, ref)
		if code != "" {
			_ = incoming.Reject(code)
			continue
		}
		if err := incoming.Accept(); err != nil {
			return err
		}
		go r.handle(incoming.Stream)
	}
}

func (r *Route) validateIncomingRoute(
	header tunnelv1.PublisherStreamHeader,
	ref tunnelv1.PublisherConnectionRef,
) tunnelv1.ErrorCode {
	r.mu.Lock()
	closed := r.closed
	r.mu.Unlock()
	if closed {
		return tunnelv1.Unavailable
	}
	if header.RouteID != ref.RouteID || header.RouteSessionID != ref.RouteSessionID ||
		header.RouteVersion != ref.RouteVersion {
		return tunnelv1.StaleRouteVersion
	}
	if header.PublisherConnectionID != ref.PublisherConnectionID ||
		header.ConnectionAssignmentRevision != ref.ConnectionAssignmentRevision {
		return tunnelv1.StaleConnectionAssignment
	}
	return ""
}

func (r *Route) Drain(ctx context.Context) error {
	return r.http.Shutdown(ctx)
}

func (r *Route) Close() error {
	var result error
	r.closeOnce.Do(func() {
		r.mu.Lock()
		r.closed = true
		if r.certificateTimer != nil {
			r.certificateTimer.Stop()
			r.certificateTimer = nil
		}
		started := r.started
		r.mu.Unlock()
		result = errors.Join(r.http.Close(), r.queue.Close())
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
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(10 * time.Second))
	header, replay, err := proxyproto.Decode(connection)
	if err != nil {
		return
	}
	metadata := &metadataConn{Conn: &routeReaderConn{Conn: connection, reader: replay}, header: header}
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
	if secured.ConnectionState().NegotiatedProtocol == acme.ALPNProto {
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

func (routeAddress) Network() string  { return "tnl" }
func (a routeAddress) String() string { return string(a) }

type routeReaderConn struct {
	net.Conn
	reader io.Reader
}

func (c *routeReaderConn) Read(destination []byte) (int, error) { return c.reader.Read(destination) }

type metadataConn struct {
	net.Conn
	header proxyproto.Header
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

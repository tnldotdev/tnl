package publisher

import (
	"context"
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

	"github.com/tnldotdev/tnl/internal/certificateidentity"
	"github.com/tnldotdev/tnl/internal/diagnostic"
	"github.com/tnldotdev/tnl/internal/localproxy"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/proxyproto"
	"github.com/tnldotdev/tnl/internal/tlschallenge"
	"github.com/tnldotdev/tnl/internal/tunnel"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
	"golang.org/x/crypto/acme"
)

// PublicURLServerConfig configures publisher TLS termination and local HTTP forwarding.
type PublicURLServerConfig struct {
	Hostname        string
	Target          string
	RequestLimit    int // zero selects localproxy.DefaultRequestLimit.
	OnTargetFailure func()
	Certificate     tls.Certificate
	CertificatePlan controlv1.CertificatePlan
}

type PublicURLServer struct {
	hostname           string
	certificatePlan    controlv1.CertificatePlan
	tls                *tls.Config
	certificate        atomic.Pointer[tls.Certificate]
	certificateTimer   *time.Timer
	certificateExpired chan struct{}
	challenges         tlschallenge.TLSALPNChallenges
	queue              *publicURLListener
	http               *http.Server
	mu                 sync.Mutex
	started            bool
	closed             bool
	draining           bool
	streams            map[net.Conn]struct{}
	handlers           sync.WaitGroup
	httpDone           chan error
	closeOnce          sync.Once
	closeErr           error

	// certificate transactions retain challenge identity across lost control responses.
	challengeIssuanceID string
	challengeID         string
}

type denialContextKey struct{}

// NewPublicURLServer creates a public URL server served by publisher connections.
func NewPublicURLServer(config PublicURLServerConfig) (*PublicURLServer, error) {
	hostname, err := naming.CanonicalizeHostname(config.Hostname)
	if err != nil || hostname != config.Hostname {
		return nil, errors.New("publisher: public URL hostname must be canonical")
	}
	if config.CertificatePlan.Identifiers != nil || config.CertificatePlan.CacheKey != "" || config.CertificatePlan.Scope != "" || config.CertificatePlan.ChallengeMethod != "" {
		config.CertificatePlan, err = certificateidentity.CanonicalPlan(config.CertificatePlan)
		if err != nil || !certificateidentity.Covers(config.CertificatePlan.Identifiers, hostname) {
			return nil, errors.New("publisher: certificate plan does not cover public URL")
		}
	}
	handler, err := localproxy.New(config.Target, hostname, config.RequestLimit, config.OnTargetFailure)
	if err != nil {
		return nil, err
	}
	queue := newRouteListener()
	route := &PublicURLServer{
		hostname:        hostname,
		certificatePlan: config.CertificatePlan,
		queue:           queue,
		tls: &tls.Config{
			MinVersion:             tls.VersionTLS12,
			NextProtos:             []string{"h2", "http/1.1", acme.ALPNProto},
			SessionTicketsDisabled: true,
		},
		http: &http.Server{
			Handler: http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
				if request.Context().Value(denialContextKey{}) == true {
					diagnostic.WriteHTTP(response, request, diagnostic.IPPolicyDenied)
					return
				}
				handler.ServeHTTP(response, request)
			}),
			ConnContext: func(ctx context.Context, connection net.Conn) context.Context {
				if secured, ok := connection.(*tls.Conn); ok {
					if tracked, ok := secured.NetConn().(*doneConn); ok {
						if metadata, ok := tracked.Conn.(*metadataConn); ok {
							if metadata.denied {
								return context.WithValue(ctx, denialContextKey{}, true)
							}
							return ctx
						}
					}
				}
				// an unrecognized connection must never bypass visitor policy.
				return context.WithValue(ctx, denialContextKey{}, true)
			},
			ReadHeaderTimeout: 10 * time.Second,
			// bound incomplete bodies with a real read deadline. for HTTP/2,
			// net/http enforces this independently on each request stream.
			ReadTimeout:    30 * time.Second,
			IdleTimeout:    2 * time.Minute,
			MaxHeaderBytes: 64 << 10,
			ErrorLog:       log.New(io.Discard, "", 0),
		},
		httpDone:           make(chan error, 1),
		certificateExpired: make(chan struct{}),
		streams:            make(map[net.Conn]struct{}),
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

func (r *PublicURLServer) InstallChallenge(challenge tlschallenge.TLSALPNChallenge) error {
	if challenge.Hostname != r.hostname {
		return errors.New("publisher: TLS-ALPN challenge hostname does not match public URL")
	}
	return r.challenges.Install(challenge)
}

func (r *PublicURLServer) RemoveChallenge(id string) bool { return r.challenges.Remove(id) }

func (r *PublicURLServer) InstallCertificate(certificate tls.Certificate) error {
	copy := certificate
	if len(copy.Certificate) == 0 || copy.PrivateKey == nil {
		return errors.New("publisher: application certificate and private key are required")
	}
	var err error
	if len(r.certificatePlan.Identifiers) != 0 {
		copy.Leaf, err = certificateidentity.ValidateCertificate(copy, r.hostname, r.certificatePlan.Identifiers)
	} else {
		copy.Leaf, err = x509.ParseCertificate(copy.Certificate[0])
		if err == nil {
			err = copy.Leaf.VerifyHostname(r.hostname)
		}
	}
	if err != nil {
		return fmt.Errorf("publisher: invalid application certificate: %w", err)
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

func (r *PublicURLServer) certificateExpiration() <-chan struct{} { return r.certificateExpired }

func (r *PublicURLServer) withValidCertificate(call func() error) error {
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

func (r *PublicURLServer) expireCertificateLocked(certificate *tls.Certificate) {
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

func (r *PublicURLServer) getCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	if hello == nil {
		return nil, errors.New("publisher: TLS SNI does not match public URL")
	}
	hostname, err := naming.CanonicalizeHostname(hello.ServerName)
	if err != nil || hostname != r.hostname {
		return nil, errors.New("publisher: TLS SNI does not match public URL")
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
func (r *PublicURLServer) Start() error {
	return r.start()
}

func (r *PublicURLServer) start() error {
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return net.ErrClosed
	}
	if r.started {
		r.mu.Unlock()
		return errors.New("publisher: public URL already started")
	}
	r.started = true
	r.mu.Unlock()
	r.startHTTP()
	return nil
}

// ServePublisherConnection accepts visitor streams for one exact publisher
// connection. on exit it closes the session to stop pending header reads;
// callers may also close it to interrupt active streams.
func (r *PublicURLServer) ServePublisherConnection(
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
	// bound header parsing while letting a slow or invalid stream coexist with
	// healthy streams on the same publisher connection.
	const headerReaders = 4
	acceptCtx, cancel := context.WithCancel(ctx)
	var readers sync.WaitGroup
	defer func() {
		cancel()
		_ = session.Close()
		readers.Wait()
	}()
	results := make(chan error, headerReaders)
	for range headerReaders {
		readers.Go(func() {
			for {
				incoming, err := session.AcceptVisitorStream(acceptCtx)
				if err != nil {
					var headerErr *tunnel.StreamHeaderError
					if errors.As(err, &headerErr) {
						continue
					}
					results <- err
					return
				}
				if acceptCtx.Err() != nil {
					_ = incoming.Stream.Close()
					return
				}
				if err := r.acceptVisitor(incoming, ref); err != nil {
					results <- err
					return
				}
			}
		})
	}
	select {
	case <-ctx.Done():
		return nil
	case err := <-results:
		if ctx.Err() != nil {
			return nil
		}
		return err
	}
}

func (r *PublicURLServer) acceptVisitor(incoming *tunnel.IncomingVisitorStream, ref tunnelv1.PublisherConnectionRef) error {
	code := r.validateIncomingPublicURL(incoming.Header, ref)
	r.mu.Lock()
	if r.closed || r.draining {
		code = tunnelv1.Unavailable
	}
	if code != "" {
		r.mu.Unlock()
		_ = incoming.Reject(code)
		return nil
	}
	r.streams[incoming.Stream] = struct{}{}
	r.handlers.Add(1)
	r.mu.Unlock()
	if err := incoming.Accept(); err != nil {
		r.mu.Lock()
		delete(r.streams, incoming.Stream)
		r.mu.Unlock()
		r.handlers.Done()
		return err
	}
	go func() {
		defer r.handlers.Done()
		defer func() {
			r.mu.Lock()
			delete(r.streams, incoming.Stream)
			r.mu.Unlock()
		}()
		r.handleVisitor(incoming.Stream, incoming.Header.IPPolicyDenied)
	}()
	return nil
}

func (r *PublicURLServer) validateIncomingPublicURL(
	header tunnelv1.VisitorStreamHeader,
	ref tunnelv1.PublisherConnectionRef,
) tunnelv1.ErrorCode {
	if header.PublicURLID != ref.PublicURLID || header.PublishRunID != ref.PublishRunID ||
		header.PublishRunNumber != ref.PublishRunNumber {
		return tunnelv1.StalePublishRunNumber
	}
	if header.PublisherConnectionID != ref.PublisherConnectionID ||
		header.ConnectionAssignmentRevision != ref.ConnectionAssignmentRevision {
		return tunnelv1.StaleConnectionAssignment
	}
	return ""
}

func (r *PublicURLServer) Drain(ctx context.Context) error {
	r.stopAdmissions()
	return r.http.Shutdown(ctx)
}

func (r *PublicURLServer) stopAdmissions() {
	r.mu.Lock()
	r.draining = true
	r.mu.Unlock()
	r.http.SetKeepAlivesEnabled(false)
}

func (r *PublicURLServer) Close() error {
	r.closeOnce.Do(func() {
		r.mu.Lock()
		r.closed = true
		if r.certificateTimer != nil {
			r.certificateTimer.Stop()
			r.certificateTimer = nil
		}
		started := r.started
		streams := make([]net.Conn, 0, len(r.streams))
		for stream := range r.streams {
			streams = append(streams, stream)
		}
		r.mu.Unlock()
		result := errors.Join(r.http.Close(), r.queue.Close())
		for _, stream := range streams {
			_ = stream.Close()
		}
		r.handlers.Wait()
		if started {
			result = errors.Join(result, <-r.httpDone)
		}
		r.closeErr = result
	})
	return r.closeErr
}

func (r *PublicURLServer) startHTTP() {
	go func() {
		err := r.http.Serve(r.queue)
		if errors.Is(err, http.ErrServerClosed) || errors.Is(err, net.ErrClosed) {
			err = nil
		}
		r.httpDone <- err
		close(r.httpDone)
	}()
}

func (r *PublicURLServer) handle(connection net.Conn) {
	r.handleVisitor(connection, false)
}

func (r *PublicURLServer) handleVisitor(connection net.Conn, denied bool) {
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(10 * time.Second))
	header, replay, err := proxyproto.Decode(connection)
	if err != nil {
		return
	}
	metadata := &metadataConn{Conn: &publicURLReaderConn{Conn: connection, reader: replay}, header: header, denied: denied}
	tracked := newDoneConn(metadata)
	secured := tls.Server(tracked, r.tls)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	err = secured.HandshakeContext(ctx)
	cancel()
	if err != nil {
		_ = secured.Close()
		return
	}
	if denied {
		_ = secured.SetDeadline(time.Now().Add(5 * time.Second))
	} else {
		_ = secured.SetDeadline(time.Time{})
	}
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

type publicURLListener struct {
	connections chan net.Conn
	closed      chan struct{}
	mu          sync.Mutex
	isClosed    bool
	once        sync.Once
}

func newRouteListener() *publicURLListener {
	return &publicURLListener{connections: make(chan net.Conn, 64), closed: make(chan struct{})}
}

func (l *publicURLListener) Accept() (net.Conn, error) {
	select {
	case connection := <-l.connections:
		return connection, nil
	case <-l.closed:
		return nil, net.ErrClosed
	}
}

func (l *publicURLListener) Close() error {
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

func (*publicURLListener) Addr() net.Addr { return publicURLAddress("tnl-route") }

func (l *publicURLListener) enqueue(connection net.Conn) bool {
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

type publicURLAddress string

func (publicURLAddress) Network() string  { return "tnl" }
func (a publicURLAddress) String() string { return string(a) }

type publicURLReaderConn struct {
	net.Conn
	reader io.Reader
}

func (c *publicURLReaderConn) Read(destination []byte) (int, error) {
	return c.reader.Read(destination)
}

type metadataConn struct {
	net.Conn
	header proxyproto.Header
	denied bool
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

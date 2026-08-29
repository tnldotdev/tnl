package publication

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
	"time"

	"github.com/0xcadams/tnl/internal/localproxy"
	"github.com/0xcadams/tnl/internal/naming"
	"github.com/0xcadams/tnl/internal/proxyproto"
	"github.com/0xcadams/tnl/internal/tailtransport"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
)

type RouteConfig struct {
	Hostname      string
	Target        string
	Certificate   tls.Certificate
	AllowedClient key.NodePublic
	RelayProfile  string
	Profiles      map[string]*tailcfg.DERPRegion
	Logf          logger.Logf
}

type Route struct {
	hostname string
	tls      *tls.Config
	queue    *routeListener
	http     *http.Server
	tailcat  *tailtransport.Server

	mu        sync.Mutex
	started   bool
	closed    bool
	httpDone  chan error
	closeOnce sync.Once
}

func NewRoute(config RouteConfig) (*Route, error) {
	hostname, err := naming.CanonicalizeHostname(config.Hostname)
	if err != nil || hostname != config.Hostname {
		return nil, errors.New("agent: route hostname must be canonical")
	}
	if err := validateCertificate(config.Certificate, hostname); err != nil {
		return nil, err
	}
	handler, err := localproxy.New(config.Target, hostname)
	if err != nil {
		return nil, err
	}
	queue := newRouteListener()
	route := &Route{
		hostname: hostname,
		queue:    queue,
		tls: &tls.Config{
			MinVersion:             tls.VersionTLS12,
			NextProtos:             []string{"http/1.1"},
			SessionTicketsDisabled: true,
			GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
				if hello == nil || hello.ServerName != hostname {
					return nil, errors.New("agent: TLS SNI does not match route")
				}
				return &config.Certificate, nil
			},
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
	tailcat, err := tailtransport.NewServer(tailtransport.ServerConfig{
		AllowedClient: config.AllowedClient,
		RelayProfile:  config.RelayProfile,
		Profiles:      config.Profiles,
		Handler:       route.handle,
		Logf:          config.Logf,
	})
	if err != nil {
		return nil, err
	}
	route.tailcat = tailcat
	return route, nil
}

func (r *Route) Start(ctx context.Context) (tailtransport.Endpoint, error) {
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return tailtransport.Endpoint{}, net.ErrClosed
	}
	if r.started {
		r.mu.Unlock()
		return tailtransport.Endpoint{}, errors.New("agent: route already started")
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
	if !r.queue.enqueue(secured) {
		_ = secured.Close()
		return
	}
	<-tracked.done
}

func validateCertificate(certificate tls.Certificate, hostname string) error {
	if len(certificate.Certificate) == 0 || certificate.PrivateKey == nil {
		return errors.New("agent: application certificate and private key are required")
	}
	leaf := certificate.Leaf
	if leaf == nil {
		var err error
		leaf, err = x509.ParseCertificate(certificate.Certificate[0])
		if err != nil {
			return fmt.Errorf("agent: parse application certificate: %w", err)
		}
	}
	if err := leaf.VerifyHostname(hostname); err != nil {
		return fmt.Errorf("agent: application certificate does not match route: %w", err)
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

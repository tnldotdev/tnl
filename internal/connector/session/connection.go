package session

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"sync"
	"time"

	connectorstream "github.com/tnldotdev/tnl/internal/connector/stream"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

const MaxStreams = 64

// Connection owns a prepared peer session without a local TCP listener. the
// native engine retains its signing, authority renewal and joined retirement.
type Connection struct {
	session    preparedSession
	metadata   controlv1.ServiceSummary
	trust      *tls.Config
	ctx        context.Context
	cancel     context.CancelFunc
	mu         sync.Mutex
	closed     bool
	streams    map[*Conn]struct{}
	work       sync.WaitGroup
	closeOnce  sync.Once
	closeErr   error
	http       *http.Transport
	stopParent func() bool
	parent     context.Context
}

type preparedSession interface {
	Context() context.Context
	Forward(context.Context, net.Conn) error
	Close() error
}

func (d *Deployment) Connect(lifetime, setup context.Context, name string, config connectorstream.Config) (_ *Connection, result error) {
	setup, finish := context.WithTimeout(setup, 30*time.Second)
	defer finish()
	service, err := d.SelectService(setup, name)
	if err != nil {
		return nil, err
	}
	control, err := d.ControlFor(name, service.Id)
	if err != nil {
		return nil, err
	}
	config.Control, config.ServiceID, config.Protocol = control, service.Id, string(service.Protocol)
	config.Endpoint, config.TrustRevision = service.Endpoint, service.TrustRevision
	config.MaxConnections = MaxStreams
	// the retained session must outlive each stream's abort and terminal join.
	// parent cancellation enters Connection.Close instead of closing carriers.
	ctx, cancel := context.WithCancel(context.WithoutCancel(lifetime))
	setup, cancelSetup := context.WithCancelCause(setup)
	setupDone := make(chan struct{})
	stopLifetime := context.AfterFunc(lifetime, func() { defer close(setupDone); cancelSetup(context.Cause(lifetime)) })
	session, err := connectorstream.Prepare(ctx, setup, config)
	if !stopLifetime() {
		<-setupDone
	}
	cancelSetup(context.Canceled)
	if err != nil {
		cancel()
		return nil, err
	}
	connection := newConnection(ctx, cancel, session, service, config.ServiceTLS)
	connection.followLifetime(lifetime)
	return connection, nil
}

func (c *Connection) followLifetime(lifetime context.Context) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.parent = lifetime
	c.stopParent = context.AfterFunc(lifetime, func() { _ = c.Close() })
}

func newConnection(ctx context.Context, cancel context.CancelFunc, session preparedSession, service controlv1.ServiceSummary, trust *tls.Config) *Connection {
	c := &Connection{session: session, metadata: service, trust: trust.Clone(), ctx: ctx, cancel: cancel, streams: make(map[*Conn]struct{})}
	c.trust.ServerName = service.Endpoint.Hostname
	c.http = &http.Transport{
		// js/wasm net/http must use the Go transport rather than Fetch for
		// service requests; only the control client uses runtime Fetch.
		DialContext: func(context.Context, string, string) (net.Conn, error) {
			return nil, errors.New("connector HTTP requires HTTPS")
		},
		DialTLSContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			raw, err := c.Open(ctx)
			if err != nil {
				return nil, err
			}
			if err := raw.StartTLS(ctx, nil); err != nil {
				return nil, errors.Join(err, raw.Close())
			}
			return raw, nil
		},
		// net/http may replay a received request after a pooled connection
		// closes without a response. keep the peer session, not HTTP streams.
		DisableKeepAlives:      true,
		ForceAttemptHTTP2:      false,
		MaxConnsPerHost:        MaxStreams,
		MaxIdleConns:           MaxStreams,
		MaxIdleConnsPerHost:    MaxStreams,
		IdleConnTimeout:        30 * time.Second,
		ResponseHeaderTimeout:  30 * time.Second,
		MaxResponseHeaderBytes: 64 << 10,
	}
	return c
}

func (c *Connection) Metadata() controlv1.ServiceSummary {
	metadata := c.metadata
	if metadata.Endpoint != nil {
		endpoint := *metadata.Endpoint
		metadata.Endpoint = &endpoint
	}
	return metadata
}
func (c *Connection) Context() context.Context { return c.session.Context() }

// Fetch pins every request to this service's verified origin and never follows
// redirects. its response body remains owned by the caller until closed.
func (c *Connection) Fetch(request *http.Request) (*http.Response, error) {
	if c.metadata.Protocol != "http" && c.metadata.Protocol != "kubernetes" {
		return nil, errors.New("connector fetch requires HTTP or Kubernetes")
	}
	base := &url.URL{Scheme: "https", Host: c.metadata.Endpoint.Hostname}
	resolved := base.ResolveReference(request.URL)
	if resolved.Scheme != "https" || resolved.Host != base.Host || resolved.User != nil || resolved.Fragment != "" || request.Host != "" && request.Host != base.Host {
		return nil, errors.New("connector fetch URL must select this service")
	}
	request = request.Clone(request.Context())
	request.URL, request.Host = resolved, base.Host
	return c.http.RoundTrip(request)
}

type arrivalConn struct {
	*pipeConn
	ready chan struct{}
	once  sync.Once
}

func (c *arrivalConn) arrived()                    { c.once.Do(func() { close(c.ready) }) }
func (c *arrivalConn) Read(p []byte) (int, error)  { c.arrived(); return c.pipeConn.Read(p) }
func (c *arrivalConn) Write(p []byte) (int, error) { c.arrived(); return c.pipeConn.Write(p) }

// Open waits for the existing connector opening to be admitted before exposing
// bytes. at most MaxStreams forwarding workers belong to this connection.
func (c *Connection) Open(ctx context.Context) (*Conn, error) {
	c.mu.Lock()
	if c.closed || c.ctx.Err() != nil || len(c.streams) >= MaxStreams {
		c.mu.Unlock()
		return nil, net.ErrClosed
	}
	app, local := newPipe()
	life, cancel := context.WithCancel(ctx)
	s := &Conn{Conn: app, owner: c, ctx: life, cancel: cancel, raw: app, done: make(chan struct{})}
	if c.metadata.Protocol == "tcp" {
		s.secure = true // the existing prepared connector already completed TLS.
	}
	c.streams[s] = struct{}{}
	c.work.Add(1)
	c.mu.Unlock()
	arrival := &arrivalConn{pipeConn: local, ready: make(chan struct{})}
	go func() {
		defer c.work.Done()
		s.forwardErr = c.session.Forward(life, arrival)
		_ = local.Close()
		close(s.done)
	}()
	select {
	case <-arrival.ready:
		return s, nil
	case <-s.done:
		return nil, errors.Join(errors.New("connector stream admission failed"), s.Close(), s.forwardErr)
	case <-ctx.Done():
		return nil, errors.Join(context.Cause(ctx), s.Close())
	}
}

func (c *Connection) Close() error {
	c.closeOnce.Do(func() {
		c.mu.Lock()
		c.closed = true
		streams := make([]*Conn, 0, len(c.streams))
		for stream := range c.streams {
			streams = append(streams, stream)
		}
		stopParent := c.stopParent
		c.mu.Unlock()
		if stopParent != nil {
			stopParent()
		}
		var joins sync.WaitGroup
		results := make([]error, len(streams))
		for index, stream := range streams {
			joins.Go(func() { results[index] = stream.Close() })
		}
		joins.Wait()
		c.work.Wait()
		c.http.CloseIdleConnections()
		c.cancel()
		c.closeErr = errors.Join(append(results, c.session.Close())...)
		if c.parent != nil {
			if cause := context.Cause(c.parent); cause != nil && cause != context.Canceled {
				c.closeErr = errors.Join(c.closeErr, cause)
			}
		}
	})
	return c.closeErr
}

// Conn retains the admitted stream and joins its forwarding and protocol work.
// protocol TLS negotiation remains in Go, even for JavaScript driver adapters.
type Conn struct {
	net.Conn
	owner                                     *Connection
	ctx                                       context.Context
	cancel                                    context.CancelFunc
	raw                                       *pipeConn
	done                                      chan struct{}
	forwardErr                                error
	readMu, writeMu                           sync.Mutex
	mu                                        sync.Mutex
	closed, secure, upgrading, mysqlRequested bool
	mysqlRequest                              []byte
	once                                      sync.Once
	closeErr                                  error
}

func (s *Conn) Read(p []byte) (int, error) {
	s.readMu.Lock()
	defer s.readMu.Unlock()
	s.mu.Lock()
	conn, secure, closed, requested := s.Conn, s.secure, s.closed, s.mysqlRequested
	s.mu.Unlock()
	if closed {
		return 0, net.ErrClosed
	}
	if !secure && s.owner.metadata.Protocol != "mysql" {
		return 0, errors.New("connector stream requires TLS")
	}
	if !secure && requested {
		return 0, errors.New("MySQL SSLRequest requires TLS before further reads")
	}
	return conn.Read(p)
}

func (s *Conn) Write(p []byte) (int, error) {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	s.mu.Lock()
	conn, secure, closed := s.Conn, s.secure, s.closed
	s.mu.Unlock()
	if closed {
		return 0, net.ErrClosed
	}
	if !secure {
		s.mu.Lock()
		allowed := s.owner.metadata.Protocol == "mysql" && !s.mysqlRequested && !s.upgrading && len(s.mysqlRequest)+len(p) <= 36
		var request []byte
		if allowed {
			request = make([]byte, 0, 36)
			request = append(request, s.mysqlRequest...)
			request = append(request, p...)
			header := [...]byte{32, 0, 0, 1}
			for i := 0; i < min(len(request), len(header)); i++ {
				if request[i] != header[i] {
					allowed = false
				}
			}
			if len(request) == 36 && !validMySQLSSLRequest(request) {
				allowed = false
			}
		}
		if allowed {
			s.mysqlRequest = request
			s.mysqlRequested = len(request) == 36
		}
		complete := s.mysqlRequested
		s.mu.Unlock()
		if !allowed {
			return 0, errors.New("connector stream requires TLS")
		}
		if !complete {
			return len(p), nil
		}
		for len(request) > 0 {
			n, err := conn.Write(request)
			if err != nil {
				_ = s.raw.Close()
				return 0, err
			}
			if n == 0 {
				_ = s.raw.Close()
				return 0, io.ErrNoProgress
			}
			request = request[n:]
		}
		return len(p), nil
	}
	return conn.Write(p)
}

func (s *Conn) CloseWrite() error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	s.mu.Lock()
	conn, closed := s.Conn, s.closed
	s.mu.Unlock()
	if closed {
		return net.ErrClosed
	}
	if half, ok := conn.(interface{ CloseWrite() error }); ok {
		return half.CloseWrite()
	}
	return errors.ErrUnsupported
}

func (s *Conn) Close() error {
	s.once.Do(func() {
		s.mu.Lock()
		s.closed = true
		s.mu.Unlock()
		// the forwarding operation owns the selected-stream reset and local
		// abort. do not race it with an unowned pipe close or TLS close-notify.
		s.cancel()
		<-s.done
		s.closeErr = errors.Join(s.raw.Close(), s.forwardErr)
		s.readMu.Lock()
		s.writeMu.Lock()
		s.writeMu.Unlock()
		s.readMu.Unlock()
		s.owner.mu.Lock()
		delete(s.owner.streams, s)
		s.owner.mu.Unlock()
	})
	return s.closeErr
}

// a pipe half-close marks only the peer's read side as EOF. it leaves the
// opposite direction alive for server-first protocols and response completion.
type pipeConn struct {
	net.Conn
	readEOF  chan struct{}
	peer     *pipeConn
	eofOnce  sync.Once
	state    *pipeState
	abortErr error
}

type pipeState struct {
	sync.Mutex
	closed bool
}

func newPipe() (*pipeConn, *pipeConn) {
	left, right := net.Pipe()
	state := &pipeState{}
	a, b := &pipeConn{Conn: left, readEOF: make(chan struct{}), state: state}, &pipeConn{Conn: right, readEOF: make(chan struct{}), state: state}
	a.peer, b.peer = b, a
	return a, b
}
func (c *pipeConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n == 0 && errors.Is(err, os.ErrDeadlineExceeded) {
		select {
		case <-c.readEOF:
			return 0, io.EOF
		default:
		}
	}
	return n, c.result(err)
}
func (c *pipeConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	return n, c.result(err)
}

func (c *pipeConn) result(err error) error {
	c.state.Lock()
	defer c.state.Unlock()
	if err == io.ErrClosedPipe && c.abortErr != nil {
		return c.abortErr
	}
	return err
}

func (c *pipeConn) Close() error {
	c.state.Lock()
	c.state.closed = true
	c.state.Unlock()
	return c.Conn.Close()
}
func (c *pipeConn) CloseWrite() error {
	c.peer.eofOnce.Do(func() { close(c.peer.readEOF); _ = c.peer.SetReadDeadline(time.Now()) })
	return nil
}

func (c *pipeConn) Abort(error) error {
	c.state.Lock()
	if !c.state.closed {
		c.abortErr = &net.OpError{Op: "connector pipe abort", Net: "pipe", Err: io.ErrClosedPipe}
		c.state.closed = true
	}
	c.state.Unlock()
	return c.Conn.Close()
}

func (c *pipeConn) OwnsAbortError(err error) bool {
	c.state.Lock()
	defer c.state.Unlock()
	return c.abortErr != nil && err == c.abortErr
}

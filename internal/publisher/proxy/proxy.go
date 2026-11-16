// package proxy forwards one public hostname to local HTTP or HTTPS targets.
package proxy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/tnldotdev/tnl/internal/failure/diagnostic"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/observability"
	targetsyntax "github.com/tnldotdev/tnl/internal/policy/target"
	"github.com/tnldotdev/tnl/internal/transport/httpstream"
)

const maxHeaderFields = 100

const defaultMaxConnsPerHost = 64

// Preflight validates the target and verifies that it accepts a connection.
func Preflight(ctx context.Context, target string) error {
	return PreflightWithOptions(ctx, target, TargetOptions{})
}

// TargetOptions configures trust for one target, independently of control and relays.
type TargetOptions struct {
	RootCAs    *x509.CertPool
	ServerName string
}

// transport owns a captured target's requests, connections, and joined shutdown.
type Transport interface {
	RoundTrip(*http.Request) (*http.Response, error)
	CloseIdleConnections()
	Close() error
}

// LoadTargetRootCAs adds a PEM file to the system roots used for one HTTPS target.
func LoadTargetRootCAs(path string) (*x509.CertPool, error) {
	roots, err := x509.SystemCertPool()
	if err != nil {
		return nil, diagnostic.Wrap(diagnostic.TargetInvalid, fmt.Errorf("read system certificate roots: %w", err))
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, diagnostic.Wrap(diagnostic.TargetInvalid, fmt.Errorf("open target CA file: %w", err))
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, (1<<20)+1))
	if err != nil || len(data) > 1<<20 || !roots.AppendCertsFromPEM(data) {
		return nil, diagnostic.Wrap(diagnostic.TargetInvalid, errors.New("target CA file must contain PEM certificates and be at most 1 MiB"))
	}
	return roots, nil
}

// PreflightWithOptions checks target reachability and HTTPS certificate trust.
func PreflightWithOptions(ctx context.Context, target string, options TargetOptions) (result error) {
	ctx = observability.WithPublisherProtocol(ctx, "http")
	ctx, finish := observability.PublisherOperation(ctx, "target_preflight")
	defer func() { finish(result) }()
	canonicalTarget, err := targetsyntax.NormalizeTarget(target)
	if err != nil {
		return err
	}
	parsed, err := url.Parse(canonicalTarget)
	if err != nil {
		return err
	}
	if parsed.Scheme != "https" && options.ServerName != "" {
		return diagnostic.Wrap(diagnostic.TargetInvalid, errors.New("target TLS server name requires HTTPS"))
	}
	setup, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	connection, err := observability.DialTarget(setup, "tcp", parsed.Host)
	if err != nil {
		return diagnostic.Wrap(diagnostic.TargetUnavailable, fmt.Errorf("localproxy: connect to target: %w", err))
	}
	if parsed.Scheme == "https" {
		name := options.ServerName
		if name == "" {
			name = parsed.Hostname()
		}
		secured := tls.Client(connection, &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: options.RootCAs, ServerName: name})
		tlsCtx, finish := observability.PublisherOperation(setup, "target_tls")
		err = secured.HandshakeContext(tlsCtx)
		observability.PublisherTLS(tlsCtx, "target", secured.ConnectionState(), err)
		finish(err)
		if err != nil {
			_ = connection.Close()
			return diagnostic.Wrap(diagnostic.TargetUnavailable, fmt.Errorf("localproxy: connect to target: %w", err))
		}
		connection = secured
	}
	if err := connection.Close(); err != nil {
		return diagnostic.Wrap(diagnostic.TargetUnavailable, fmt.Errorf("localproxy: close target connection: %w", err))
	}
	return nil
}

// WaitForTarget waits until a valid target accepts a connection.
func WaitForTarget(ctx context.Context, target string) error {
	return waitForTarget(ctx, target, Preflight)
}

func waitForTarget(ctx context.Context, target string, preflight func(context.Context, string) error) error {
	canonicalTarget, err := targetsyntax.NormalizeTarget(target)
	if err != nil {
		return err
	}
	var lastErr error
	for {
		lastErr = preflight(ctx, canonicalTarget)
		if lastErr == nil {
			return nil
		}
		timer := time.NewTimer(100 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return fmt.Errorf("localproxy: wait for target: %w", errors.Join(ctx.Err(), lastErr))
		case <-timer.C:
		}
	}
}

// Config selects targets, target trust, response hooks, and transport sizing.
// the publisher owns application admission for base, mounted, and inline handlers.
type Config struct {
	Target        string
	Hostname      string
	Mounts        []Mount
	Hooks         httpstream.ResponseHooks
	TargetOptions TargetOptions
	// transport receives one normalized target and its captured trust. nil keeps
	// the pooled transport used by standalone callers. base identifies the base
	// slot, including resolved targets; mounts remain independent at any address.
	Transport func(target *url.URL, options TargetOptions, base bool) (Transport, error)
	// ResolveTarget selects the base target before each request. its immutable
	// identity retires pooled connections even when the address stays the same.
	// nil uses Target; mounted paths retain their own target selection.
	ResolveTarget func(*http.Request) (address, identity string, err error)
	// MaxConnsPerHost sizes each target's transport, not application admission.
	// zero uses 64; excess transport work waits for a connection or cancellation.
	MaxConnsPerHost int
	OnTargetFailure func()
}

// proxy owns captured target transports. close fences new handlers and creation,
// closes every remaining owner, and joins handlers, factories, and retirement.
type Proxy struct {
	handler    http.Handler
	hostname   string
	mu         sync.Mutex
	transports map[*targetProxy]struct{}
	work       sync.WaitGroup
	closed     bool
	closeDone  chan struct{}
	closeErr   error
}

func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p.serve(w, r, false)
}

// ServeAdmittedHTTP keeps request-shape checks without rebinding the host or SNI.
// the service owner must already have authorized and bound this visitor.
func (p *Proxy) ServeAdmittedHTTP(w http.ResponseWriter, r *http.Request) {
	p.serve(w, r, true)
}

func (p *Proxy) serve(w http.ResponseWriter, r *http.Request, admitted bool) {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		diagnostic.WriteHTTP(w, r, diagnostic.TargetUnavailable, "")
		return
	}
	p.work.Add(1)
	p.mu.Unlock()
	defer p.work.Done()
	var code diagnostic.Code
	if admitted {
		code = validateRequestShape(r)
	} else {
		code = ValidateRequest(r, p.hostname)
	}
	if code != "" {
		diagnostic.WriteHTTP(w, r, code, "")
		return
	}
	p.handler.ServeHTTP(w, r)
}

func (p *Proxy) Close() error {
	p.mu.Lock()
	if p.closed {
		done := p.closeDone
		p.mu.Unlock()
		<-done
		p.mu.Lock()
		err := p.closeErr
		p.mu.Unlock()
		return err
	}
	p.closed = true
	var targets []*targetProxy
	for target := range p.transports {
		if p.beginCloseLocked(target) {
			targets = append(targets, target)
		}
	}
	p.mu.Unlock()
	for _, target := range targets {
		go p.closeTarget(target)
	}
	p.work.Wait()
	p.mu.Lock()
	defer p.mu.Unlock()
	close(p.closeDone)
	return p.closeErr
}

type targetProxy struct {
	*httputil.ReverseProxy
	transport Transport
	refs      int
	retired   bool
	closing   bool
}

func (p *Proxy) beginCloseLocked(target *targetProxy) bool {
	if target.closing {
		return false
	}
	target.closing = true
	p.work.Add(1)
	return true
}

func (p *Proxy) closeTarget(target *targetProxy) {
	err := target.transport.Close()
	p.mu.Lock()
	p.closeErr = errors.Join(p.closeErr, err)
	delete(p.transports, target)
	p.mu.Unlock()
	p.work.Done()
}

func (p *Proxy) retire(target *targetProxy) {
	// closing idle connections must not interrupt a captured request or upgrade.
	// retain the owner until its last captured handler and Close have joined.
	target.transport.CloseIdleConnections()
	p.mu.Lock()
	target.retired = true
	close := target.refs == 0 && p.beginCloseLocked(target)
	p.mu.Unlock()
	if close {
		go p.closeTarget(target)
	}
}

func (p *Proxy) release(target *targetProxy) {
	p.mu.Lock()
	target.refs--
	close := target.refs == 0 && target.retired && p.beginCloseLocked(target)
	p.mu.Unlock()
	if close {
		go p.closeTarget(target)
	}
}

// targetSlot shares capture and retirement mechanics for base and mounted targets.
// its selection lock covers acquisition, so replacement cannot retire a target
// between capture and the request's first use.
type targetSlot struct {
	owner             *Proxy
	mu                sync.Mutex
	current           *targetProxy
	address, identity string
	resolve           func(*http.Request) (string, string, error)
	create            func(string) (*targetProxy, error)
}

func (s *targetSlot) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var address, identity string
	if s.resolve != nil {
		var err error
		address, identity, err = s.resolve(r)
		if err != nil || address == "" || identity == "" {
			diagnostic.WriteHTTP(w, r, diagnostic.TargetUnavailable, "")
			return
		}
		address, err = targetsyntax.NormalizeTarget(address)
		if err != nil {
			diagnostic.WriteHTTP(w, r, diagnostic.TargetUnavailable, "")
			return
		}
	}
	s.mu.Lock()
	selected := s.current
	var previous *targetProxy
	if s.resolve != nil && (s.address != address || s.identity != identity) {
		var err error
		selected, err = s.create(address)
		if err != nil {
			s.mu.Unlock()
			diagnostic.WriteHTTP(w, r, diagnostic.TargetUnavailable, "")
			return
		}
		previous = s.current
	}
	s.owner.mu.Lock()
	if s.owner.closed {
		s.owner.mu.Unlock()
		s.mu.Unlock()
		diagnostic.WriteHTTP(w, r, diagnostic.TargetUnavailable, "")
		return
	}
	selected.refs++
	s.current = selected
	s.address, s.identity = address, identity
	s.owner.mu.Unlock()
	s.mu.Unlock()
	defer s.owner.release(selected)
	if previous != nil {
		s.owner.retire(previous)
	}
	httpstream.ServeProxy(selected.ReverseProxy, w, r, func(err error) {
		s.owner.mu.Lock()
		s.owner.closeErr = errors.Join(s.owner.closeErr, err)
		s.owner.mu.Unlock()
	})
}

// New forwards requests already admitted by the publisher.
func New(config Config) (_ *Proxy, result error) {
	if config.MaxConnsPerHost < 0 {
		return nil, errors.New("localproxy: transport connection limit cannot be negative")
	}
	if config.MaxConnsPerHost == 0 {
		config.MaxConnsPerHost = defaultMaxConnsPerHost
	}
	canonical, err := naming.CanonicalizeHostname(config.Hostname)
	if err != nil || canonical != config.Hostname {
		return nil, diagnostic.Wrap(diagnostic.PublicURLInvalid, errors.New("localproxy: hostname must be canonical"))
	}
	owner := &Proxy{hostname: canonical, transports: make(map[*targetProxy]struct{}), closeDone: make(chan struct{})}
	defer func() {
		if result != nil {
			result = errors.Join(result, owner.Close())
		}
	}()
	// validate the declared base even when a resolver will capture each request.
	if _, err := parseTarget(config.Target, config.TargetOptions); err != nil {
		return nil, err
	}
	newSlot := func(target string, options TargetOptions, base bool, resolve func(*http.Request) (string, string, error)) (*targetSlot, error) {
		options = captureTargetOptions(options)
		slot := &targetSlot{owner: owner, resolve: resolve, create: func(target string) (*targetProxy, error) {
			return owner.newReverseProxy(target, config.MaxConnsPerHost, config.Hooks, options, base, config.OnTargetFailure, config.Transport)
		}}
		if resolve == nil {
			current, err := slot.create(target)
			if err != nil {
				return nil, err
			}
			slot.current = current
		}
		return slot, nil
	}
	baseHandler, err := newSlot(config.Target, config.TargetOptions, true, config.ResolveTarget)
	if err != nil {
		return nil, err
	}
	type mountedProxy struct {
		Mount
		proxy http.Handler
	}
	routes := make([]mountedProxy, 0, len(config.Mounts))
	seen := make(map[string]bool, len(config.Mounts))
	for _, mount := range config.Mounts {
		if !targetsyntax.ValidMountPrefix(mount.Prefix) || seen[mount.Prefix] {
			return nil, errors.New("localproxy: mount prefixes must be distinct clean absolute paths outside /__tnl/")
		}
		seen[mount.Prefix] = true
		var proxy http.Handler
		if mount.ResolveTarget != nil {
			proxy, err = newSlot("", mount.Options, false, func(r *http.Request) (string, string, error) {
				return mount.ResolveTarget(r.Context())
			})
		} else {
			proxy, err = newSlot(mount.Target, mount.Options, false, nil)
		}
		if err != nil {
			return nil, fmt.Errorf("localproxy: mount %q: %w", mount.Prefix, err)
		}
		routes = append(routes, mountedProxy{Mount: mount, proxy: proxy})
	}
	slices.SortFunc(routes, func(left, right mountedProxy) int {
		if len(left.Prefix) != len(right.Prefix) {
			return len(right.Prefix) - len(left.Prefix)
		}
		return strings.Compare(left.Prefix, right.Prefix)
	})
	owner.handler = httpstream.Requests(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		escapedPath := request.URL.EscapedPath()
		for _, mount := range routes {
			if !matchesMountPath(escapedPath, mount.Prefix) {
				continue
			}
			if mount.StripPrefix {
				copy := request.Clone(request.Context())
				location := *request.URL
				location.Path = strings.TrimPrefix(location.Path, mount.Prefix)
				if location.Path == "" {
					location.Path = "/"
				}
				if location.RawPath != "" {
					location.RawPath = strings.TrimPrefix(escapedPath, mount.Prefix)
					if location.RawPath == "" {
						location.RawPath = "/"
					}
				}
				copy.URL = &location
				request = copy
			}
			mount.proxy.ServeHTTP(response, request)
			return
		}
		baseHandler.ServeHTTP(response, request)
	}), 0)
	return owner, nil
}

func captureTargetOptions(options TargetOptions) TargetOptions {
	if options.RootCAs != nil {
		options.RootCAs = options.RootCAs.Clone()
	}
	return options
}

type pooledTransport struct{ *http.Transport }

func (t *pooledTransport) Close() error {
	t.CloseIdleConnections()
	return nil
}

func newPooledTransport(targetURL *url.URL, maxConnsPerHost int, options TargetOptions) Transport {
	targetAddress := targetURL.Host
	dialer := &net.Dialer{Timeout: 3 * time.Second, KeepAlive: 30 * time.Second}
	return &pooledTransport{&http.Transport{
		Proxy:               nil,
		DisableCompression:  true,
		ForceAttemptHTTP2:   false,
		TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: options.RootCAs, ServerName: options.ServerName},
		MaxIdleConns:        16,
		MaxIdleConnsPerHost: 16,
		MaxConnsPerHost:     maxConnsPerHost,
		IdleConnTimeout:     90 * time.Second,
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			if network != "tcp" || address != targetAddress {
				return nil, errors.New("localproxy: refused unexpected upstream")
			}
			ctx, finish := observability.PublisherOperation(ctx, "target_connect")
			connection, err := dialer.DialContext(ctx, "tcp", targetAddress)
			finish(err)
			return connection, err
		},
	}}
}

func parseTarget(target string, options TargetOptions) (*url.URL, error) {
	canonicalTarget, err := targetsyntax.NormalizeTarget(target)
	if err != nil {
		return nil, err
	}
	targetURL, err := url.Parse(canonicalTarget)
	if err != nil {
		return nil, err
	}
	if targetURL.Scheme != "https" && options.ServerName != "" {
		return nil, diagnostic.Wrap(diagnostic.TargetInvalid, errors.New("target TLS server name requires HTTPS"))
	}
	return targetURL, nil
}

func (p *Proxy) newReverseProxy(target string, maxConnsPerHost int, hooks httpstream.ResponseHooks, options TargetOptions, base bool, onTargetFailure func(), factory func(*url.URL, TargetOptions, bool) (Transport, error)) (*targetProxy, error) {
	targetURL, err := parseTarget(target, options)
	if err != nil {
		return nil, err
	}
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return nil, net.ErrClosed
	}
	// creation may finish after Close starts. keep it joined until any late
	// transport has also closed; no owner may escape through that race.
	p.work.Add(1)
	p.mu.Unlock()
	defer p.work.Done()
	options = captureTargetOptions(options)
	var transport Transport
	if factory == nil {
		transport = newPooledTransport(targetURL, maxConnsPerHost, options)
	} else {
		captured := *targetURL
		transport, err = factory(&captured, options, base)
	}
	if err != nil {
		if transport != nil {
			cleanup := transport.Close()
			p.mu.Lock()
			p.closeErr = errors.Join(p.closeErr, cleanup)
			p.mu.Unlock()
		}
		return nil, err
	}
	if transport == nil {
		return nil, errors.New("localproxy: target transport factory returned no owner")
	}
	var failing atomic.Bool
	proxy := &httputil.ReverseProxy{
		Transport:     transport,
		FlushInterval: -1,
		Rewrite: func(request *httputil.ProxyRequest) {
			httpstream.ForwardTrailers(request.In, request.Out)
			observability.PublisherHTTPForward(request.Out.Context())
			request.Out = observability.TargetRequest(request.Out)
			host := request.In.Host
			hooks.Rewrite(request)
			// remove client forwarding identity before deriving trusted headers.
			removeForwardingHeaders(request.Out.Header)
			request.SetURL(targetURL)
			request.Out.Host = host
			request.SetXForwarded()
		},
		ErrorHandler: func(response http.ResponseWriter, request *http.Request, targetErr error) {
			observability.PublisherHTTPError(request.Context(), targetErr)
			hooks.ForwardingFailed(request)
			if code, ok := diagnostic.CodeOf(targetErr); ok {
				diagnostic.WriteHTTP(response, request, code, "")
				return
			}
			if failing.CompareAndSwap(false, true) && onTargetFailure != nil {
				onTargetFailure()
			}
			caseID := ""
			if errors.Is(targetErr, syscall.ECONNREFUSED) {
				caseID = "connection-refused"
			} else if errors.Is(targetErr, context.DeadlineExceeded) {
				caseID = "timeout"
			}
			diagnostic.WriteHTTP(response, request, diagnostic.TargetUnavailable, caseID)
		},
		ModifyResponse: func(response *http.Response) error {
			failing.Store(false)
			return hooks.ModifyResponse(response)
		},
	}
	selected := &targetProxy{ReverseProxy: proxy, transport: transport}
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		cleanup := transport.Close()
		p.mu.Lock()
		p.closeErr = errors.Join(p.closeErr, cleanup)
		p.mu.Unlock()
		return nil, errors.Join(net.ErrClosed, cleanup)
	}
	p.transports[selected] = struct{}{}
	p.mu.Unlock()
	return selected, nil
}

// ValidateRequest binds a visitor HTTP request to its public URL hostname and SNI.
func ValidateRequest(request *http.Request, hostname string) diagnostic.Code {
	if code := validateRequestShape(request); code != "" {
		return code
	}
	// bind origin-form authority and TLS SNI to this public URL's hostname.
	authority, err := naming.CanonicalizeAuthority(request.Host)
	if err != nil || request.TLS == nil {
		return diagnostic.RequestRejected
	}
	serverName, err := naming.CanonicalizeHostname(request.TLS.ServerName)
	if err != nil || serverName != hostname {
		return diagnostic.RequestRejected
	}
	if authority != hostname {
		// HTTP/2 clients may reuse a TLS connection for sibling hostnames on
		// the same wildcard certificate. A 421 asks them to retry on a new
		// connection with the requested hostname as SNI.
		if request.ProtoMajor == 2 {
			return diagnostic.RequestMisdirected
		}
		return diagnostic.RequestRejected
	}
	return ""
}

func validateRequestShape(request *http.Request) diagnostic.Code {
	if request.Method == http.MethodConnect || request.URL == nil || request.URL.IsAbs() || request.URL.Host != "" ||
		strings.HasPrefix(request.RequestURI, "http://") || strings.HasPrefix(request.RequestURI, "https://") {
		return diagnostic.RequestRejected
	}
	fields := 0
	for _, values := range request.Header {
		fields += len(values)
		if fields > maxHeaderFields {
			return diagnostic.RequestRejected
		}
	}
	return ""
}

func removeForwardingHeaders(headers http.Header) {
	for name := range headers {
		lower := strings.ToLower(name)
		if lower == "forwarded" || lower == "x-real-ip" || strings.HasPrefix(lower, "x-forwarded-") {
			headers.Del(name)
		}
	}
}

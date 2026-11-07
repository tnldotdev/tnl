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

// readiness probes keep HTML responses streaming and observe headers only.
const ReadinessProbeHeader = "X-Tnl-Readiness-Probe"
const ProxyTokenHeader = "X-Tnl-Proxy-Token"

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

func WaitForTargetWithOptions(ctx context.Context, target string, options TargetOptions) error {
	return waitForTarget(ctx, target, func(ctx context.Context, target string) error {
		return PreflightWithOptions(ctx, target, options)
	})
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

// ResponseHooks separates header observation from body modification. observing
// a response must not disable upstream compression or consume its body.
type ResponseHooks struct {
	ModifyHTML    func(*http.Response) error
	Observe       func(*http.Response) error
	ObserveStatus func(*http.Request, int)
	OnForwarded   func(*http.Request)
}

// Config selects targets, target trust, response hooks, and transport sizing.
// the publisher owns application admission for base, mounted, and inline handlers.
type Config struct {
	Target        string
	Hostname      string
	Mounts        []Mount
	Hooks         ResponseHooks
	TargetOptions TargetOptions
	ProxyToken    string
	// ResolveTarget selects the base target before each request. its immutable
	// identity retires pooled connections even when the address stays the same.
	// nil uses Target; mounted paths retain their own target selection.
	ResolveTarget func(*http.Request) (address, identity string, err error)
	// MaxConnsPerHost sizes each target's transport, not application admission.
	// zero uses 64; excess transport work waits for a connection or cancellation.
	MaxConnsPerHost int
	OnTargetFailure func()
}

// New forwards requests already admitted by the publisher.
func New(config Config) (http.Handler, error) {
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
	base, err := newReverseProxy(config.Target, config.MaxConnsPerHost, config.Hooks, config.TargetOptions, config.ProxyToken, config.OnTargetFailure)
	if err != nil {
		return nil, err
	}
	var baseHandler http.Handler = base
	if config.ResolveTarget != nil {
		var mu sync.Mutex
		var currentAddress, currentIdentity string
		baseHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			address, identity, err := config.ResolveTarget(r)
			if err != nil || address == "" || identity == "" {
				diagnostic.WriteHTTP(w, r, diagnostic.TargetUnavailable)
				return
			}
			canonical, err := targetsyntax.NormalizeTarget(address)
			if err != nil {
				diagnostic.WriteHTTP(w, r, diagnostic.TargetUnavailable)
				return
			}
			mu.Lock()
			if currentAddress != canonical || currentIdentity != identity {
				selected, err := newReverseProxy(canonical, config.MaxConnsPerHost, config.Hooks, config.TargetOptions, config.ProxyToken, config.OnTargetFailure)
				if err != nil {
					mu.Unlock()
					diagnostic.WriteHTTP(w, r, diagnostic.TargetUnavailable)
					return
				}
				if transport, ok := base.Transport.(interface{ CloseIdleConnections() }); ok {
					transport.CloseIdleConnections()
				}
				base, currentAddress, currentIdentity = selected, canonical, identity
			}
			selected := base
			mu.Unlock()
			selected.ServeHTTP(w, r)
		})
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
			var mu sync.Mutex
			var current string
			var upstream *httputil.ReverseProxy
			proxy = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				target := mount.ResolveTarget()
				if target == "" {
					diagnostic.WriteHTTP(w, r, diagnostic.TargetUnavailable)
					return
				}
				mu.Lock()
				if current != target {
					if upstream != nil {
						if transport, ok := upstream.Transport.(interface{ CloseIdleConnections() }); ok {
							transport.CloseIdleConnections()
						}
					}
					var err error
					upstream, err = newReverseProxy(target, config.MaxConnsPerHost, config.Hooks, mount.Options, "", config.OnTargetFailure)
					if err != nil {
						mu.Unlock()
						diagnostic.WriteHTTP(w, r, diagnostic.TargetUnavailable)
						return
					}
					current = target
				}
				selected := upstream
				mu.Unlock()
				selected.ServeHTTP(w, r)
			})
		} else {
			proxy, err = newReverseProxy(mount.Target, config.MaxConnsPerHost, config.Hooks, mount.Options, "", config.OnTargetFailure)
			if err != nil {
				return nil, fmt.Errorf("localproxy: mount %q: %w", mount.Prefix, err)
			}
		}
		routes = append(routes, mountedProxy{Mount: mount, proxy: proxy})
	}
	slices.SortFunc(routes, func(left, right mountedProxy) int {
		if len(left.Prefix) != len(right.Prefix) {
			return len(right.Prefix) - len(left.Prefix)
		}
		return strings.Compare(left.Prefix, right.Prefix)
	})
	return httpstream.Requests(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if code := ValidateRequest(request, config.Hostname); code != "" {
			diagnostic.WriteHTTP(response, request, code)
			return
		}
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
	}), httpstream.RequestBodyTimeout), nil
}

func newReverseProxy(target string, maxConnsPerHost int, hooks ResponseHooks, options TargetOptions, proxyToken string, onTargetFailure func()) (*httputil.ReverseProxy, error) {
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
	targetAddress := targetURL.Host
	dialer := &net.Dialer{Timeout: 3 * time.Second, KeepAlive: 30 * time.Second}
	var failing atomic.Bool
	transport := &http.Transport{
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
	}
	proxy := &httputil.ReverseProxy{
		Transport:     transport,
		FlushInterval: -1,
		Rewrite: func(request *httputil.ProxyRequest) {
			httpstream.ForwardTrailers(request.In, request.Out)
			observability.PublisherHTTPForward(request.Out.Context())
			request.Out = observability.TargetRequest(request.Out)
			host := request.In.Host
			if hooks.ModifyHTML != nil && !IsReadinessProbe(request.In) {
				request.Out.Header.Del("Accept-Encoding")
			}
			// remove client forwarding identity before deriving trusted headers.
			removeForwardingHeaders(request.Out.Header)
			request.Out.Header.Del(ReadinessProbeHeader)
			request.SetURL(targetURL)
			request.Out.Host = host
			request.SetXForwarded()
			if proxyToken != "" {
				request.Out.Header.Set(ProxyTokenHeader, proxyToken)
			}
		},
		ErrorHandler: func(response http.ResponseWriter, request *http.Request, targetErr error) {
			observability.PublisherHTTPError(request.Context(), targetErr)
			if code, ok := diagnostic.CodeOf(targetErr); ok {
				diagnostic.WriteHTTP(response, request, code)
				return
			}
			if hooks.ObserveStatus != nil {
				hooks.ObserveStatus(request, 0)
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
			if hooks.ObserveStatus != nil && response.StatusCode >= 400 {
				hooks.ObserveStatus(response.Request, response.StatusCode)
			}
			if hooks.Observe != nil {
				if err := hooks.Observe(response); err != nil {
					return err
				}
			}
			if hooks.ModifyHTML != nil && !IsReadinessProbe(response.Request) {
				if err := hooks.ModifyHTML(response); err != nil {
					return err
				}
			}
			if hooks.OnForwarded != nil {
				hooks.OnForwarded(response.Request)
			}
			observability.PublisherHTTPResponse(response.Request.Context())
			observability.PublisherHTTPUpgrade(response)
			return nil
		},
	}
	return proxy, nil
}

// ValidateRequest binds a visitor HTTP request to its public URL hostname and SNI.
func ValidateRequest(request *http.Request, hostname string) diagnostic.Code {
	// bind origin-form authority and TLS SNI to this public URL's hostname.
	if request.Method == http.MethodConnect || request.URL.IsAbs() || request.URL.Host != "" || strings.HasPrefix(request.RequestURI, "http://") || strings.HasPrefix(request.RequestURI, "https://") {
		return diagnostic.RequestRejected
	}
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
		lower := strings.ToLower(strings.ReplaceAll(name, "_", "-"))
		if lower == "forwarded" || lower == "x-real-ip" || lower == "x-tnl-proxy-token" || strings.HasPrefix(lower, "x-forwarded-") {
			delete(headers, name)
		}
	}
}

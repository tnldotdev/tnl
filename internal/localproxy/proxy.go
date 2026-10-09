// Package localproxy forwards one public hostname to one HTTP or HTTPS target.
package localproxy

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"
	"unicode"

	"github.com/tnldotdev/tnl/internal/diagnostic"
	"github.com/tnldotdev/tnl/internal/naming"
)

const maxHeaderFields = 100

// DefaultRequestLimit bounds active requests to one public URL's local service,
// across all visitor connections and HTTP/2 streams.
const DefaultRequestLimit = 500

// Preflight validates the target and verifies that it accepts a connection.
func Preflight(ctx context.Context, target string) error {
	canonicalTarget, err := NormalizeTarget(target)
	if err != nil {
		return err
	}
	parsed, err := url.Parse(canonicalTarget)
	if err != nil {
		return err
	}
	dialer := &net.Dialer{Timeout: 3 * time.Second}
	var connection net.Conn
	if parsed.Scheme == "https" {
		connection, err = (&tls.Dialer{NetDialer: dialer, Config: &tls.Config{MinVersion: tls.VersionTLS12}}).DialContext(ctx, "tcp", parsed.Host)
	} else {
		connection, err = dialer.DialContext(ctx, "tcp", parsed.Host)
	}
	if err != nil {
		return diagnostic.Wrap(diagnostic.TargetUnavailable, fmt.Errorf("localproxy: connect to target: %w", err))
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
	canonicalTarget, err := NormalizeTarget(target)
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

// NewWithMounts shares one hostname check and request limit across the base
// service and all mounted local services.
func NewWithMounts(target, hostname string, requestLimit int, mounts []Mount, onTargetFailure ...func()) (http.Handler, error) {
	return NewWithMountsHooks(target, hostname, requestLimit, mounts, ResponseHooks{}, onTargetFailure...)
}

// ResponseHooks separates header observation from body modification. observing
// a response must not disable upstream compression or consume its body.
type ResponseHooks struct {
	ModifyHTML    func(*http.Response) error
	Observe       func(*http.Response) error
	ObserveStatus func(*http.Request, int)
	OnForwarded   func(*http.Request)
}

func NewWithMountsHooks(target, hostname string, requestLimit int, mounts []Mount, hooks ResponseHooks, onTargetFailure ...func()) (http.Handler, error) {
	if requestLimit < 0 {
		return nil, errors.New("localproxy: request limit cannot be negative")
	}
	if requestLimit == 0 {
		requestLimit = DefaultRequestLimit
	}
	canonical, err := naming.CanonicalizeHostname(hostname)
	if err != nil || canonical != hostname {
		return nil, diagnostic.Wrap(diagnostic.PublicURLInvalid, errors.New("localproxy: hostname must be canonical"))
	}
	base, err := newReverseProxy(target, requestLimit, hooks, onTargetFailure)
	if err != nil {
		return nil, err
	}
	type mountedProxy struct {
		Mount
		proxy *httputil.ReverseProxy
	}
	routes := make([]mountedProxy, 0, len(mounts))
	seen := make(map[string]bool, len(mounts))
	for _, mount := range mounts {
		if !ValidMountPrefix(mount.Prefix) || seen[mount.Prefix] {
			return nil, errors.New("localproxy: mount prefixes must be distinct clean absolute paths outside /__tnl/")
		}
		seen[mount.Prefix] = true
		proxy, err := newReverseProxy(mount.Target, requestLimit, hooks, onTargetFailure)
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
	requests := make(chan struct{}, requestLimit)
	return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if code := ValidateRequest(request, hostname); code != "" {
			diagnostic.WriteHTTP(response, request, code)
			return
		}
		// admission is shared across the public URL, not per visitor connection. do
		// not queue handlers behind an upstream transport's connection limit.
		select {
		case requests <- struct{}{}:
			defer func() { <-requests }()
		default:
			if request.ProtoMajor == 1 {
				// avoid draining an unread body before sending the rejection.
				response.Header().Set("Connection", "close")
			}
			response.Header().Set("Retry-After", "1")
			diagnostic.WriteHTTP(response, request, diagnostic.RequestLimitReached, "saturated")
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
		base.ServeHTTP(response, request)
	}), nil
}

func newReverseProxy(target string, requestLimit int, hooks ResponseHooks, onTargetFailure []func()) (*httputil.ReverseProxy, error) {
	canonicalTarget, err := NormalizeTarget(target)
	if err != nil {
		return nil, err
	}
	targetURL, err := url.Parse(canonicalTarget)
	if err != nil {
		return nil, err
	}
	targetAddress := targetURL.Host
	dialer := &net.Dialer{Timeout: 3 * time.Second, KeepAlive: 30 * time.Second}
	var failing atomic.Bool
	transport := &http.Transport{
		Proxy:               nil,
		DisableCompression:  true,
		ForceAttemptHTTP2:   false,
		TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12},
		MaxIdleConns:        16,
		MaxIdleConnsPerHost: 16,
		MaxConnsPerHost:     requestLimit,
		IdleConnTimeout:     90 * time.Second,
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			if network != "tcp" || address != targetAddress {
				return nil, errors.New("localproxy: refused unexpected upstream")
			}
			return dialer.DialContext(ctx, "tcp", targetAddress)
		},
	}
	proxy := &httputil.ReverseProxy{
		Transport:     transport,
		FlushInterval: -1,
		Rewrite: func(request *httputil.ProxyRequest) {
			host := request.In.Host
			if hooks.ModifyHTML != nil {
				request.Out.Header.Del("Accept-Encoding")
			}
			// remove client forwarding identity before deriving trusted headers.
			removeForwardingHeaders(request.Out.Header)
			request.SetURL(targetURL)
			request.Out.Host = host
			request.SetXForwarded()
		},
		ErrorHandler: func(response http.ResponseWriter, request *http.Request, targetErr error) {
			if code, ok := diagnostic.CodeOf(targetErr); ok {
				diagnostic.WriteHTTP(response, request, code)
				return
			}
			if hooks.ObserveStatus != nil {
				hooks.ObserveStatus(request, 0)
			}
			if failing.CompareAndSwap(false, true) && len(onTargetFailure) != 0 && onTargetFailure[0] != nil {
				onTargetFailure[0]()
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
			if hooks.ModifyHTML != nil {
				if err := hooks.ModifyHTML(response); err != nil {
					return err
				}
			}
			if hooks.OnForwarded != nil {
				hooks.OnForwarded(response.Request)
			}
			return nil
		},
	}
	return proxy, nil
}

// NormalizeTarget validates a proxy target and returns its canonical HTTP or HTTPS origin.
func NormalizeTarget(target string) (string, error) {
	if target == "" || strings.ContainsFunc(target, unicode.IsSpace) {
		return "", diagnostic.Wrap(diagnostic.TargetInvalid, errors.New("localproxy: target must be a port, localhost:<port>, or an HTTP or HTTPS origin"))
	}

	barePort := true
	for i := 0; i < len(target); i++ {
		if target[i] < '0' || target[i] > '9' {
			barePort = false
			break
		}
	}

	hostname, portText, scheme := "127.0.0.1", target, "http"
	localhostName, localhostPort, localhostTarget := strings.Cut(target, ":")
	if !barePort && localhostTarget && strings.EqualFold(localhostName, "localhost") && !strings.Contains(localhostPort, ":") {
		portText = localhostPort
	} else if !barePort {
		parsed, err := url.Parse(target)
		if err != nil || parsed.Host == "" || parsed.User != nil || parsed.Path != "" || parsed.Opaque != "" || parsed.ForceQuery || parsed.RawQuery != "" || strings.Contains(target, "#") ||
			!strings.EqualFold(parsed.Scheme, "http") && !strings.EqualFold(parsed.Scheme, "https") {
			return "", diagnostic.Wrap(diagnostic.TargetInvalid, errors.New("localproxy: target must be a port, localhost:<port>, or an HTTP or HTTPS origin"))
		}
		scheme = strings.ToLower(parsed.Scheme)
		hostname, portText = parsed.Hostname(), parsed.Port()
		if scheme == "http" && strings.EqualFold(hostname, "localhost") {
			hostname = "127.0.0.1"
		}
	}

	if address, err := netip.ParseAddr(hostname); err == nil {
		if address.Zone() != "" {
			return "", diagnostic.Wrap(diagnostic.TargetInvalid, errors.New("localproxy: target host must not have an IP zone"))
		}
		hostname = address.String()
	} else {
		canonical, err := naming.CanonicalizeHostname(hostname)
		if err != nil || canonical != strings.ToLower(hostname) {
			return "", diagnostic.Wrap(diagnostic.TargetInvalid, errors.New("localproxy: target requires a DNS name or IP address"))
		}
		hostname = canonical
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return "", diagnostic.Wrap(diagnostic.TargetInvalid, errors.New("localproxy: target requires a valid port"))
	}
	targetAddress := net.JoinHostPort(hostname, strconv.Itoa(port))
	return scheme + "://" + targetAddress, nil
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
		lower := strings.ToLower(name)
		if lower == "forwarded" || lower == "x-real-ip" || strings.HasPrefix(lower, "x-forwarded-") {
			headers.Del(name)
		}
	}
}

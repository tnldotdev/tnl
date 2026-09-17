// Package localproxy forwards one public hostname to one local HTTP target.
package localproxy

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/tnldotdev/tnl/internal/diagnostic"
	"github.com/tnldotdev/tnl/internal/naming"
)

const maxHeaderFields = 100

// Preflight validates target and verifies that it accepts a local TCP connection.
func Preflight(ctx context.Context, target string) error {
	canonicalTarget, err := NormalizeTarget(target)
	if err != nil {
		return err
	}
	targetAddress := strings.TrimPrefix(canonicalTarget, "http://")
	connection, err := (&net.Dialer{Timeout: 3 * time.Second}).DialContext(ctx, "tcp", targetAddress)
	if err != nil {
		return diagnostic.Wrap(diagnostic.TargetUnavailable, fmt.Errorf("localproxy: connect to target: %w", err))
	}
	if err := connection.Close(); err != nil {
		return diagnostic.Wrap(diagnostic.TargetUnavailable, fmt.Errorf("localproxy: close target connection: %w", err))
	}
	return nil
}

// WaitForTarget waits until a valid target accepts a local TCP connection.
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

func New(target, hostname string) (http.Handler, error) {
	canonical, err := naming.CanonicalizeHostname(hostname)
	if err != nil || canonical != hostname {
		return nil, diagnostic.Wrap(diagnostic.RouteInvalid, errors.New("localproxy: hostname must be canonical"))
	}
	canonicalTarget, err := NormalizeTarget(target)
	if err != nil {
		return nil, err
	}
	targetAddress := strings.TrimPrefix(canonicalTarget, "http://")
	targetURL := &url.URL{Scheme: "http", Host: targetAddress}
	dialer := &net.Dialer{Timeout: 3 * time.Second, KeepAlive: 30 * time.Second}
	transport := &http.Transport{
		Proxy:               nil,
		DisableCompression:  true,
		ForceAttemptHTTP2:   false,
		MaxIdleConns:        16,
		MaxIdleConnsPerHost: 16,
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
			// Remove client forwarding identity before deriving trusted headers.
			removeForwardingHeaders(request.Out.Header)
			request.SetURL(targetURL)
			request.Out.Host = host
			request.SetXForwarded()
		},
		ErrorHandler: func(response http.ResponseWriter, request *http.Request, _ error) {
			diagnostic.WriteHTTP(response, request, http.StatusBadGateway, diagnostic.TargetUnavailable)
		},
	}
	return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if !validRequest(request, hostname) {
			diagnostic.WriteHTTP(response, request, http.StatusBadRequest, diagnostic.RequestRejected)
			return
		}
		proxy.ServeHTTP(response, request)
	}), nil
}

// NormalizeTarget validates a local proxy target and returns its canonical HTTP origin.
func NormalizeTarget(target string) (string, error) {
	if target == "" || strings.ContainsFunc(target, unicode.IsSpace) {
		return "", diagnostic.Wrap(diagnostic.TargetInvalid, errors.New("localproxy: target must be a port, localhost:<port>, or an HTTP URL on this computer"))
	}

	barePort := true
	for i := 0; i < len(target); i++ {
		if target[i] < '0' || target[i] > '9' {
			barePort = false
			break
		}
	}

	hostname, portText := "127.0.0.1", target
	localhostName, localhostPort, localhostTarget := strings.Cut(target, ":")
	if !barePort && localhostTarget && strings.EqualFold(localhostName, "localhost") && !strings.Contains(localhostPort, ":") {
		portText = localhostPort
	} else if !barePort {
		parsed, err := url.Parse(target)
		if err != nil || !strings.EqualFold(parsed.Scheme, "http") || parsed.User != nil || parsed.Host == "" || parsed.Path != "" || parsed.ForceQuery || parsed.RawQuery != "" || strings.Contains(target, "#") {
			return "", diagnostic.Wrap(diagnostic.TargetInvalid, errors.New("localproxy: target must be a port, localhost:<port>, or an HTTP URL on this computer"))
		}
		hostname, portText = parsed.Hostname(), parsed.Port()
		if strings.EqualFold(hostname, "localhost") {
			hostname = "127.0.0.1"
		}
	}

	address, err := netip.ParseAddr(hostname)
	if err != nil || !address.IsLoopback() || address.Zone() != "" {
		return "", diagnostic.Wrap(diagnostic.TargetInvalid, errors.New("localproxy: target host must be localhost, a 127.x.x.x address, or ::1"))
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return "", diagnostic.Wrap(diagnostic.TargetInvalid, errors.New("localproxy: target requires a valid port"))
	}
	targetAddress := net.JoinHostPort(address.String(), strconv.Itoa(port))
	return "http://" + targetAddress, nil
}

func validRequest(request *http.Request, hostname string) bool {
	// Bind origin-form authority and TLS SNI to this route's hostname.
	if request.Method == http.MethodConnect || request.URL.IsAbs() || request.URL.Host != "" || strings.HasPrefix(request.RequestURI, "http://") || strings.HasPrefix(request.RequestURI, "https://") {
		return false
	}
	authority, err := naming.CanonicalizeAuthority(request.Host)
	if err != nil || authority != hostname || request.TLS == nil {
		return false
	}
	serverName, err := naming.CanonicalizeHostname(request.TLS.ServerName)
	if err != nil || serverName != hostname {
		return false
	}
	fields := 0
	for _, values := range request.Header {
		fields += len(values)
		if fields > maxHeaderFields {
			return false
		}
	}
	return true
}

func removeForwardingHeaders(headers http.Header) {
	for name := range headers {
		lower := strings.ToLower(name)
		if lower == "forwarded" || lower == "x-real-ip" || strings.HasPrefix(lower, "x-forwarded-") {
			headers.Del(name)
		}
	}
}

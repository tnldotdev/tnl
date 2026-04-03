// Package localproxy securely proxies one exact public hostname to one loopback HTTP target.
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

	"github.com/0xcadams/tnl/internal/naming"
)

const maxHeaderFields = 100

// Preflight validates target and verifies that it accepts a loopback TCP connection.
func Preflight(ctx context.Context, target string) error {
	_, targetAddress, err := parseTarget(target)
	if err != nil {
		return err
	}
	connection, err := (&net.Dialer{Timeout: 3 * time.Second}).DialContext(ctx, "tcp", targetAddress)
	if err != nil {
		return fmt.Errorf("localproxy: connect to target: %w", err)
	}
	return connection.Close()
}

func New(target, hostname string) (http.Handler, error) {
	canonical, err := naming.CanonicalizeHostname(hostname)
	if err != nil || canonical != hostname {
		return nil, errors.New("localproxy: hostname must be canonical")
	}
	targetURL, targetAddress, err := parseTarget(target)
	if err != nil {
		return nil, err
	}
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
			removeForwardingHeaders(request.Out.Header)
			request.SetURL(targetURL)
			request.Out.Host = host
			request.SetXForwarded()
		},
		ErrorHandler: func(response http.ResponseWriter, _ *http.Request, _ error) {
			http.Error(response, "bad gateway", http.StatusBadGateway)
		},
	}
	return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if !validRequest(request, hostname) {
			http.Error(response, "bad request", http.StatusBadRequest)
			return
		}
		proxy.ServeHTTP(response, request)
	}), nil
}

func parseTarget(target string) (*url.URL, string, error) {
	parsed, err := url.Parse(target)
	if err != nil || parsed.Scheme != "http" || parsed.User != nil || parsed.Path != "" && parsed.Path != "/" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, "", errors.New("localproxy: target must be a literal loopback HTTP origin")
	}
	hostname := parsed.Hostname()
	address, err := netip.ParseAddr(hostname)
	if err != nil || !address.IsLoopback() || address.Zone() != "" {
		return nil, "", errors.New("localproxy: target host must be a literal loopback address")
	}
	port, err := strconv.Atoi(parsed.Port())
	if err != nil || port < 1 || port > 65535 {
		return nil, "", errors.New("localproxy: target requires a valid port")
	}
	targetAddress := net.JoinHostPort(address.String(), strconv.Itoa(port))
	return &url.URL{Scheme: "http", Host: targetAddress}, targetAddress, nil
}

func validRequest(request *http.Request, hostname string) bool {
	if request.Method == http.MethodConnect || request.URL.IsAbs() || request.URL.Host != "" || strings.HasPrefix(request.RequestURI, "http://") || strings.HasPrefix(request.RequestURI, "https://") {
		return false
	}
	authority, err := naming.CanonicalizeAuthority(request.Host)
	if err != nil || authority != hostname || request.TLS == nil || request.TLS.ServerName != hostname {
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

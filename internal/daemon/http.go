package daemon

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"time"
)

// matchedAPIPattern also probes known HTTP methods when the router reports a
// method mismatch, so the owning API still handles authentication and fallback.
func matchedAPIPattern(request *http.Request, match func(*http.Request) string) string {
	if pattern := match(request); pattern != "" && pattern != "/" {
		return pattern
	}
	for _, method := range []string{http.MethodGet, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete} {
		if method == request.Method {
			continue
		}
		candidate := *request
		candidate.Method = method
		if pattern := match(&candidate); pattern != "" && pattern != "/" {
			return pattern
		}
	}
	return ""
}

func matchedPrivatePattern(handler http.Handler, request *http.Request) string {
	if matcher, ok := handler.(interface{ MatchedPattern(*http.Request) string }); ok {
		return matcher.MatchedPattern(request)
	}
	return ""
}

func controlHTTPServer(handler http.Handler, tlsConfig *tls.Config) *http.Server {
	return &http.Server{
		Handler: handler, TLSConfig: tlsConfig, ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout: 30 * time.Second, WriteTimeout: 3 * time.Minute,
		IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 << 10,
		ErrorLog: log.New(io.Discard, "", 0),
	}
}

func serveTLS(server *http.Server, listener net.Listener) error {
	err := server.ServeTLS(listener, "", "")
	if errors.Is(err, http.ErrServerClosed) || errors.Is(err, net.ErrClosed) {
		return nil
	}
	return err
}

func newServiceHTTPClient(base *http.Client, clusterSecret, dialAddress string) (*http.Client, error) {
	if base == nil || clusterSecret == "" {
		return nil, errors.New("service HTTP client and cluster secret are required")
	}
	baseTransport := base.Transport
	if baseTransport == nil {
		baseTransport = http.DefaultTransport
	}
	if dialAddress != "" {
		configured, ok := baseTransport.(*http.Transport)
		if !ok {
			return nil, errors.New("service dial override requires an HTTP transport")
		}
		transport := configured.Clone()
		dialer := new(net.Dialer)
		transport.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, network, dialAddress)
		}
		baseTransport = transport
	}
	client := *base
	client.Transport = serviceBearerRoundTripper{secret: clusterSecret, base: baseTransport}
	client.Timeout = 30 * time.Second
	return &client, nil
}

type serviceBearerRoundTripper struct {
	secret string
	base   http.RoundTripper
}

func (t serviceBearerRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	copy := request.Clone(request.Context())
	copy.Header = request.Header.Clone()
	copy.Header.Set("Authorization", "Bearer "+t.secret)
	return t.base.RoundTrip(copy)
}

package daemon

import (
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"sync"
	"testing"

	"github.com/tnldotdev/tnl/internal/serviceapi"
)

// this fixture is the deployment proxy: it terminates verified public TLS and
// overwrites source metadata before forwarding HTTP to the private backend.
func serveIntegrationControlProxy(t *testing.T, owner *runtimeTopology, listener net.Listener, backend string, certificate *tls.Config) func() {
	t.Helper()
	origin := &url.URL{Scheme: "http", Host: backend}
	transport := &http.Transport{}
	proxy := &httputil.ReverseProxy{Transport: transport, Rewrite: func(r *httputil.ProxyRequest) {
		r.SetURL(origin)
		r.Out.Host = r.In.Host
		source, _, err := net.SplitHostPort(r.In.RemoteAddr)
		if err != nil {
			return
		}
		r.Out.Header.Set("X-Forwarded-For", source)
		r.Out.Header.Set("X-Forwarded-Proto", "https")
	}, ErrorHandler: func(response http.ResponseWriter, _ *http.Request, _ error) {
		// a stopped backend is an outage, not a malformed renewal response.
		serviceapi.WriteProblem(response, http.StatusBadGateway, "unavailable", "control backend is unavailable", "")
	}}
	server := controlHTTPServer(proxy, certificate)
	done := make(chan error, 1)
	go func() { done <- serveTLS(server, listener) }()
	stop := sync.OnceFunc(func() {
		_ = server.Close()
		transport.CloseIdleConnections()
		if err := <-done; err != nil {
			t.Errorf("control proxy shutdown: %v", err)
		}
	})
	owner.cleanupResource(t, stop)
	return stop
}

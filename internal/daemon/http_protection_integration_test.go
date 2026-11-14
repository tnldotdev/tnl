package daemon

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/policy/httpprotection"
)

func TestIntegrationHTTPProtectionTemporaryBlocks(t *testing.T) {
	f := newStandalonePublishFixture(t, "temporary-blocks")
	var forwarded atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		forwarded.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	cleanupIntegrationHTTPServer(t, target, f.owner)
	quic, tcp := f.connectors()
	config := f.identity.publisherConfig(target.URL, quic, tcp)
	config.Protection.TemporaryBlocks = true
	handle := startOwnedIntegrationPublisher(t, f.owner, config, f.diagnostics)
	ready := f.waitReady(t, handle)
	client, transport := newIntegrationHTTPSClient(t, f.pebble.roots, f.publicAddress, false, f.owner)
	transport.ForceAttemptHTTP2 = true
	request := func(path string, status int, reuse bool) {
		t.Helper()
		var reused bool
		ctx := httptrace.WithClientTrace(t.Context(), &httptrace.ClientTrace{GotConn: func(info httptrace.GotConnInfo) { reused = info.Reused }})
		r, err := http.NewRequestWithContext(ctx, http.MethodGet, ready.PublicURL+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		r.Header.Set("X-Forwarded-For", "203.0.113.10")
		response, err := client.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		_, readErr := io.Copy(io.Discard, response.Body)
		closeErr := response.Body.Close()
		if readErr != nil || closeErr != nil || response.StatusCode != status || response.ProtoMajor != 2 || reused != reuse {
			t.Fatalf("HTTP/2 request status=%d want=%d reused=%t want=%t read=%v close=%v", response.StatusCode, status, reused, reuse, readErr, closeErr)
		}
	}
	request("/", 204, false)
	baseline := forwarded.Load()
	for range httpprotection.BlockThreshold {
		request("/?q="+url.QueryEscape("<script>alert(1)</script>"), 403, true)
	}
	// this uses the same TLS connection. ingress cannot inspect HTTP/2 streams
	// inside it, so the publisher must reject the now-benign request locally.
	request("/", 403, true)
	waitForIntegrationCondition(t, 10*time.Second, func(ctx context.Context) (bool, error) {
		var accepted bool
		err := f.inspect.QueryRowContext(ctx, `SELECT EXISTS (
			SELECT 1 FROM control.http_temporary_blocks block
			JOIN control.public_urls url ON url.id=block.resource_id
			WHERE block.resource_kind='public_url' AND url.canonical_hostname=$1
			  AND block.source_ip='127.0.0.1' AND block.expires_at>now()
		)`, f.identity.hostname).Scan(&accepted)
		return accepted, err
	})
	waitForIngressRoutingCurrent(t, f.inspect, 1)
	// control's accepted report reaches ingress through its ordinary routing
	// stream. a new visitor must be rejected before publisher TLS begins.
	r, err := http.NewRequestWithContext(t.Context(), http.MethodGet, ready.PublicURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	response, err := f.visitor.client.Do(r)
	if response != nil {
		_ = response.Body.Close()
	}
	if err == nil || response != nil {
		t.Fatal("ingress forwarded a new connection from the blocked source", err)
	}
	if forwarded.Load() != baseline {
		t.Fatal("blocked request reached the target")
	}
	transport.CloseIdleConnections()
	stopIntegrationPublisher(t, handle)
}

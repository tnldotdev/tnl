package service

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/observability/inspection"
	protectionpolicy "github.com/tnldotdev/tnl/internal/policy/httpprotection"
	"github.com/tnldotdev/tnl/internal/publisher/httpaccess"
	"github.com/tnldotdev/tnl/internal/publisher/requestlimit"
	servicestream "github.com/tnldotdev/tnl/internal/publisher/service/stream"
	"github.com/tnldotdev/tnl/internal/security/visitortoken"
	"github.com/tnldotdev/tnl/internal/transport/httpstream"
	"github.com/tnldotdev/tnl/internal/transport/targettransport"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type serviceHTTPResult struct {
	status, protocol int
	header           http.Header
	err              error
}

func serviceHTTPDo(client *http.Client, request *http.Request) serviceHTTPResult {
	response, err := client.Do(request)
	if err != nil {
		return serviceHTTPResult{err: err}
	}
	defer response.Body.Close()
	_, err = io.Copy(io.Discard, response.Body)
	return serviceHTTPResult{status: response.StatusCode, protocol: response.ProtoMajor, header: response.Header, err: err}
}

// the frontend and all visitor connections borrow one real run-owned target
// proxy. no independent proxy or application budget is created per connection.
func serviceHTTPLimitedRun(t *testing.T, address string, limit int, number int64) (*http.Transport, visitortoken.Token, <-chan struct{}) {
	t.Helper()
	target := servicestream.HTTPTarget{Address: address, Connections: limit, Transport: targettransport.Transport{Protocol: config.ProtocolHTTP}}
	forwarder, err := target.NewHTTPProxy(t.Context(), "preview.example.test", httpstream.ResponseHooks{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := forwarder.Close(); err != nil {
			t.Error("close run HTTP proxy", err)
		}
	})
	finished := make(chan struct{}, 16)
	client, _, _, token := serviceHTTPConfiguredFixture(t, http.HandlerFunc(forwarder.ServeAdmittedHTTP), true, true, func(f *HTTP) {
		// this fixture holds uploads open at the target to test streaming limits.
		f.Protection.WAF = protectionpolicy.Off
		f.Number, f.Header.RunNumber = number, uint64(number)
		f.RunID = "srun_" + strings.Repeat(string(rune('R'+number)), 22)
		f.Header.ServiceRunID = f.RunID
		f.Requests, err = requestlimit.NewHTTP(&controlv1.ProjectHTTPApplicationLimits{Concurrency: &limit})
		if err != nil {
			t.Fatal(err)
		}
		f.InspectionMode = inspection.SummaryMode
		f.ObserveSummary = func(summary inspection.Summary) {
			if summary.Path == "/hold" {
				finished <- struct{}{}
			}
		}
	})
	return client.Transport.(*http.Transport), token, finished
}

func serviceHTTPSingleVisitor(t *testing.T, base *http.Transport) *http.Client {
	t.Helper()
	transport := base.Clone()
	var dialed atomic.Bool
	dial := transport.DialContext
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		if dialed.Swap(true) {
			return nil, errors.New("test client attempted another visitor connection")
		}
		return dial(ctx, network, address)
	}
	t.Cleanup(transport.CloseIdleConnections)
	return &http.Client{Transport: transport, Timeout: 5 * time.Second}
}

func serviceHTTPLimitedGet(t *testing.T, client *http.Client, token visitortoken.Token, overloaded bool) {
	t.Helper()
	request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "https://preview.example.test/", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set(httpaccess.VisitorTokenHeader, token.Reveal())
	got := serviceHTTPDo(client, request)
	if overloaded {
		if got.err != nil || got.status != http.StatusServiceUnavailable || got.protocol != 2 ||
			got.header.Get("Retry-After") != "1" || got.header.Get("Tnl-Error-Code") != "TNL_REQUEST_LIMIT_REACHED" {
			t.Fatalf("excess HTTP/2 request: status=%d protocol=%d headers=%v err=%v", got.status, got.protocol, got.header, got.err)
		}
		return
	}
	if got.err != nil || got.status != http.StatusNoContent || got.protocol != 2 {
		t.Fatalf("available HTTP/2 request: status=%d protocol=%d headers=%v err=%v", got.status, got.protocol, got.header, got.err)
	}
}

func TestServiceHTTPBoundsHTTP2FanoutAcrossVisitorConnections(t *testing.T) {
	const limit = 4
	started := make(chan struct{}, limit+1)
	var accepted atomic.Int32
	upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ProtoMajor != 1 {
			t.Error("local service no longer used HTTP/1", r.Proto)
		}
		if r.Method == http.MethodPost {
			started <- struct{}{}
			_, _ = io.Copy(io.Discard, r.Body)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	upstream.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			accepted.Add(1)
		}
	}
	upstream.Start()
	t.Cleanup(upstream.Close)
	base, token, finished := serviceHTTPLimitedRun(t, strings.TrimPrefix(upstream.URL, "http://"), limit, 1)
	client := serviceHTTPSingleVisitor(t, base)
	var bodies []*io.PipeWriter
	var results []<-chan serviceHTTPResult
	var cancels []context.CancelFunc
	for range limit {
		reader, writer := io.Pipe()
		ctx, cancel := context.WithCancel(t.Context())
		request, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://preview.example.test/hold", reader)
		if err != nil {
			t.Fatal(err)
		}
		request.ContentLength = 2
		request.Header.Set(httpaccess.VisitorTokenHeader, token.Reveal())
		result, done := make(chan serviceHTTPResult, 1), make(chan struct{})
		go func() { defer close(done); result <- serviceHTTPDo(client, request) }()
		t.Cleanup(func() { cancel(); _ = writer.Close(); serviceHTTPAwait(t, done) })
		if _, err := writer.Write([]byte("a")); err != nil {
			t.Fatal(err)
		}
		bodies, results, cancels = append(bodies, writer), append(results, result), append(cancels, cancel)
		serviceHTTPAwait(t, started)
	}
	for range 32 {
		serviceHTTPLimitedGet(t, client, token, true)
	}
	other := serviceHTTPSingleVisitor(t, base)
	serviceHTTPLimitedGet(t, other, token, true)

	// send only the HTTP/1 headers: overload must respond without waiting for
	// the unread body and close that connection rather than draining it.
	raw, err := base.DialContext(t.Context(), "tcp", "preview.example.test:443")
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	_ = raw.SetDeadline(time.Now().Add(3 * time.Second))
	trust := base.TLSClientConfig.Clone()
	trust.ServerName, trust.NextProtos = "preview.example.test", []string{"http/1.1"}
	http1 := tls.Client(raw, trust)
	if _, err := fmt.Fprintf(http1, "POST / HTTP/1.1\r\nHost: preview.example.test\r\n%s: %s\r\nContent-Length: 2\r\n\r\n", httpaccess.VisitorTokenHeader, token.Reveal()); err != nil {
		t.Fatal(err)
	}
	response, err := http.ReadResponse(bufio.NewReader(http1), nil)
	if err != nil {
		t.Fatal("HTTP/1 overload waited for an unread body", err)
	}
	if response.StatusCode != http.StatusServiceUnavailable || !response.Close ||
		response.Header.Get("Retry-After") != "1" || response.Header.Get("Tnl-Error-Code") != "TNL_REQUEST_LIMIT_REACHED" {
		t.Fatal("HTTP/1 overload lost its close or diagnostic", response.Status, response.Close, response.Header)
	}
	_, readErr := io.Copy(io.Discard, response.Body)
	if err := errors.Join(readErr, response.Body.Close()); err != nil {
		t.Fatal("HTTP/1 overload response did not finish", err)
	}
	if got := accepted.Load(); got != limit {
		t.Fatalf("target TCP connections=%d, want exactly %d despite excess streams and visitors", got, limit)
	}
	independent, independentToken, _ := serviceHTTPLimitedRun(t, strings.TrimPrefix(upstream.URL, "http://"), 1, 2)
	serviceHTTPLimitedGet(t, serviceHTTPSingleVisitor(t, independent), independentToken, false)
	if got := accepted.Load(); got != limit+1 {
		t.Fatal("independent run did not own a separate request/target budget", got)
	}
	cancels[0]()
	if got := serviceHTTPAwait(t, results[0]); got.err == nil {
		t.Fatal("canceled HTTP/2 stream succeeded", got)
	}
	serviceHTTPAwait(t, finished)
	serviceHTTPLimitedGet(t, other, token, false)
	for i := 1; i < limit; i++ {
		if _, err := bodies[i].Write([]byte("b")); err != nil {
			t.Fatal("canceling one HTTP/2 stream interrupted a sibling upload", err)
		}
		_ = bodies[i].Close()
		if got := serviceHTTPAwait(t, results[i]); got.err != nil || got.status != http.StatusNoContent || got.protocol != 2 {
			t.Fatalf("completed HTTP/2 sibling: %+v", got)
		}
		serviceHTTPAwait(t, finished)
	}
	serviceHTTPLimitedGet(t, client, token, false)
	if got := accepted.Load(); got != limit+2 {
		t.Fatalf("target sockets=%d, want %d including independent run and one canceled-socket replacement", got, limit+2)
	}
}

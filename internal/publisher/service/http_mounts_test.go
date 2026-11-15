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
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/observability/inspection"
	"github.com/tnldotdev/tnl/internal/publisher/httpaccess"
	"github.com/tnldotdev/tnl/internal/publisher/proxy"
	"github.com/tnldotdev/tnl/internal/publisher/requestlimit"
	servicestream "github.com/tnldotdev/tnl/internal/publisher/service/stream"
	"github.com/tnldotdev/tnl/internal/security/visitortoken"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

// hold the publisher's response cleanup, not a remote application goroutine.
// the application slot must remain occupied until its proxy handler can return.
type mountResponseCleanup struct {
	io.ReadCloser
	writer  io.Writer
	entered chan struct{}
	release <-chan struct{}
	once    sync.Once
}

func (b *mountResponseCleanup) Write(value []byte) (int, error) {
	if b.writer == nil {
		return 0, errors.New("response is not an upgrade")
	}
	return b.writer.Write(value)
}

func (b *mountResponseCleanup) Close() error {
	err := b.ReadCloser.Close()
	b.once.Do(func() {
		close(b.entered)
		<-b.release
	})
	return err
}

func serviceMountGet(t *testing.T, client *http.Client, path string, token visitortoken.Token) *http.Response {
	t.Helper()
	request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "https://preview.example.test"+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set(httpaccess.VisitorTokenHeader, token.Reveal())
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	return response
}

func serviceMountCheck(t *testing.T, client *http.Client, path string, token visitortoken.Token, status int, body string) {
	t.Helper()
	response := serviceMountGet(t, client, path, token)
	defer response.Body.Close()
	got, err := io.ReadAll(response.Body)
	if err != nil || response.StatusCode != status || status == http.StatusOK && string(got) != body {
		t.Fatal("service mount response changed", path, response.StatusCode, string(got), err)
	}
	if status == http.StatusServiceUnavailable && (response.Header.Get("Tnl-Error-Code") != "TNL_REQUEST_LIMIT_REACHED" ||
		response.Header.Get("Retry-After") != "1" || !response.Close) {
		t.Fatal("mount saturation lost its diagnostic, retry hint, or HTTP/1 close", response.Header, response.Close)
	}
}

func TestServiceHTTPMountSharesStreamBudgetUntilHandlerCleanup(t *testing.T) {
	sendLast, finishCleanup := make(chan struct{}), make(chan struct{})
	unblockBody := sync.OnceFunc(func() { close(sendLast) })
	unblockCleanup := sync.OnceFunc(func() { close(finishCleanup) })
	defer unblockBody()
	defer unblockCleanup()
	cleanupEntered, handled := make(chan struct{}), make(chan struct{})
	mounted := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/hold" {
			_, _ = io.WriteString(w, "mounted")
			return
		}
		_, _ = io.WriteString(w, "first")
		_ = http.NewResponseController(w).Flush()
		select {
		case <-sendLast:
		case <-r.Context().Done():
			return
		}
		_, _ = io.WriteString(w, "last")
	}))
	t.Cleanup(mounted.Close)
	budget, err := requestlimit.NewHTTP(&controlv1.ProjectHTTPApplicationLimits{Concurrency: new(1)})
	if err != nil {
		t.Fatal(err)
	}
	client, _, _, token := serviceHTTPConfiguredFixture(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "base")
	}), false, false, func(f *HTTP) {
		f.Requests = budget
		f.InspectionMode = inspection.SummaryMode
		f.ObserveSummary = func(summary inspection.Summary) {
			if summary.Path == "/api/hold" {
				close(handled)
			}
		}
		f.ResponseHooks.Observe = func(response *http.Response) error {
			if response.Request.URL.Path == "/hold" {
				response.Body = &mountResponseCleanup{ReadCloser: response.Body, entered: cleanupEntered, release: finishCleanup}
			}
			return nil
		}
	}, func(target *servicestream.HTTPTarget) {
		target.Mounts = []proxy.Mount{{Prefix: "/api", Target: mounted.URL, StripPrefix: true}}
	})
	response := serviceMountGet(t, client, "/api/hold", token)
	defer func() {
		unblockBody()
		unblockCleanup()
		response.Body.Close()
	}()
	first := make([]byte, len("first"))
	if _, err := io.ReadFull(response.Body, first); err != nil || string(first) != "first" || response.StatusCode != http.StatusOK {
		t.Fatal("mounted stream did not flush its first bytes", string(first), err)
	}
	for _, path := range []string{"/", "/api/check"} {
		serviceMountCheck(t, client, path, token, http.StatusServiceUnavailable, "")
	}
	unblockBody()
	last := make([]byte, len("last"))
	if _, err := io.ReadFull(response.Body, last); err != nil || string(first)+string(last) != "firstlast" {
		t.Fatal("mounted stream lost its final bytes", string(last), err)
	}
	serviceHTTPAwait(t, cleanupEntered)
	for _, path := range []string{"/", "/api/check"} {
		serviceMountCheck(t, client, path, token, http.StatusServiceUnavailable, "")
	}
	select {
	case <-handled:
		t.Fatal("mounted response finished before publisher cleanup joined")
	default:
	}
	unblockCleanup()
	if rest, err := io.ReadAll(response.Body); err != nil || len(rest) != 0 {
		t.Fatal("mounted stream did not finish cleanly", string(rest), err)
	}
	serviceHTTPAwait(t, handled)
	serviceMountCheck(t, client, "/", token, http.StatusOK, "base")
	serviceMountCheck(t, client, "/api/check", token, http.StatusOK, "mounted")
}

func TestServiceHTTPMountHoldsUpgradeBudgetThroughAckAndCleanup(t *testing.T) {
	finishCleanup := make(chan struct{})
	unblock := sync.OnceFunc(func() { close(finishCleanup) })
	defer unblock()
	cleanupEntered, handled := make(chan struct{}), make(chan struct{})
	upgraded := make(chan error, 1)
	mounted := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/hmr" {
			_, _ = io.WriteString(w, "mounted")
			return
		}
		if r.Header.Get("Connection") != "Upgrade" || r.Header.Get("Upgrade") != "websocket" {
			http.Error(w, "missing upgrade", http.StatusBadRequest)
			return
		}
		conn, buffer, err := http.NewResponseController(w).Hijack()
		if err != nil {
			upgraded <- err
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		_, err = buffer.WriteString("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\nhot")
		if err == nil {
			err = buffer.Flush()
		}
		payload := make([]byte, len("client upgrade bytes"))
		if err == nil {
			_, err = io.ReadFull(buffer, payload)
		}
		if err == nil && string(payload) != "client upgrade bytes" {
			err = fmt.Errorf("upgraded request changed: %q", payload)
		}
		if err == nil {
			_, err = io.WriteString(conn, "ack")
		}
		upgraded <- err
	}))
	t.Cleanup(mounted.Close)
	budget, err := requestlimit.NewHTTP(&controlv1.ProjectHTTPApplicationLimits{Concurrency: new(1)})
	if err != nil {
		t.Fatal(err)
	}
	client, _, _, token := serviceHTTPConfiguredFixture(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "base")
	}), false, false, func(f *HTTP) {
		f.Requests = budget
		f.InspectionMode = inspection.SummaryMode
		f.ObserveSummary = func(summary inspection.Summary) {
			if summary.Path == "/api/hmr" {
				close(handled)
			}
		}
		f.ResponseHooks.Observe = func(response *http.Response) error {
			if response.StatusCode == http.StatusSwitchingProtocols {
				writer, ok := response.Body.(io.Writer)
				if !ok {
					return errors.New("upgrade response lost its writable stream")
				}
				response.Body = &mountResponseCleanup{ReadCloser: response.Body, writer: writer, entered: cleanupEntered, release: finishCleanup}
			}
			return nil
		}
	}, func(target *servicestream.HTTPTarget) {
		target.Mounts = []proxy.Mount{{Prefix: "/api", Target: mounted.URL, StripPrefix: true}}
	})
	transport := client.Transport.(*http.Transport)
	raw, err := transport.DialContext(t.Context(), "tcp", "preview.example.test:443")
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	_ = raw.SetDeadline(time.Now().Add(5 * time.Second))
	trust := transport.TLSClientConfig.Clone()
	trust.ServerName = "preview.example.test"
	conn := tls.Client(raw, trust)
	if _, err := fmt.Fprintf(conn, "GET /api/hmr HTTP/1.1\r\nHost: preview.example.test\r\n%s: %s\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n", httpaccess.VisitorTokenHeader, token.Reveal()); err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(conn)
	response, err := http.ReadResponse(reader, nil)
	if err != nil || response.StatusCode != http.StatusSwitchingProtocols {
		t.Fatal("mounted upgrade was not admitted", response, err)
	}
	hot := make([]byte, len("hot"))
	if _, err := io.ReadFull(reader, hot); err != nil || string(hot) != "hot" {
		t.Fatal("mounted upgrade lost its initial bytes", string(hot), err)
	}
	for _, path := range []string{"/", "/api/check"} {
		serviceMountCheck(t, client, path, token, http.StatusServiceUnavailable, "")
	}
	if _, err := io.WriteString(conn, "client upgrade bytes"); err != nil {
		t.Fatal(err)
	}
	ack := make([]byte, len("ack"))
	if _, err := io.ReadFull(reader, ack); err != nil || string(ack) != "ack" {
		t.Fatal("mounted upgrade lost the application acknowledgement", string(ack), err)
	}
	if err := serviceHTTPAwait(t, upgraded); err != nil {
		t.Fatal(err)
	}
	// avoid simultaneous TLS close-notify writes over the in-memory visitor.
	_ = raw.Close()
	serviceHTTPAwait(t, cleanupEntered)
	for _, path := range []string{"/", "/api/check"} {
		serviceMountCheck(t, client, path, token, http.StatusServiceUnavailable, "")
	}
	select {
	case <-handled:
		t.Fatal("upgrade released its request slot before handler cleanup joined")
	default:
	}
	unblock()
	serviceHTTPAwait(t, handled)
	serviceMountCheck(t, client, "/", token, http.StatusOK, "base")
	serviceMountCheck(t, client, "/api/check", token, http.StatusOK, "mounted")
}

func TestServiceHTTP2SameTargetConcurrencyKeepsMountsAndLaterRequests(t *testing.T) {
	canceled := make(chan struct{})
	var applications atomic.Int32
	client, _, _, token := serviceHTTPConfiguredFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		applications.Add(1)
		if r.URL.Path == "/hold" {
			_, _ = io.WriteString(w, "first")
			_ = http.NewResponseController(w).Flush()
			<-r.Context().Done()
			close(canceled)
			return
		}
		_, _ = io.WriteString(w, "short")
	}), true, false, nil, func(target *servicestream.HTTPTarget) {
		target.Mounts = []proxy.Mount{{Prefix: "/api", Target: "http://" + target.Address, StripPrefix: true}}
	})
	transport := client.Transport.(*http.Transport)
	dial := transport.DialContext
	var dials atomic.Int32
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		if dials.Add(1) != 1 {
			return nil, errors.New("visitor tried to replace its HTTP/2 TLS connection")
		}
		return dial(ctx, network, address)
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://preview.example.test/hold", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set(httpaccess.VisitorTokenHeader, token.Reveal())
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	first := make([]byte, len("first"))
	if _, err := io.ReadFull(response.Body, first); err != nil || string(first) != "first" || response.ProtoMajor != 2 {
		t.Fatal("long service request did not start on HTTP/2", response.Proto, string(first), err)
	}
	short := func(path string) {
		t.Helper()
		reply := serviceMountGet(t, client, path, token)
		defer reply.Body.Close()
		body, err := io.ReadAll(reply.Body)
		if err != nil || reply.StatusCode != http.StatusOK || reply.ProtoMajor != 2 || string(body) != "short" {
			t.Fatal("independent request could not share the HTTP/2 service connection", path, reply.StatusCode, reply.Proto, string(body), err)
		}
	}
	short("/check")
	short("/api/check")
	select {
	case <-canceled:
		t.Fatal("a short request interrupted the long response")
	default:
	}
	cancel()
	if _, err := io.Copy(io.Discard, response.Body); err == nil || errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("closing one request did not cancel only that stream", err)
	}
	serviceHTTPAwait(t, canceled)
	short("/future")
	short("/api/future")
	if dials.Load() != 1 || applications.Load() != 5 {
		t.Fatal("request cancellation replaced the visitor connection or replayed application work", dials.Load(), applications.Load())
	}
}

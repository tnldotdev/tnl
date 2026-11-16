package stream

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/testutil/visitorfixture"
)

type finishOutcomeResetConn struct {
	net.Conn
	armed atomic.Bool
	read  chan struct{}
	once  sync.Once
}

func (c *finishOutcomeResetConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if err != nil && c.armed.Load() {
		c.once.Do(func() { close(c.read) })
	}
	return n, err
}

type finishOutcomeCase struct {
	name                               string
	abort, reset, requestReset, target bool
	closeFailure, completionFailure    bool
}

// exercise the actual HTTP worker and its TLS connection, not a frontend that
// returns a supplied result. input cancellation is independent of admission and
// of the lifetime cancellations Forward performs during successful cleanup.
func TestHTTPVisitorFinishRetainsInputOutcomeAfterJoinedCleanup(t *testing.T) {
	for _, h2 := range []bool{false, true} {
		for _, test := range []finishOutcomeCase{
			{name: "complete"},
			{name: "input_abort", abort: true},
			{name: "request_reset", requestReset: true},
			{name: "visitor_connection_close", reset: true},
			{name: "target_truncated_response", target: true},
			{name: "physical_close_failure", closeFailure: true},
			{name: "input_abort_close_failure", abort: true, closeFailure: true},
			{name: "input_abort_completion_failure", abort: true, completionFailure: true},
			{name: "visitor_connection_close_cancellation_and_close_failure", abort: true, reset: true, closeFailure: true},
		} {
			protocol := "http1"
			if h2 {
				protocol = "http2"
			}
			t.Run(protocol+"/"+test.name, func(t *testing.T) {
				testHTTPFinishOutcome(t, h2, test)
			})
		}
	}
}

func testHTTPFinishOutcome(t *testing.T, h2 bool, test finishOutcomeCase) {
	t.Helper()
	ctx, finish := context.WithTimeout(t.Context(), 5*time.Second)
	defer finish()
	operation, abort := context.WithCancel(ctx)
	defer abort()
	requestContext, resetRequest := context.WithCancel(ctx)
	defer resetRequest()
	const hostname = "service.example.test"
	const first, last = "active response\n", "complete response\n"
	certificate := visitorfixture.Certificate(t, hostname)
	server, visitor := net.Pipe()
	reset := &finishOutcomeResetConn{Conn: server, read: make(chan struct{})}
	closeGate, callbackGate, handlerGate, responseGate := make(chan struct{}), make(chan struct{}), make(chan struct{}), make(chan struct{})
	releaseClose := sync.OnceFunc(func() { close(closeGate) })
	releaseCallback := sync.OnceFunc(func() { close(callbackGate) })
	releaseHandler := sync.OnceFunc(func() { close(handlerGate) })
	releaseResponse := sync.OnceFunc(func() { close(responseGate) })
	closeFailure, completionFailure := errors.New("independent visitor physical close failure"), errors.New("independent delivery completion failure")
	wire := &completionCloseConn{
		Conn: reset, entered: make(chan struct{}), finished: make(chan struct{}), release: closeGate,
	}
	if test.closeFailure {
		wire.err = closeFailure
	}
	admission := &completionAdmission{}
	handlerEntered, handlerCanceled, handlerJoined := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var calls atomic.Int32
	var siblings atomic.Int32
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/sibling" {
			siblings.Add(1)
			_, _ = io.WriteString(w, "healthy sibling\n")
			return
		}
		if calls.Add(1) != 1 {
			t.Error("HTTP completion proof replayed its application request")
			return
		}
		defer close(handlerJoined)
		// completed-body observation must not depend on connection teardown.
		// the same declared length makes an interrupted response incomplete.
		w.Header().Set("Content-Length", strconv.Itoa(len(first)+len(last)))
		_, _ = io.WriteString(w, first)
		if err := http.NewResponseController(w).Flush(); err != nil {
			t.Error("active response did not flush", err)
			return
		}
		close(handlerEntered)
		select {
		case <-responseGate:
			if test.target {
				// the actual target terminates a response after sending headers
				// and body bytes. a fully delivered HTTP error is not this case.
				panic(http.ErrAbortHandler)
			}
			_, _ = io.WriteString(w, last)
		case <-r.Context().Done():
			close(handlerCanceled)
			// hold entered work after cancellation so the callback must prove
			// it joins the handler, rather than merely canceling its context.
			<-handlerGate
		}
	})
	type outcome struct {
		err                                   error
		handlerJoined, physicalJoined         bool
		admissionLive, admissionNotYetStopped bool
	}
	observed := make(chan outcome, 1)
	var completions atomic.Int32
	endpoint := Stream{
		Protocol: config.ProtocolHTTP, Hostname: hostname, Handler: handler,
		TLS:     &tls.Config{Certificates: []tls.Certificate{certificate}},
		Visitor: ConnectorVisitor{Admission: admission},
		FinishVisitor: func(result error) error {
			completions.Add(1)
			snapshot := outcome{err: result, admissionNotYetStopped: admission.stopped.Load() == 0}
			until, err := admission.CheckUse(context.Background())
			snapshot.admissionLive = err == nil && until.After(time.Now())
			select {
			case <-handlerJoined:
				snapshot.handlerJoined = true
			default:
			}
			select {
			case <-wire.finished:
				snapshot.physicalJoined = true
			default:
			}
			observed <- snapshot
			<-callbackGate
			if test.completionFailure {
				return errors.Join(context.Canceled, completionFailure)
			}
			return nil
		},
	}
	if test.target {
		target := httptest.NewServer(handler)
		t.Cleanup(target.Close)
		endpoint.Handler, endpoint.Target = nil, target.Listener.Addr().String()
	}
	var dialed atomic.Bool
	transport := &http.Transport{
		ForceAttemptHTTP2: h2,
		TLSClientConfig:   &tls.Config{RootCAs: visitorfixture.Roots(t, certificate)},
		DialContext: func(context.Context, string, string) (net.Conn, error) {
			if dialed.Swap(true) {
				return nil, errors.New("HTTP completion proof attempted another visitor connection")
			}
			return visitor, nil
		},
	}
	forwarded, forwardJoined := make(chan error, 1), make(chan struct{})
	type reply struct {
		body string
		err  error
	}
	clientStarted, clientDone, clientJoined := make(chan error, 1), make(chan reply, 1), make(chan struct{})
	t.Cleanup(func() {
		abort()
		releaseHandler()
		releaseResponse()
		releaseClose()
		releaseCallback()
		_ = visitor.Close()
		_ = server.Close()
		transport.CloseIdleConnections()
		finishOutcomeCleanupJoin(t, forwardJoined)
		finishOutcomeCleanupJoin(t, clientJoined)
	})
	go func() { defer close(forwardJoined); forwarded <- endpoint.Forward(operation, wire) }()
	go func() {
		defer close(clientJoined)
		request, err := http.NewRequestWithContext(requestContext, http.MethodGet, "https://"+hostname+"/", nil)
		if err != nil {
			clientStarted <- err
			return
		}
		response, err := transport.RoundTrip(request)
		if err != nil {
			clientStarted <- err
			return
		}
		defer response.Body.Close()
		body := bufio.NewReader(response.Body)
		prefix, err := body.ReadString('\n')
		wantProtocol := 1
		if h2 {
			wantProtocol = 2
		}
		if err != nil || prefix != first || response.StatusCode != http.StatusOK || response.ProtoMajor != wantProtocol ||
			response.TLS == nil || len(response.TLS.VerifiedChains) == 0 {
			clientStarted <- errors.Join(err, errors.New("active HTTP response lost its body, protocol, or verified visitor TLS"))
			return
		}
		clientStarted <- nil
		rest, err := io.ReadAll(body)
		clientDone <- reply{body: prefix + string(rest), err: err}
	}()
	if err := finishOutcomeAwait(t, ctx, clientStarted); err != nil {
		t.Fatal("visitor did not enter actual TLS/HTTP serving", err)
	}
	finishOutcomeAwait(t, ctx, handlerEntered)
	select {
	case got := <-observed:
		t.Fatal("delivery callback entered before the active response finished", got.err)
	default:
	}
	if admission.stopped.Load() != 0 {
		t.Fatal("active HTTP response stopped its independently live admission")
	}
	switch {
	case test.requestReset:
		resetRequest()
		finishOutcomeAwait(t, ctx, handlerCanceled)
		releaseHandler()
	case test.reset:
		reset.armed.Store(true)
		_ = visitor.Close()
		finishOutcomeAwait(t, ctx, reset.read)
		finishOutcomeAwait(t, ctx, handlerCanceled)
		if test.abort {
			abort()
		}
		releaseHandler()
	case test.abort:
		abort()
		finishOutcomeAwait(t, ctx, handlerCanceled)
		select {
		case got := <-observed:
			t.Fatal("input cancellation skipped its active handler join", got.err)
		default:
		}
		releaseHandler()
	default:
		releaseResponse()
	}
	response := finishOutcomeAwait(t, ctx, clientDone)
	if test.abort || test.reset || test.requestReset || test.target {
		if response.err == nil {
			t.Error("aborted or truncated active response appeared complete to its visitor", response.body)
		}
	} else if response.err != nil || response.body != first+last {
		t.Error("normal response or independent cleanup failure lost completed visitor bytes", response.body, response.err)
	}
	if h2 && (test.requestReset || test.target) {
		// an HTTP/2 request reset or truncated target response does not make
		// the admitted connection fail. completion concerns raw return-copy
		// delivery, not whether every application request succeeded.
		select {
		case got := <-observed:
			t.Fatal("one failed HTTP/2 request completed the shared connection", got.err)
		default:
		}
		sibling, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+hostname+"/sibling", nil)
		if err != nil {
			t.Fatal(err)
		}
		reply, err := transport.RoundTrip(sibling)
		if err != nil {
			t.Fatal("failed HTTP/2 request poisoned its same-connection sibling", err)
		}
		body, readErr := io.ReadAll(reply.Body)
		closeErr := reply.Body.Close()
		if reply.StatusCode != http.StatusOK || reply.ProtoMajor != 2 || string(body) != "healthy sibling\n" || readErr != nil || closeErr != nil {
			t.Error("failed HTTP/2 request changed its healthy sibling", reply.Status, reply.Proto, string(body), readErr, closeErr)
		}
		if siblings.Load() != 1 {
			t.Error("healthy HTTP/2 sibling did not reach the target exactly once", siblings.Load())
		}
	}
	// stop the connection only after the complete body (and any sibling) was
	// consumed. do not make client TLS close-notify wait on the held server Close.
	_ = visitor.Close()
	transport.CloseIdleConnections()
	finishOutcomeAwait(t, ctx, wire.entered)
	select {
	case got := <-observed:
		t.Fatal("delivery callback ran before physical close joined", got.err)
	default:
	}
	releaseClose()
	got := finishOutcomeAwait(t, ctx, observed)
	if !got.handlerJoined || !got.physicalJoined || !got.admissionLive || !got.admissionNotYetStopped {
		t.Error("delivery callback did not follow owned joins while admission remained live", got)
	}
	if test.abort && !errors.Is(got.err, context.Canceled) {
		t.Error("input HTTP cancellation became successful return delivery", got.err)
	}
	if test.closeFailure && !errors.Is(got.err, closeFailure) {
		t.Error("delivery completion lost independent physical cleanup failure", got.err)
	}
	if !test.abort && !test.reset && !test.requestReset && !test.target && !test.closeFailure && got.err != nil {
		t.Error("owned deferred cancellation turned completed HTTP delivery into failure", got.err)
	}
	select {
	case err := <-forwarded:
		t.Fatal("HTTP forwarding returned before its delivery callback joined", err)
	default:
	}
	if admission.stopped.Load() != 0 {
		t.Error("HTTP admission stopped while its delivery callback was still active")
	}
	releaseCallback()
	result := finishOutcomeAwait(t, ctx, forwarded)
	if test.abort && !errors.Is(result, context.Canceled) ||
		test.closeFailure && !errors.Is(result, closeFailure) || test.completionFailure && !errors.Is(result, completionFailure) {
		t.Error("HTTP forwarding discarded an operation, cleanup, or delivery failure", result)
	}
	if !test.abort && !test.reset && !test.requestReset && !test.target && !test.closeFailure && result != nil {
		t.Error("complete HTTP forwarding acquired a cleanup cancellation", result)
	}
	finishOutcomeAwait(t, ctx, forwardJoined)
	finishOutcomeAwait(t, ctx, clientJoined)
	if completions.Load() != 1 || admission.stopped.Load() != 1 || calls.Load() != 1 {
		t.Error("HTTP completion, admission stop, or application invocation was not exactly once", completions.Load(), admission.stopped.Load(), calls.Load())
	}
}

func finishOutcomeAwait[T any](t *testing.T, ctx context.Context, events <-chan T) T {
	t.Helper()
	select {
	case event := <-events:
		return event
	case <-ctx.Done():
		t.Fatal("HTTP finish outcome fixture did not join within five seconds", ctx.Err())
		var zero T
		return zero
	}
}

func finishOutcomeCleanupJoin(t *testing.T, joined <-chan struct{}) {
	t.Helper()
	select {
	case <-joined:
	case <-time.After(5 * time.Second):
		t.Error("HTTP finish outcome worker outlived fixture cleanup")
	}
}

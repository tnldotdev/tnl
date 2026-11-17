//go:build js && wasm

package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"syscall/js"
	"testing"
)

func publisherFunction(t *testing.T, source string) js.Value {
	t.Helper()
	return js.Global().Get("Function").New("return (" + source + ")").Invoke()
}

func publisherTestHandler(t *testing.T, source string) *publisherFetchHandler {
	t.Helper()
	handler, err := newPublisherFetchHandler(publisherFunction(t, source))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := handler.Close(); err != nil {
			t.Error(err)
		}
	})
	return handler
}

func TestPublisherFetchRequestAndResponse(t *testing.T) {
	handler := publisherTestHandler(t, `async request => {
		if (!(request instanceof Request) || request.url !== "https://preview.example.test/path?q=1" ||
			request.method !== "POST" || request.headers.get("x-application") !== "secret" ||
			request.headers.get("cookie") !== "session=app" || request.headers.get("host") !== "preview.example.test") throw Error("request facts");
		const text = await request.text();
		const headers = new Headers([
			["set-cookie", "a=1; Expires=Wed, 21 Oct 2037 07:28:00 GMT"],
			["set-cookie", "b=2"], ["x-response", "yes"]
		]);
		const response = new Response(text.toUpperCase(), {status: 201, headers});
		Object.defineProperty(response, "headers", {value: headers});
		return response;
	}`)
	request := httptest.NewRequest(http.MethodPost, "https://preview.example.test/path?q=1", strings.NewReader("hello"))
	request.Header.Set("X-Application", "secret")
	request.Header.Set("Cookie", "session=app")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != 201 || response.Body.String() != "HELLO" || response.Header().Get("X-Response") != "yes" {
		t.Fatal("Fetch lost request or response facts", response.Code, response.Body.String(), response.Header())
	}
	if cookies := response.Header().Values("Set-Cookie"); len(cookies) != 2 || cookies[0] != "a=1; Expires=Wed, 21 Oct 2037 07:28:00 GMT" || cookies[1] != "b=2" {
		t.Fatal("Fetch collapsed cookies", cookies)
	}
}

func TestPublisherFetchHeadJoinsCancel(t *testing.T) {
	state := publisherFunction(t, `(() => {
		let cancelResolve, finish;
		return {
			canceling: new Promise(r => cancelResolve = r),
			finish() {finish()},
			fetch: request => new Response(new ReadableStream({
				cancel() {cancelResolve(); return new Promise(r => finish = r)}
			}, {highWaterMark:0}))
		};
	})()`)
	handler, err := newPublisherFetchHandler(state.Get("fetch"))
	if err != nil {
		t.Fatal(err)
	}
	defer handler.Close()
	done := make(chan error, 1)
	go func() {
		_, err := handler.serve(t.Context(), httptest.NewRecorder(), httptest.NewRequest(http.MethodHead, "https://preview.example.test/", nil))
		done <- err
	}()
	if _, err := publisherAwait(t.Context(), state.Get("canceling"), nil); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		t.Fatal("HEAD returned before response cancellation joined", err)
	default:
	}
	state.Call("finish")
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

type publisherObservedBody struct {
	io.Reader
	mu     sync.Mutex
	reads  int
	max    int
	closed bool
}

func (b *publisherObservedBody) Read(p []byte) (int, error) {
	b.mu.Lock()
	b.reads++
	b.max = max(b.max, len(p))
	b.mu.Unlock()
	return b.Reader.Read(p)
}

func (b *publisherObservedBody) Close() error {
	b.mu.Lock()
	b.closed = true
	b.mu.Unlock()
	return nil
}

func TestPublisherFetchDoesNotReadUnconsumedRequest(t *testing.T) {
	handler := publisherTestHandler(t, `request => new Response("early")`)
	body := &publisherObservedBody{Reader: strings.NewReader("not consumed")}
	request := httptest.NewRequest(http.MethodPost, "https://preview.example.test/", body)
	request.Body = body
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != 200 || response.Body.String() != "early" || body.reads != 0 || !body.closed {
		t.Fatal("Fetch prefetched an unread body or failed to close it", body.reads, body.closed)
	}
}

func TestPublisherFetchStreamsLargeBodiesInBoundedCopies(t *testing.T) {
	handler := publisherTestHandler(t, `async request => new Response(request.body)`)
	input := bytes.Repeat([]byte("x"), 3*publisherChunkSize+7)
	body := &publisherObservedBody{Reader: bytes.NewReader(input)}
	request := httptest.NewRequest(http.MethodPost, "https://preview.example.test/", body)
	request.Body = body
	response := &publisherBoundedWriter{ResponseRecorder: httptest.NewRecorder()}
	handler.ServeHTTP(response, request)
	if !bytes.Equal(response.Body.Bytes(), input) || body.max > publisherChunkSize || response.max > publisherChunkSize || !body.closed {
		t.Fatal("Fetch buffered or changed streamed data", body.max, response.max, body.closed)
	}
	// a string Response can deliver a single large host chunk; go still copies
	// it in fixed-size writes without reading another response chunk ahead.
	handler = publisherTestHandler(t, `request => new Response("x".repeat(196615))`)
	response = &publisherBoundedWriter{ResponseRecorder: httptest.NewRecorder()}
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "https://preview.example.test/", nil))
	if !bytes.Equal(response.Body.Bytes(), input) || response.max > publisherChunkSize {
		t.Fatal("large host response bypassed bounded writes", response.max)
	}
}

type publisherBoundedWriter struct {
	*httptest.ResponseRecorder
	max int
}

func (w *publisherBoundedWriter) Write(p []byte) (int, error) {
	w.max = max(w.max, len(p))
	return w.ResponseRecorder.Write(p)
}

type publisherGatedWriter struct {
	*httptest.ResponseRecorder
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func (w *publisherGatedWriter) Write(p []byte) (int, error) {
	w.once.Do(func() { close(w.entered); <-w.release })
	return w.ResponseRecorder.Write(p)
}

func TestPublisherFetchResponseBackpressure(t *testing.T) {
	state := publisherFunction(t, `(() => {
		let pulls = 0;
		return {get pulls() {return pulls}, fetch: request => new Response(new ReadableStream({
			pull(controller) {
				pulls++;
				if (pulls === 3) controller.close();
				else controller.enqueue(new Uint8Array([pulls]));
			}
		}, {highWaterMark: 0}))};
	})()`)
	handler, err := newPublisherFetchHandler(state.Get("fetch"))
	if err != nil {
		t.Fatal(err)
	}
	defer handler.Close()
	writer := &publisherGatedWriter{ResponseRecorder: httptest.NewRecorder(), entered: make(chan struct{}), release: make(chan struct{})}
	done := make(chan struct{})
	go func() {
		handler.ServeHTTP(writer, httptest.NewRequest(http.MethodGet, "https://preview.example.test/", nil))
		close(done)
	}()
	<-writer.entered
	if count := state.Get("pulls").Int(); count != 1 {
		t.Fatal("Fetch read another host chunk before visitor write completed", count)
	}
	close(writer.release)
	<-done
	if !bytes.Equal(writer.Body.Bytes(), []byte{1, 2}) {
		t.Fatal("Fetch changed response stream", writer.Body.Bytes())
	}
}

func TestPublisherFetchCancellationJoinsHandler(t *testing.T) {
	state := publisherFunction(t, `(() => {
		let resolve, enteredResolve, abortedResolve;
		const entered = new Promise(r => enteredResolve = r);
		const aborted = new Promise(r => abortedResolve = r);
		return {entered, aborted, finish() {resolve(new Response("late"))}, fetch: request => {
			enteredResolve();
			request.signal.addEventListener("abort", () => abortedResolve(), {once:true});
			return new Promise(r => resolve = r);
		}};
	})()`)
	handler, err := newPublisherFetchHandler(state.Get("fetch"))
	if err != nil {
		t.Fatal(err)
	}
	defer handler.Close()
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() {
		_, err := handler.serve(ctx, httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "https://preview.example.test/", nil))
		done <- err
	}()
	if _, err := publisherAwait(t.Context(), state.Get("entered"), nil); err != nil {
		t.Fatal(err)
	}
	cancel()
	if _, err := publisherAwait(t.Context(), state.Get("aborted"), nil); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		t.Fatal("Fetch returned before canceled handler settled", err)
	default:
	}
	state.Call("finish")
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatal("Fetch lost cancellation", err)
	}
}

func TestPublisherFetchCancellationJoinsOriginalReaderCancel(t *testing.T) {
	state := publisherFunction(t, `(() => {
		let readResolve, cancelResolve, finish;
		return {
			reading: new Promise(r => readResolve = r),
			canceling: new Promise(r => cancelResolve = r),
			finish() { finish() },
			fetch: request => new Response(new ReadableStream({
				pull() {readResolve(); return new Promise(() => {})},
				cancel() {cancelResolve(); return new Promise(r => finish = r)}
			}, {highWaterMark: 0}))
		};
	})()`)
	handler, err := newPublisherFetchHandler(state.Get("fetch"))
	if err != nil {
		t.Fatal(err)
	}
	defer handler.Close()
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() {
		_, err := handler.serve(ctx, httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "https://preview.example.test/", nil))
		done <- err
	}()
	if _, err := publisherAwait(t.Context(), state.Get("reading"), nil); err != nil {
		t.Fatal(err)
	}
	cancel()
	if _, err := publisherAwait(t.Context(), state.Get("canceling"), nil); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		t.Fatal("Fetch lost the original asynchronous cancel cleanup", err)
	default:
	}
	state.Call("finish")
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatal("Fetch lost response cancellation", err)
	}
}

type publisherBlockedBody struct {
	entered chan struct{}
	closed  chan struct{}
	exited  chan struct{}
	once    sync.Once
}

func (b *publisherBlockedBody) Read([]byte) (int, error) {
	close(b.entered)
	<-b.closed
	close(b.exited)
	return 0, io.ErrClosedPipe
}

func (b *publisherBlockedBody) Close() error {
	b.once.Do(func() { close(b.closed) })
	return nil
}

func TestPublisherFetchCloseJoinsBlockedRequestReadAndFencesNewRequests(t *testing.T) {
	handler := publisherTestHandler(t, `async request => {
		try { await request.text() } catch {}
		return new Response("stopped");
	}`)
	body := &publisherBlockedBody{entered: make(chan struct{}), closed: make(chan struct{}), exited: make(chan struct{})}
	request := httptest.NewRequest(http.MethodPost, "https://preview.example.test/", nil)
	request.Body, request.ContentLength = body, -1
	done := make(chan struct{})
	go func() {
		handler.ServeHTTP(httptest.NewRecorder(), request)
		close(done)
	}()
	<-body.entered
	if err := handler.Close(); err != nil {
		t.Fatal(err)
	}
	<-done
	select {
	case <-body.exited:
	default:
		t.Fatal("handler cleanup returned before the blocked body read joined")
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "https://preview.example.test/", nil))
	if response.Code != http.StatusServiceUnavailable {
		t.Fatal("closed handler admitted another application request", response.Code)
	}
}

func TestPublisherFetchRejectsUpgradesAndRedactsFailures(t *testing.T) {
	handler := publisherTestHandler(t, `request => {throw Error("private application content")}`)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "https://preview.example.test/", nil))
	if response.Code != 502 || strings.Contains(response.Body.String(), "private") {
		t.Fatal("Fetch exposed handler error content", response.Code, response.Body.String())
	}
	request := httptest.NewRequest(http.MethodGet, "https://preview.example.test/", nil)
	request.Header.Set("Upgrade", "websocket")
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusNotImplemented {
		t.Fatal("Fetch attempted a socket upgrade", response.Code)
	}
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "https://preview.example.test/", strings.NewReader("not representable by Request")))
	if response.Code != http.StatusNotImplemented {
		t.Fatal("Fetch silently discarded a GET request body", response.Code)
	}
}

func TestPublisherFetchBoundsHeadersBeforeCommitting(t *testing.T) {
	handler := publisherTestHandler(t, `request => new Response("not sent", {
		headers: {"x-too-large": "x".repeat(65536), "content-length": "8"}
	})`)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "https://preview.example.test/", nil))
	if response.Code != http.StatusBadGateway || response.Header().Get("X-Too-Large") != "" {
		t.Fatal("Fetch committed an oversized or partially copied header block", response.Code)
	}
}

func TestPublisherFetchRedactsThrowingResponseGetter(t *testing.T) {
	handler := publisherTestHandler(t, `request => {
		const response = new Response("not sent");
		Object.defineProperty(response, "headers", {get() {throw Error("private response configuration")}});
		return response;
	}`)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "https://preview.example.test/", nil))
	if response.Code != http.StatusBadGateway || strings.Contains(response.Body.String(), "private") {
		t.Fatal("response getter escaped the host failure boundary", response.Code, response.Body.String())
	}
}

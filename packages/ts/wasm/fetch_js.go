//go:build js && wasm

package main

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"syscall/js"

	connectorstream "github.com/tnldotdev/tnl/internal/connector/stream"
)

// fetchTransport uses a request-owned Fetch function. it is independent of
// net/http's Node detection and never opens a host TCP listener or dialer.
type fetchTransport struct{ fetch js.Value }

func (t *fetchTransport) RoundTrip(request *http.Request) (_ *http.Response, result error) {
	defer func() {
		if recover() != nil {
			result = errArguments
		}
	}()
	if request.URL == nil || request.URL.Scheme != "https" && request.URL.Scheme != "http" {
		return nil, errArguments
	}
	controller := js.Global().Get("AbortController").New()
	// only this exact reason object proves that this request's abort rejected
	// Fetch. error names/messages cannot distinguish a raced independent failure.
	abortReason := js.Global().Get("Object").New()
	abort := func() { controller.Call("abort", abortReason) }
	done := make(chan struct{})
	stopAbort := context.AfterFunc(request.Context(), func() { defer close(done); abort() })
	var stopOnce sync.Once
	stop := func() {
		stopOnce.Do(func() {
			abort()
			if !stopAbort() {
				<-done
			}
		})
	}
	owned := false
	defer func() {
		if !owned {
			stop()
		}
	}()
	headers := js.Global().Get("Headers").New()
	for name, values := range request.Header {
		if strings.HasPrefix(strings.ToLower(name), "js.fetch:") {
			continue
		}
		for _, value := range values {
			headers.Call("append", name, value)
		}
	}
	options := map[string]any{
		"method": request.Method, "headers": headers, "signal": controller.Get("signal"),
		"redirect": "manual", "credentials": "omit",
	}
	if request.Body != nil {
		data, err := io.ReadAll(io.LimitReader(request.Body, chunkBytes+1))
		closeErr := request.Body.Close()
		if err != nil || closeErr != nil {
			return nil, errors.Join(err, closeErr)
		}
		if len(data) > chunkBytes {
			return nil, errCapacity
		}
		options["body"] = jsBytes(data)
	}
	value, err := invoke(t.fetch, js.Global().Get("Request").New(request.URL.String(), options))
	if err != nil {
		return nil, err
	}
	response, ownedAbort, err := awaitWithAbort(value, abortReason)
	if err != nil {
		cause := context.Cause(request.Context())
		if ownedAbort && cause != nil {
			return nil, cause
		}
		return nil, errors.Join(err, cause)
	}
	status := bridgeGet(response, "status")
	if bridgeGet(response, "type").Type() == js.TypeString && bridgeGet(response, "type").String() == "opaqueredirect" ||
		bridgeGet(response, "redirected").Type() == js.TypeBoolean && bridgeGet(response, "redirected").Bool() ||
		status.Type() == js.TypeNumber && status.Int() >= 300 && status.Int() < 400 {
		return nil, errors.New("WASM control redirects are not permitted")
	}
	if status.Type() != js.TypeNumber || status.Int() < 100 || status.Int() > 599 {
		return nil, errArguments
	}
	header, err := readHeaders(bridgeGet(response, "headers"))
	if err != nil {
		return nil, err
	}
	body, err := newJSReader(bridgeGet(response, "body"), stop)
	if err != nil {
		return nil, err
	}
	owned = true
	contentLength := int64(-1)
	if raw := header.Get("Content-Length"); raw != "" {
		if parsed, err := strconv.ParseInt(raw, 10, 64); err == nil && parsed >= 0 {
			contentLength = parsed
		}
	}
	return &http.Response{
		StatusCode: status.Int(), Status: strconv.Itoa(status.Int()) + " " + http.StatusText(status.Int()),
		Header: header, Body: body, ContentLength: contentLength, Request: request,
		Proto: "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1,
	}, nil
}

func invoke(fn js.Value, args ...any) (value js.Value, err error) {
	defer func() {
		if recover() != nil {
			err = errors.New("WASM host call failed")
		}
	}()
	return fn.Invoke(args...), nil
}
func bridgeCall(value js.Value, name string, args ...any) (result js.Value, err error) {
	defer func() {
		if recover() != nil {
			err = errArguments
		}
	}()
	return value.Call(name, args...), nil
}
func await(value js.Value) (result js.Value, err error) {
	result, _, err = awaitWithAbort(value, js.Undefined())
	return result, err
}

func awaitWithAbort(value, abortReason js.Value) (result js.Value, ownedAbort bool, err error) {
	defer func() {
		if recover() != nil {
			err = errArguments
		}
	}()
	if value.Type() != js.TypeObject || value.IsNull() || bridgeGet(value, "then").Type() != js.TypeFunction {
		return value, false, nil
	}
	done := make(chan struct{})
	var once sync.Once
	success := js.FuncOf(func(_ js.Value, args []js.Value) any {
		once.Do(func() {
			if len(args) > 0 {
				result = args[0]
			}
			close(done)
		})
		return nil
	})
	failed := js.FuncOf(func(_ js.Value, args []js.Value) any {
		once.Do(func() {
			ownedAbort = abortReason.Type() == js.TypeObject && !abortReason.IsNull() && len(args) > 0 && args[0].Equal(abortReason)
			err = errors.New("WASM host operation failed")
			close(done)
		})
		return nil
	})
	defer success.Release()
	defer failed.Release()
	value.Call("then", success, failed)
	<-done
	return result, ownedAbort, err
}
func readHeaders(value js.Value) (http.Header, error) {
	if value.Type() != js.TypeObject || bridgeGet(value, "forEach").Type() != js.TypeFunction {
		return nil, errArguments
	}
	header := http.Header{}
	size := 0
	invalid := false
	callback := js.FuncOf(func(_ js.Value, args []js.Value) any {
		if len(args) < 2 || args[0].Type() != js.TypeString || args[1].Type() != js.TypeString {
			invalid = true
			return nil
		}
		name, content := args[1].String(), args[0].String()
		size += len(name) + len(content)
		if size > chunkBytes {
			invalid = true
			return nil
		}
		header.Add(name, content)
		return nil
	})
	defer callback.Release()
	value.Call("forEach", callback)
	if invalid {
		return nil, errArguments
	}
	return header, nil
}

// jsReader copies at most one bounded chunk into Go, even if the host emits a
// larger chunk. closing cancels the source and joins an entered read callback.
type jsReader struct {
	reader  js.Value
	pending js.Value
	offset  int
	readMu  sync.Mutex
	mu      sync.Mutex
	closed  bool
	once    sync.Once
	err     error
	stop    func()
}

func newJSReader(body js.Value, stop func()) (*jsReader, error) {
	r := &jsReader{reader: js.Undefined(), pending: js.Undefined(), stop: stop}
	if body.IsNull() || body.IsUndefined() {
		return r, nil
	}
	if body.Type() != js.TypeObject || bridgeGet(body, "getReader").Type() != js.TypeFunction {
		return nil, errArguments
	}
	r.reader = body.Call("getReader")
	return r, nil
}
func (r *jsReader) Read(data []byte) (count int, result error) {
	defer func() {
		if recover() != nil {
			count, result = 0, errArguments
		}
	}()
	if len(data) == 0 {
		return 0, nil
	}
	r.readMu.Lock()
	defer r.readMu.Unlock()
	r.mu.Lock()
	closed := r.closed
	r.mu.Unlock()
	if closed {
		return 0, io.ErrClosedPipe
	}
	if r.reader.IsUndefined() {
		return 0, io.EOF
	}
	for r.pending.IsUndefined() || r.offset >= bridgeByteLength(r.pending) {
		result, err := await(r.reader.Call("read"))
		if err != nil {
			return 0, err
		}
		if bridgeGet(result, "done").Bool() {
			return 0, io.EOF
		}
		value := bridgeGet(result, "value")
		if !isBytes(value) {
			return 0, errArguments
		}
		r.pending, r.offset = value, 0
		if bridgeByteLength(value) == 0 {
			continue
		}
	}
	n := min(len(data), chunkBytes, bridgeByteLength(r.pending)-r.offset)
	js.CopyBytesToGo(data[:n], bridgeSubarray(r.pending, r.offset, r.offset+n))
	r.offset += n
	if r.offset == bridgeByteLength(r.pending) {
		r.pending = js.Undefined()
		r.offset = 0
	}
	return n, nil
}
func (r *jsReader) Close() error {
	r.once.Do(func() {
		r.mu.Lock()
		r.closed = true
		r.mu.Unlock()
		if r.stop != nil {
			r.stop()
		}
		if !r.reader.IsUndefined() {
			cancel, callErr := bridgeCall(r.reader, "cancel")
			if callErr == nil {
				_, r.err = await(cancel)
			} else {
				r.err = callErr
			}
			r.readMu.Lock()
			func() {
				defer r.readMu.Unlock()
				_, err := bridgeCall(r.reader, "releaseLock")
				r.err = errors.Join(r.err, err)
				r.pending = js.Undefined()
			}()
		}
	})
	return r.err
}

// request upload cancellation must interrupt the reader independently of the
// HTTP write worker that may be waiting for it. Close joins both that callback
// and the original reader's read/cancel promises before returning its result.
type jsRequestBody struct {
	*jsReader
	stop   func() bool
	done   chan struct{}
	joined chan struct{}
	once   sync.Once
	err    error
}

func newJSRequestBody(ctx context.Context, source js.Value) (*jsRequestBody, error) {
	reader, err := newJSReader(source, nil)
	if err != nil {
		return nil, err
	}
	body := &jsRequestBody{jsReader: reader, done: make(chan struct{}), joined: make(chan struct{})}
	body.stop = context.AfterFunc(ctx, func() { defer close(body.done); _ = reader.Close() })
	return body, nil
}

func (b *jsRequestBody) Close() error {
	b.once.Do(func() {
		stopped := b.stop()
		err := b.jsReader.Close()
		if !stopped {
			<-b.done
		}
		if err != nil {
			b.err = &connectorstream.CleanupError{Err: err}
		}
		close(b.joined)
	})
	return b.err
}

func (h *connectionHandle) fetch(args []js.Value) (_ any, result error) {
	if len(args) < 1 || len(args) > 2 || args[0].Type() != js.TypeObject {
		return nil, errArguments
	}
	if err := h.enter(); err != nil {
		return nil, err
	}
	defer h.pending.Done()
	ctx, stop, err := signalContext(h.connection.Context(), argumentSignal(args, 1))
	if err != nil {
		return nil, err
	}
	owned := false
	defer func() {
		if !owned {
			stop()
		}
	}()
	input := args[0]
	if bridgeGet(input, "url").Type() != js.TypeString || bridgeGet(input, "method").Type() != js.TypeString {
		return nil, errArguments
	}
	headers, err := readHeaders(bridgeGet(input, "headers"))
	if err != nil {
		return nil, err
	}
	body, err := newJSRequestBody(ctx, bridgeGet(input, "body"))
	if err != nil {
		return nil, err
	}
	defer func() {
		if body != nil {
			result = errors.Join(result, body.Close())
		}
	}()
	request, err := http.NewRequestWithContext(ctx, bridgeGet(input, "method").String(), bridgeGet(input, "url").String(), body)
	if err != nil {
		return nil, errArguments
	}
	if bridgeGet(input, "body").IsNull() {
		request.Body = nil
	}
	request.Header = headers
	response, err := h.connection.Fetch(request)
	var bodyErr error
	if err != nil {
		bodyErr = body.Close()
	} else {
		select {
		case <-body.joined:
			bodyErr = body.err
		default:
		}
	}
	if err != nil || bodyErr != nil {
		body = nil
		if response != nil && response.Body != nil {
			if closeErr := response.Body.Close(); closeErr != nil {
				bodyErr = errors.Join(bodyErr, &connectorstream.CleanupError{Err: closeErr})
			}
		}
		return nil, operationError(ctx, errors.Join(err, bodyErr))
	}
	// net/http owns request-body closure after RoundTrip, including streaming
	// bodies. response ownership below keeps cancellation attached until EOF.
	// response headers can arrive before the HTTP writer finishes its upload.
	// retain that body until transport closure or joined response cleanup.
	output := &responseBody{owner: h, body: response.Body, upload: body, stop: stop}
	body = nil
	h.mu.Lock()
	closed := h.closed
	if !closed {
		h.bodies[output] = struct{}{}
	}
	h.mu.Unlock()
	if closed {
		return nil, errors.Join(context.Canceled, output.close())
	}
	value, err := output.export(response, request.Method)
	if err != nil {
		return nil, errors.Join(err, output.close())
	}
	owned = true
	return value, nil
}

type responseBody struct {
	owner   *connectionHandle
	body    io.ReadCloser
	upload  *jsRequestBody
	stop    func()
	methods methodSet
	readMu  sync.Mutex
	once    sync.Once
	err     error
}

func (b *responseBody) export(response *http.Response, method string) (js.Value, error) {
	headers := js.Global().Get("Headers").New()
	for name, values := range response.Header {
		for _, value := range values {
			headers.Call("append", name, value)
		}
	}
	options := map[string]any{"status": response.StatusCode, "headers": headers}
	if method == http.MethodHead || response.StatusCode == 204 || response.StatusCode == 205 || response.StatusCode == 304 {
		if err := b.close(); err != nil {
			return js.Undefined(), err
		}
		return js.Global().Get("Response").New(js.Null(), options), nil
	}
	source := js.Global().Get("Object").New()
	bind(source, "pull", &b.methods, func(args []js.Value) (any, error) {
		if len(args) != 1 {
			return nil, errArguments
		}
		b.readMu.Lock()
		defer b.readMu.Unlock()
		controller := args[0]
		data := make([]byte, chunkBytes)
		n, err := b.body.Read(data)
		if n > 0 {
			controller.Call("enqueue", jsBytes(data[:n]))
		}
		if err == io.EOF {
			if closeErr := b.close(); closeErr != nil {
				controller.Call("error", safeError(closeErr))
				return nil, closeErr
			}
			controller.Call("close")
			return nil, nil
		}
		if err != nil {
			controller.Call("error", safeError(err))
			return nil, errors.Join(err, b.close())
		}
		return nil, nil
	})
	bind(source, "cancel", &b.methods, func([]js.Value) (any, error) { return nil, b.close() })
	stream := js.Global().Get("ReadableStream").New(source, map[string]any{"highWaterMark": 0})
	return js.Global().Get("Response").New(stream, options), nil
}
func (b *responseBody) close() error {
	b.once.Do(func() {
		b.stop()
		b.err = b.body.Close()
		if b.upload != nil {
			b.err = errors.Join(b.err, b.upload.Close())
		}
		b.methods.retire()
		b.owner.mu.Lock()
		delete(b.owner.bodies, b)
		b.owner.mu.Unlock()
	})
	return b.err
}

var _ http.RoundTripper = (*fetchTransport)(nil)
var _ io.ReadCloser = (*jsReader)(nil)

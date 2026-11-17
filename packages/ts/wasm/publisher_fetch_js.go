//go:build js && wasm

package main

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"syscall/js"
)

const publisherChunkSize = 64 << 10

var errPublisherHost = errors.New("publisher host operation failed")

// publisherPromise never blocks a javascript callback on a go operation.
func publisherPromise(work func() (js.Value, error)) js.Value {
	executor := js.FuncOf(func(_ js.Value, args []js.Value) any {
		resolve, reject := args[0], args[1]
		go func() {
			value, err := publisherWork(work)
			if err != nil {
				reject.Invoke(js.Global().Get("Error").New("publisher host operation failed"))
			} else {
				resolve.Invoke(value)
			}
		}()
		return nil
	})
	defer executor.Release()
	return js.Global().Get("Promise").New(executor)
}

func publisherWork(work func() (js.Value, error)) (value js.Value, err error) {
	defer func() {
		if recover() != nil {
			value, err = js.Undefined(), errPublisherHost
		}
	}()
	return work()
}

func publisherJS(work func() js.Value) (value js.Value, err error) {
	defer func() {
		if recover() != nil {
			value, err = js.Undefined(), errPublisherHost
		}
	}()
	return work(), nil
}

// Value.Get does not trap javascript getter exceptions. Reflect.get through
// Value.Call does, so a host getter cannot escape redaction or wasm cleanup.
func publisherGet(object js.Value, key string) js.Value {
	return js.Global().Get("Reflect").Call("get", object, key)
}

// cancellation interrupts the host operation, then joins its actual settlement.
// callbacks remain registered until that settlement; cancellation alone is not
// proof that javascript stopped using a request or a response reader.
func publisherAwait(ctx context.Context, value js.Value, interrupt func()) (js.Value, error) {
	type result struct {
		value js.Value
		err   error
	}
	done := make(chan result, 1)
	resolved := js.FuncOf(func(_ js.Value, args []js.Value) any {
		v := js.Undefined()
		if len(args) != 0 {
			v = args[0]
		}
		done <- result{value: v}
		return nil
	})
	rejected := js.FuncOf(func(js.Value, []js.Value) any {
		// host errors can contain request headers, credentials, or application
		// data. expose a stable boundary error instead of their message.
		done <- result{err: errPublisherHost}
		return nil
	})
	defer resolved.Release()
	defer rejected.Release()
	if _, err := publisherJS(func() js.Value {
		return js.Global().Get("Promise").Call("resolve", value).Call("then", resolved, rejected)
	}); err != nil {
		return js.Undefined(), err
	}
	select {
	case r := <-done:
		return r.value, r.err
	case <-ctx.Done():
		if interrupt != nil {
			interrupt()
		}
		r := <-done
		return r.value, errors.Join(context.Cause(ctx), r.err)
	}
}

type publisherFetchHandler struct {
	fetch  js.Value
	ctx    context.Context
	cancel context.CancelFunc
	mu     sync.Mutex
	closed bool
	active sync.WaitGroup
}

func newPublisherFetchHandler(fetch js.Value) (*publisherFetchHandler, error) {
	if fetch.Type() != js.TypeFunction {
		return nil, errPublisherHost
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &publisherFetchHandler{fetch: fetch, ctx: ctx, cancel: cancel}, nil
}

// close fences new requests, aborts admitted handlers, and joins their body
// readers and response cleanup. the service run remains the publication owner.
func (h *publisherFetchHandler) Close() error {
	h.stop()
	h.active.Wait()
	return nil
}

func (h *publisherFetchHandler) stop() {
	h.mu.Lock()
	h.closed = true
	h.cancel()
	h.mu.Unlock()
}

func (h *publisherFetchHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.mu.Lock()
	if h.closed {
		h.mu.Unlock()
		http.Error(w, "publisher stopped", http.StatusServiceUnavailable)
		return
	}
	h.active.Add(1)
	h.mu.Unlock()
	defer h.active.Done()
	if r.Method == http.MethodConnect || r.Header.Get("Upgrade") != "" {
		http.Error(w, "Fetch handlers do not support socket upgrades", http.StatusNotImplemented)
		return
	}
	if (r.Method == http.MethodGet || r.Method == http.MethodHead) && r.Body != nil && r.Body != http.NoBody && r.ContentLength != 0 {
		http.Error(w, "Fetch handlers do not support GET or HEAD request bodies", http.StatusNotImplemented)
		return
	}
	ctx, cancel := context.WithCancel(r.Context())
	stop := context.AfterFunc(h.ctx, cancel)
	defer stop()
	defer cancel()
	committed, err := h.serve(ctx, w, r)
	if err != nil {
		if committed {
			// net/http closes this response without turning a truncated body
			// into an apparently complete application response.
			panic(http.ErrAbortHandler)
		}
		http.Error(w, "Fetch handler failed", http.StatusBadGateway)
	}
}

func (h *publisherFetchHandler) serve(ctx context.Context, w http.ResponseWriter, r *http.Request) (committed bool, result error) {
	defer func() {
		if recover() != nil {
			result = errors.Join(result, errPublisherHost)
		}
	}()
	abort, err := publisherJS(func() js.Value { return js.Global().Get("AbortController").New() })
	if err != nil {
		return false, err
	}
	interrupt := func() {
		_, _ = publisherJS(func() js.Value { return abort.Call("abort") })
	}
	request, closeRequest, err := publisherRequest(ctx, r, abort.Get("signal"))
	if err != nil {
		return false, err
	}
	defer func() {
		interrupt()
		result = errors.Join(result, closeRequest())
	}()
	pending, err := publisherJS(func() js.Value { return h.fetch.Invoke(request) })
	if err != nil {
		return false, err
	}
	response, fetchErr := publisherAwait(ctx, pending, interrupt)
	if !response.InstanceOf(js.Global().Get("Response")) || publisherGet(response, "status").Int() < 200 || publisherGet(response, "status").Int() > 599 {
		return false, errors.Join(fetchErr, errPublisherHost)
	}
	body := publisherGet(response, "body")
	var reader js.Value
	complete := false
	cancelRead := interrupt
	var joinResponseCancel func() error
	if !body.IsNull() && !body.IsUndefined() {
		reader, err = publisherJS(func() js.Value { return body.Call("getReader") })
		if err != nil {
			return false, err
		}
		var cancelOnce sync.Once
		var cancelPromise js.Value
		var cancelErr error
		cancelResponse := func() {
			cancelOnce.Do(func() {
				cancelPromise, cancelErr = publisherJS(func() js.Value { return reader.Call("cancel") })
			})
		}
		joinResponseCancel = func() error {
			cancelResponse()
			if cancelErr == nil {
				_, cancelErr = publisherAwait(context.Background(), cancelPromise, nil)
			}
			return cancelErr
		}
		defer func() {
			if !complete {
				result = errors.Join(result, joinResponseCancel())
			}
			_, err := publisherJS(func() js.Value { return reader.Call("releaseLock") })
			result = errors.Join(result, err)
		}()
		// aborting a pending read must also retain the original cancellation
		// promise, not a second cancel() that can resolve before host cleanup.
		cancelRead = func() {
			interrupt()
			cancelResponse()
		}
	}
	if fetchErr != nil {
		return false, fetchErr
	}
	if err := context.Cause(ctx); err != nil {
		return false, err
	}
	if err := publisherResponseHeaders(w.Header(), publisherGet(response, "headers")); err != nil {
		return false, err
	}
	w.WriteHeader(publisherGet(response, "status").Int())
	committed = true
	if body.IsNull() || body.IsUndefined() {
		return committed, nil
	}
	if r.Method == http.MethodHead {
		// HEAD never copies a response body, but still joins its cancellation.
		err := joinResponseCancel()
		complete = err == nil
		return committed, err
	}
	buffer := make([]byte, publisherChunkSize)
	for {
		if err := context.Cause(ctx); err != nil {
			return committed, err
		}
		pending, err := publisherJS(func() js.Value { return reader.Call("read") })
		if err != nil {
			return committed, err
		}
		chunk, err := publisherAwait(ctx, pending, cancelRead)
		if err != nil {
			return committed, err
		}
		if publisherGet(chunk, "done").Bool() {
			complete = true
			return committed, nil
		}
		data := publisherGet(chunk, "value")
		if !data.InstanceOf(js.Global().Get("Uint8Array")) {
			return committed, errPublisherHost
		}
		length := publisherGet(data, "byteLength").Float()
		if length < 0 || length > float64(^uint(0)>>1) || float64(int(length)) != length {
			return committed, errPublisherHost
		}
		// one host chunk may be larger than the copy buffer (for example a
		// Response made from a string). split it without another host read or
		// an unbounded go allocation; each write applies visitor backpressure.
		for offset, size := 0, int(length); offset < size; {
			end := min(offset+len(buffer), size)
			n := js.CopyBytesToGo(buffer, data.Call("subarray", offset, end))
			if n != end-offset {
				return committed, errPublisherHost
			}
			written, err := w.Write(buffer[:n])
			if err != nil {
				return committed, err
			}
			if written != n {
				return committed, io.ErrShortWrite
			}
			if err := http.NewResponseController(w).Flush(); err != nil && !errors.Is(err, http.ErrNotSupported) {
				return committed, err
			}
			offset = end
		}
	}
}

func publisherResponseHeaders(destination http.Header, source js.Value) error {
	headers := make(http.Header)
	size := 0
	invalid := false
	add := func(name, value string) {
		size += len(name) + len(value)
		if size > publisherChunkSize {
			invalid = true
			return
		}
		headers.Add(name, value)
	}
	each := js.FuncOf(func(_ js.Value, args []js.Value) any {
		if len(args) < 2 || args[0].Type() != js.TypeString || args[1].Type() != js.TypeString {
			invalid = true
			return nil
		}
		name := args[1].String()
		switch strings.ToLower(name) {
		case "connection", "keep-alive", "proxy-connection", "transfer-encoding", "upgrade", "trailer", "set-cookie":
			return nil
		}
		add(name, args[0].String())
		return nil
	})
	defer each.Release()
	_, err := publisherJS(func() js.Value {
		source.Call("forEach", each)
		// getSetCookie preserves separate cookies, including Expires commas.
		cookies := source.Call("getSetCookie")
		length := publisherGet(cookies, "length").Int()
		if length < 0 || length > publisherChunkSize {
			invalid = true
			return js.Undefined()
		}
		for i := 0; i < length; i++ {
			cookie := js.Global().Get("Reflect").Call("get", cookies, i)
			if cookie.Type() != js.TypeString {
				invalid = true
				return js.Undefined()
			}
			add("Set-Cookie", cookie.String())
		}
		return js.Undefined()
	})
	if err != nil {
		return err
	}
	if invalid {
		return errPublisherHost
	}
	for name, values := range headers {
		for _, value := range values {
			destination.Add(name, value)
		}
	}
	return nil
}

func publisherRequest(ctx context.Context, r *http.Request, signal js.Value) (js.Value, func() error, error) {
	// the service owner already authenticated and stripped visitor credentials.
	// construct the address from its admitted host, never forwarding headers.
	address := *r.URL
	address.Scheme, address.Host, address.User = "https", r.Host, nil
	if address.Host == "" || strings.ContainsAny(address.Host, "/\\?#@") {
		return js.Undefined(), nil, errPublisherHost
	}
	if _, err := url.ParseRequestURI(address.String()); err != nil {
		return js.Undefined(), nil, errPublisherHost
	}
	init := js.Global().Get("Object").New()
	init.Set("method", r.Method)
	init.Set("signal", signal)
	headers := js.Global().Get("Headers").New()
	headers.Call("append", "Host", r.Host)
	for name, values := range r.Header {
		for _, value := range values {
			headers.Call("append", name, value)
		}
	}
	init.Set("headers", headers)
	closeBody := func() error { return nil }
	if r.Body != nil && r.Body != http.NoBody && r.Method != http.MethodGet && r.Method != http.MethodHead {
		body, close, err := publisherRequestBody(ctx, r.Body)
		if err != nil {
			return js.Undefined(), nil, err
		}
		closeBody = close
		init.Set("body", body)
		init.Set("duplex", "half")
	}
	request, err := publisherJS(func() js.Value { return js.Global().Get("Request").New(address.String(), init) })
	if err != nil {
		return js.Undefined(), nil, errors.Join(err, closeBody())
	}
	// browsers filter Cookie and other forbidden request headers during Request
	// construction. the admitted application must still read its exact headers.
	// the host adapter preserves this same raw-header view when cloning.
	_, err = publisherJS(func() js.Value {
		descriptor := js.Global().Get("Object").New()
		descriptor.Set("value", headers)
		descriptor.Set("configurable", true)
		js.Global().Get("Object").Call("defineProperty", request, "headers", descriptor)
		return js.Undefined()
	})
	if err != nil {
		return js.Undefined(), nil, errors.Join(err, closeBody())
	}
	return request, closeBody, nil
}

func publisherRequestBody(ctx context.Context, body io.ReadCloser) (js.Value, func() error, error) {
	var controller js.Value
	var mu sync.Mutex
	var stopped bool
	var reads sync.WaitGroup
	var closeOnce sync.Once
	var closeErr error
	closeBody := func() error {
		closeOnce.Do(func() { closeErr = body.Close() })
		return closeErr
	}
	start := js.FuncOf(func(_ js.Value, args []js.Value) any {
		controller = args[0]
		return nil
	})
	pull := js.FuncOf(func(js.Value, []js.Value) any {
		mu.Lock()
		if stopped {
			mu.Unlock()
			return js.Undefined()
		}
		reads.Add(1)
		mu.Unlock()
		return publisherPromise(func() (js.Value, error) {
			defer reads.Done()
			buffer := make([]byte, publisherChunkSize)
			n, err := body.Read(buffer)
			mu.Lock()
			defer mu.Unlock()
			if stopped {
				return js.Undefined(), nil
			}
			if n > 0 {
				array := js.Global().Get("Uint8Array").New(n)
				js.CopyBytesToJS(array, buffer[:n])
				controller.Call("enqueue", array)
			}
			if errors.Is(err, io.EOF) {
				controller.Call("close")
				return js.Undefined(), nil
			}
			if err != nil {
				return js.Undefined(), errPublisherHost
			}
			return js.Undefined(), nil
		})
	})
	cancel := js.FuncOf(func(js.Value, []js.Value) any {
		mu.Lock()
		stopped = true
		mu.Unlock()
		return publisherPromise(func() (js.Value, error) {
			err := closeBody()
			reads.Wait()
			return js.Undefined(), err
		})
	})
	source := js.Global().Get("Object").New()
	source.Set("start", start)
	source.Set("pull", pull)
	source.Set("cancel", cancel)
	strategy := js.Global().Get("Object").New()
	strategy.Set("highWaterMark", 0)
	stream, err := publisherJS(func() js.Value { return js.Global().Get("ReadableStream").New(source, strategy) })
	start.Release()
	if err != nil {
		pull.Release()
		cancel.Release()
		return js.Undefined(), nil, errors.Join(err, closeBody())
	}
	var finishOnce sync.Once
	finish := func() error {
		finishOnce.Do(func() {
			mu.Lock()
			stopped = true
			_, _ = publisherJS(func() js.Value {
				return controller.Call("error", js.Global().Get("Error").New("request body closed"))
			})
			mu.Unlock()
			_ = closeBody()
			reads.Wait()
			pull.Release()
			cancel.Release()
		})
		return closeErr
	}
	interrupt := context.AfterFunc(ctx, func() { _ = finish() })
	return stream, func() error { interrupt(); return finish() }, nil
}

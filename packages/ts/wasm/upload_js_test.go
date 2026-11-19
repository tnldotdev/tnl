//go:build js && wasm

package main

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"syscall/js"
	"testing"
	"time"

	connectorsession "github.com/tnldotdev/tnl/internal/connector/session"
	connectorstream "github.com/tnldotdev/tnl/internal/connector/stream"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

// this fixture retains net/http's actual Go read/write workers over an in-memory
// admitted-connection stand-in. TLS and admission are proved at their own owners.
type uploadConnection struct {
	ctx        context.Context
	cancel     context.CancelFunc
	transport  *http.Transport
	serverDone chan struct{}
}

func (c *uploadConnection) Context() context.Context         { return c.ctx }
func (*uploadConnection) Metadata() controlv1.ServiceSummary { return controlv1.ServiceSummary{} }
func (*uploadConnection) Open(context.Context) (*connectorsession.Conn, error) {
	return nil, errors.ErrUnsupported
}
func (c *uploadConnection) Fetch(request *http.Request) (*http.Response, error) {
	return c.transport.RoundTrip(request)
}
func (c *uploadConnection) Close() error {
	c.cancel()
	c.transport.CloseIdleConnections()
	<-c.serverDone
	return nil
}

func deferredJSPromise() (promise, resolve, reject js.Value) {
	executor := js.FuncOf(func(_ js.Value, args []js.Value) any { resolve, reject = args[0], args[1]; return nil })
	defer executor.Release()
	return js.Global().Get("Promise").New(executor), resolve, reject
}

func TestResponseHeadersDoNotCloseAnUnfinishedUpload(t *testing.T) {
	for _, stop := range []bool{false, true} {
		name := "echo"
		if stop {
			name = "deployment close"
		}
		t.Run(name, func(t *testing.T) { testResponseHeadersUpload(t, stop) })
	}
}

func testResponseHeadersUpload(t *testing.T, stop bool) {
	ctx, cancel := context.WithCancel(t.Context())
	client, server := net.Pipe()
	connection := &uploadConnection{ctx: ctx, cancel: cancel, serverDone: make(chan struct{})}
	connection.transport = &http.Transport{DialTLSContext: func(context.Context, string, string) (net.Conn, error) { return client, nil }}
	go func() {
		defer close(connection.serverDone)
		defer server.Close()
		request, err := http.ReadRequest(bufio.NewReader(server))
		if err == nil {
			// return headers before the request body finishes, then echo each
			// incoming byte through the actual HTTP transport's response body.
			response := &http.Response{
				StatusCode: http.StatusOK, ProtoMajor: 1, ProtoMinor: 1,
				Header: make(http.Header), Body: request.Body, ContentLength: -1,
				TransferEncoding: []string{"chunked"},
			}
			_ = response.Write(server)
			_ = request.Body.Close()
		}
	}()
	owner := &deploymentHandle{ctx: ctx, stop: cancel, connections: map[*connectionHandle]struct{}{}, bindings: map[string]*connectionHandle{}}
	handle := &connectionHandle{owner: owner, connection: connection, stop: cancel, name: "web", streams: map[*streamHandle]struct{}{}, bodies: map[*responseBody]struct{}{}}
	owner.connections[handle], owner.bindings["web"] = struct{}{}, handle
	first := []byte("first\n")
	last := bytes.Repeat([]byte("x"), 2*chunkBytes+7)
	var controller js.Value
	pulled, canceled := false, false
	firstPull := make(chan struct{})
	pull := js.FuncOf(func(_ js.Value, args []js.Value) any {
		controller = args[0]
		if !pulled {
			pulled = true
			controller.Call("enqueue", jsBytes(first))
			close(firstPull)
		}
		return nil
	})
	cancelUpload := js.FuncOf(func(js.Value, []js.Value) any { canceled = true; return nil })
	defer func() {
		cancel()
		_ = client.Close()
		_ = server.Close()
		_ = owner.close()
		pull.Release()
		cancelUpload.Release()
	}()
	source := js.Global().Get("Object").New()
	source.Set("pull", pull)
	source.Set("cancel", cancelUpload)
	stream := js.Global().Get("ReadableStream").New(source, map[string]any{"highWaterMark": 0})
	input := js.Global().Get("Request").New("https://service.example.test/upload", map[string]any{
		"method": "POST", "body": stream, "duplex": "half",
	})
	type result struct {
		response any
		err      error
	}
	fetched := make(chan result, 1)
	go func() { response, err := handle.fetch([]js.Value{input}); fetched <- result{response, err} }()
	var response js.Value
	select {
	case result := <-fetched:
		if result.err != nil {
			t.Fatal("headers failed before upload completed", result.err)
		}
		response = result.response.(js.Value)
	case <-time.After(5 * time.Second):
		t.Fatal("fetch waited for the entire upload before returning response headers")
	}
	if canceled {
		t.Fatal("returning response headers canceled an unfinished request body")
	}
	select {
	case <-firstPull:
	case <-time.After(5 * time.Second):
		t.Fatal("HTTP writer did not start the request body after response headers")
	}
	if stop {
		closed := make(chan error, 1)
		go func() { closed <- owner.close() }()
		select {
		case err := <-closed:
			if err != nil {
				t.Fatal("deployment close lost clean upload cancellation", err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("deployment close did not join the unfinished upload")
		}
		if !canceled {
			t.Fatal("deployment close left the host upload alive")
		}
		return
	}
	controller.Call("enqueue", jsBytes(last))
	controller.Call("close")
	body, err := await(response.Call("arrayBuffer"))
	if err != nil {
		t.Fatal("echoed upload failed", err)
	}
	array := js.Global().Get("Uint8Array").New(body)
	got := make([]byte, array.Get("byteLength").Int())
	js.CopyBytesToGo(got, array)
	if !bytes.Equal(got, append(first, last...)) {
		t.Fatal("response headers truncated the streamed upload", len(got))
	}
}

type responseCleanupFailure struct {
	io.Reader
	err error
}

func (b responseCleanupFailure) Close() error { return b.err }

func TestResponseEOFDoesNotHideCleanupFailure(t *testing.T) {
	cleanup := errors.New("private response cleanup sentinel")
	owner := &connectionHandle{bodies: make(map[*responseBody]struct{})}
	body := &responseBody{
		owner: owner, stop: func() {},
		body: responseCleanupFailure{Reader: strings.NewReader(""), err: cleanup},
	}
	owner.bodies[body] = struct{}{}
	response, err := body.export(&http.Response{StatusCode: http.StatusOK, Header: make(http.Header)}, http.MethodGet)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := await(response.Call("arrayBuffer")); err == nil {
		t.Fatal("response EOF hid its independent cleanup failure")
	}
	if err := body.close(); !errors.Is(err, cleanup) || len(owner.bodies) != 0 {
		t.Fatal("response cleanup failure or joined ownership was lost", err)
	}
}

func TestRequestAbortAndDeploymentCloseJoinBlockedUpload(t *testing.T) {
	for _, cancelFails := range []bool{false, true} {
		t.Run(map[bool]string{false: "canceled", true: "independent cancel failure"}[cancelFails], func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			client, server := net.Pipe()
			connection := &uploadConnection{ctx: ctx, cancel: cancel, serverDone: make(chan struct{})}
			connection.transport = &http.Transport{DialTLSContext: func(context.Context, string, string) (net.Conn, error) { return client, nil }}
			go func() {
				defer close(connection.serverDone)
				defer server.Close()
				request, err := http.ReadRequest(bufio.NewReader(server))
				if err == nil {
					_, _ = io.Copy(io.Discard, request.Body)
					_ = request.Body.Close()
				}
			}()
			owner := &deploymentHandle{ctx: ctx, stop: cancel, connections: map[*connectionHandle]struct{}{}, bindings: map[string]*connectionHandle{}}
			handle := &connectionHandle{owner: owner, connection: connection, stop: cancel, name: "web", streams: map[*streamHandle]struct{}{}, bodies: map[*responseBody]struct{}{}}
			owner.connections[handle], owner.bindings["web"] = struct{}{}, handle
			secondRead, cancelEntered := make(chan struct{}), make(chan struct{})
			var secondOnce sync.Once
			calls := 0
			var controller js.Value
			pull := js.FuncOf(func(_ js.Value, args []js.Value) any {
				controller = args[0]
				calls++
				if calls == 1 {
					controller.Call("enqueue", jsBytes([]byte("first upload chunk")))
				} else {
					secondOnce.Do(func() { close(secondRead) })
				}
				return nil
			})
			defer pull.Release()
			cancelPromise, resolveCancel, rejectCancel := deferredJSPromise()
			cancelUpload := js.FuncOf(func(js.Value, []js.Value) any { close(cancelEntered); return cancelPromise })
			defer cancelUpload.Release()
			source := js.Global().Get("Object").New()
			source.Set("pull", pull)
			source.Set("cancel", cancelUpload)
			stream := js.Global().Get("ReadableStream").New(source, map[string]any{"highWaterMark": 0})
			input := js.Global().Get("Request").New("https://service.example.test/upload", map[string]any{"method": "POST", "body": stream, "duplex": "half"})
			abort := js.Global().Get("AbortController").New()
			fetched := make(chan error, 1)
			go func() { _, err := handle.fetch([]js.Value{input, abort.Get("signal")}); fetched <- err }()
			// even on an assertion failure, settle the controlled host source so
			// fixture callbacks are released only after Go's upload workers join.
			defer func() {
				abort.Call("abort")
				if !controller.IsUndefined() {
					controller.Call("error", js.Global().Get("Error").New("fixture stopped"))
				}
				resolveCancel.Invoke()
				_ = owner.close()
			}()
			select {
			case <-secondRead:
			case <-time.After(5 * time.Second):
				t.Fatal("Go HTTP writer did not enter the second body read")
			}
			abort.Call("abort")
			select {
			case <-cancelEntered:
			case <-time.After(5 * time.Second):
				t.Fatal("request cancellation did not cancel the blocked body reader")
			}
			closed := make(chan error, 1)
			go func() { closed <- owner.close() }()
			select {
			case err := <-fetched:
				t.Fatal("fetch returned before upload cancellation joined", err)
			default:
			}
			select {
			case err := <-closed:
				t.Fatal("deployment close returned before upload cancellation joined", err)
			default:
			}
			if cancelFails {
				rejectCancel.Invoke(js.Global().Get("Error").New("private upload cleanup sentinel"))
			} else {
				resolveCancel.Invoke()
			}
			var fetchErr error
			select {
			case fetchErr = <-fetched:
			case <-time.After(5 * time.Second):
				t.Fatal("fetch did not join the original read and cancel promises")
			}
			if !errors.Is(fetchErr, context.Canceled) {
				t.Fatal("request lost its cancellation cause", fetchErr)
			}
			if strings.Contains(fetchErr.Error(), "private upload cleanup sentinel") {
				t.Fatal("host cleanup exception leaked")
			}
			if cancelFails {
				var cleanup *connectorstream.CleanupError
				if !errors.As(fetchErr, &cleanup) || onlyOwnedCancellation(fetchErr) {
					t.Fatal("independent upload cleanup disappeared into cancellation", fetchErr)
				}
			} else if !onlyOwnedCancellation(fetchErr) {
				t.Fatal("clean upload cancellation was not classified as owned", fetchErr)
			}
			select {
			case err := <-closed:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("deployment close did not join its pending fetch")
			}
		})
	}
}

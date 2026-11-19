//go:build js && wasm

package main

import (
	"bufio"
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

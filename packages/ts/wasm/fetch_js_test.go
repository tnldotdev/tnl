//go:build js && wasm

package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"syscall/js"
	"testing"

	connectorstream "github.com/tnldotdev/tnl/internal/connector/stream"
	"github.com/tnldotdev/tnl/internal/failure"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestFetchTransportUsesExplicitUncredentialedHostPolicy(t *testing.T) {
	var calls atomic.Int32
	fetch := js.FuncOf(func(_ js.Value, args []js.Value) any {
		calls.Add(1)
		request := args[0]
		if request.Get("credentials").String() != "omit" || request.Get("redirect").String() != "manual" {
			t.Error("control request enabled cookies or redirects")
		}
		if request.Get("headers").Call("get", "Authorization").String() != "Bearer private-test-value" {
			t.Error("explicit authorization lost")
		}
		response := js.Global().Get("Response").New(jsBytes([]byte("response")), map[string]any{"status": 200, "headers": map[string]any{"X-Test": "present"}})
		return js.Global().Get("Promise").Call("resolve", response)
	})
	defer fetch.Release()
	client := &fetchTransport{fetch: fetch.Value}
	request, err := http.NewRequestWithContext(t.Context(), "POST", "https://control.example.test/v1/example", bytes.NewReader([]byte("request")))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer private-test-value")
	request.Header.Set("js.fetch:credentials", "include")
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if err := response.Body.Close(); err != nil {
		t.Fatal(err)
	}
	if string(data) != "response" || response.Header.Get("X-Test") != "present" || calls.Load() != 1 {
		t.Fatal("host Fetch response did not reach generated client")
	}
}

func TestJSBodyCopiesBoundedChunksAndJoinsCancellation(t *testing.T) {
	data := make([]byte, chunkBytes*3+17)
	for i := range data {
		data[i] = byte(i % 251)
	}
	body := js.Global().Get("Response").New(jsBytes(data)).Get("body")
	reader, err := newJSReader(body, nil)
	if err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, chunkBytes*4)
	var output []byte
	for {
		n, err := reader.Read(buffer)
		if n > chunkBytes {
			t.Fatal("body copied an oversized bridge chunk", n)
		}
		output = append(output, buffer[:n]...)
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	if !bytes.Equal(output, data) {
		t.Fatal("body data changed across bounded reads")
	}
	if err := reader.Close(); err != nil {
		t.Fatal(err)
	}
	if err := reader.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestFetchTransportContextAbortsHostOperation(t *testing.T) {
	entered := make(chan struct{})
	aborted := make(chan struct{})
	var abort js.Func
	fetch := js.FuncOf(func(_ js.Value, args []js.Value) any {
		signal := args[0].Get("signal")
		executor := js.FuncOf(func(_ js.Value, args []js.Value) any {
			reject := args[1]
			abort = js.FuncOf(func(js.Value, []js.Value) any {
				close(aborted)
				reject.Invoke(signal.Get("reason"))
				return nil
			})
			signal.Call("addEventListener", "abort", abort)
			close(entered)
			return nil
		})
		defer executor.Release()
		return js.Global().Get("Promise").New(executor)
	})
	defer fetch.Release()
	ctx, cancel := context.WithCancel(t.Context())
	request, err := http.NewRequestWithContext(ctx, "GET", "https://control.example.test", nil)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { _, err := (&fetchTransport{fetch: fetch.Value}).RoundTrip(request); done <- err }()
	<-entered
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) || !failure.Only(err, context.Canceled) {
		t.Fatal("host rejection replaced exact context cause", err)
	}
	<-aborted
	abort.Release()
}

func TestFetchTransportRetainsIndependentRejectionAfterCancellation(t *testing.T) {
	entered, aborted := make(chan struct{}), make(chan struct{})
	var reject js.Value
	var signal js.Value
	var onAbort js.Func
	fetch := js.FuncOf(func(_ js.Value, args []js.Value) any {
		signal = args[0].Get("signal")
		executor := js.FuncOf(func(_ js.Value, args []js.Value) any {
			reject = args[1]
			onAbort = js.FuncOf(func(js.Value, []js.Value) any {
				close(aborted)
				return nil
			})
			signal.Call("addEventListener", "abort", onAbort)
			close(entered)
			return nil
		})
		defer executor.Release()
		return js.Global().Get("Promise").New(executor)
	})
	defer fetch.Release()
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, "GET", "https://control.example.test", nil)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { _, err := (&fetchTransport{fetch: fetch.Value}).RoundTrip(request); done <- err }()
	<-entered
	cancel()
	<-aborted
	select {
	case err := <-done:
		t.Fatal("Fetch returned without joining the original host promise", err)
	default:
	}
	independent := js.Global().Get("Error").New("private independent host rejection sentinel")
	independent.Set("name", "AbortError")
	reject.Invoke(independent)
	err = <-done
	signal.Call("removeEventListener", "abort", onAbort)
	onAbort.Release()
	if !errors.Is(err, context.Canceled) || failure.Only(err, context.Canceled) {
		t.Fatal("independent host rejection disappeared into cancellation", err)
	}
	if strings.Contains(err.Error(), "private independent host rejection sentinel") {
		t.Fatal("host rejection was not redacted")
	}
	if onlyOwnedCancellation(operationError(ctx, err)) {
		t.Fatal("independent rejection would be presented as AbortError", err)
	}
}

func TestRetiredBridgeMethodsReleaseClosuresAndCloseRemainsIdempotent(t *testing.T) {
	initializeDispatcher()
	object := js.Global().Get("Object").New()
	var set methodSet
	bind(object, "close", &set, func([]js.Value) (any, error) { return nil, nil })
	saved := object.Get("close")
	set.retire()
	if _, err := await(saved.Invoke()); err != nil {
		t.Fatal("saved close rejected after retirement", err)
	}
	methodMu.Lock()
	_, retained := methods[set.id]
	methodMu.Unlock()
	if retained {
		t.Fatal("retired resource closure retained")
	}
}

func TestSignalContextReleasesItsListener(t *testing.T) {
	controller := js.Global().Get("AbortController").New()
	ctx, stop, err := signalContext(t.Context(), controller.Get("signal"))
	if err != nil {
		t.Fatal(err)
	}
	controller.Call("abort")
	<-ctx.Done()
	stop()
	stop()
}

func TestJSBodyCloseJoinsPendingHostRead(t *testing.T) {
	started := make(chan struct{})
	pull := js.FuncOf(func(js.Value, []js.Value) any { close(started); return nil })
	defer pull.Release()
	source := js.Global().Get("Object").New()
	source.Set("pull", pull)
	stream := js.Global().Get("ReadableStream").New(source, map[string]any{"highWaterMark": 0})
	reader, err := newJSReader(stream, nil)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { _, err := reader.Read(make([]byte, 16)); done <- err }()
	<-started
	if err := reader.Close(); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != io.EOF && !errors.Is(err, io.ErrClosedPipe) {
		t.Fatal("pending read did not join cancellation", err)
	}
}

func TestAbortErrorRequiresOnlyOwnedCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	owned := operationError(ctx, context.Canceled)
	if safeError(owned).Get("name").String() != "AbortError" {
		t.Fatal("owned cancellation was not labeled AbortError")
	}
	for _, err := range []error{
		context.Canceled,
		errors.Join(owned, errors.New("independent operation failed")),
		&connectorstream.CleanupError{Err: context.Canceled},
		errors.Join(owned, &connectorstream.CleanupError{Err: context.Canceled}),
	} {
		if safeError(err).Get("name").String() == "AbortError" {
			t.Fatal("independent or unowned failure hidden by AbortError", err)
		}
	}
}

func TestBindingReuseSeparatesEndpointChangesFromTrustAndIdentity(t *testing.T) {
	original := controlv1.ServiceSummary{Id: "svc_aaaaaaaaaaaaaaaaaaaaaa", Protocol: "postgres", TrustRevision: 7, Endpoint: &controlv1.ServiceEndpoint{Hostname: "service.example.test", Port: 0, Public: false}}
	next := original
	next.Endpoint = &controlv1.ServiceEndpoint{Hostname: original.Endpoint.Hostname, Port: 25432, Public: true}
	if !sameBinding(original, next) {
		t.Fatal("public endpoint allocation retired authorized connector binding")
	}
	next.TrustRevision++
	if sameBinding(original, next) {
		t.Fatal("changed target trust reused old binding")
	}
	next = original
	next.Id = "svc_bbbbbbbbbbbbbbbbbbbbbb"
	if sameBinding(original, next) {
		t.Fatal("replaced saved service reused old binding")
	}
	next = original
	next.Endpoint = &controlv1.ServiceEndpoint{Hostname: "another.example.test"}
	if sameBinding(original, next) {
		t.Fatal("another TLS identity reused old binding")
	}
}

func hostileGetterObject(key string) js.Value {
	object := js.Global().Get("Object").New()
	getter := js.Global().Get("Function").New(`throw new Error("private-host-getter-sentinel")`)
	js.Global().Get("Object").Call("defineProperty", object, key, map[string]any{"get": getter})
	return object
}

func TestHostileGetterRejectsWithoutLeakingOrStoppingRuntime(t *testing.T) {
	object := hostileGetterObject("fetch")
	value := promise(func() (any, error) { return bridgeGet(object, "fetch"), nil })
	done := make(chan struct{})
	var rejected js.Value
	failed := js.FuncOf(func(_ js.Value, args []js.Value) any { rejected = args[0]; close(done); return nil })
	defer failed.Release()
	value.Call("catch", failed)
	<-done
	message := rejected.Get("message").String()
	if strings.Contains(message, "private-host-getter-sentinel") || message != "sdk.configuration_invalid" {
		t.Fatal("host exception was not redacted", message)
	}
	alive, err := await(promise(func() (any, error) { return "alive", nil }))
	if err != nil || alive.String() != "alive" {
		t.Fatal("hostile getter stopped the Go instance", err)
	}
}

func TestHostileFetchResponseGetterReturnsRedactedGoError(t *testing.T) {
	response := hostileGetterObject("status")
	fetch := js.FuncOf(func(js.Value, []js.Value) any { return js.Global().Get("Promise").Call("resolve", response) })
	defer fetch.Release()
	request, err := http.NewRequestWithContext(t.Context(), "GET", "https://control.example.test", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := (&fetchTransport{fetch: fetch.Value}).RoundTrip(request); !errors.Is(err, errArguments) || strings.Contains(err.Error(), "private-host-getter-sentinel") {
		t.Fatal("host response getter escaped its Go boundary", err)
	}
}

func TestHostileStreamResultGetterReturnsRedactedReadError(t *testing.T) {
	result := hostileGetterObject("done")
	read := js.FuncOf(func(js.Value, []js.Value) any { return js.Global().Get("Promise").Call("resolve", result) })
	defer read.Release()
	cancel := js.FuncOf(func(js.Value, []js.Value) any { return js.Global().Get("Promise").Call("resolve") })
	defer cancel.Release()
	release := js.FuncOf(func(js.Value, []js.Value) any { return nil })
	defer release.Release()
	reader := js.Global().Get("Object").New()
	reader.Set("read", read)
	reader.Set("cancel", cancel)
	reader.Set("releaseLock", release)
	body := &jsReader{reader: reader, pending: js.Undefined()}
	if _, err := body.Read(make([]byte, 16)); !errors.Is(err, errArguments) || strings.Contains(err.Error(), "private-host-getter-sentinel") {
		t.Fatal("host stream getter escaped its Go boundary", err)
	}
	if err := body.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestFetchTransportRejectsRedirectsWithoutFollowingCredentials(t *testing.T) {
	for _, response := range []map[string]any{
		{"status": http.StatusMovedPermanently, "type": "basic", "redirected": false},
		{"status": http.StatusFound, "type": "basic", "redirected": false},
		{"status": http.StatusTemporaryRedirect, "type": "basic", "redirected": false},
		{"status": http.StatusPermanentRedirect, "type": "basic", "redirected": false},
		{"status": 0, "type": "opaqueredirect", "redirected": false},
		{"status": http.StatusOK, "type": "basic", "redirected": true},
	} {
		calls := 0
		fetch := js.FuncOf(func(_ js.Value, args []js.Value) any {
			calls++
			if args[0].Get("redirect").String() != "manual" || args[0].Get("credentials").String() != "omit" {
				t.Error("host Fetch could follow a credential-bearing redirect")
			}
			return js.Global().Get("Promise").Call("resolve", js.ValueOf(response))
		})
		request, err := http.NewRequestWithContext(t.Context(), "POST", "https://control.example.test/v1/publisher-token", nil)
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("Authorization", "Bearer private proof")
		if _, err := (&fetchTransport{fetch: fetch.Value}).RoundTrip(request); err == nil || calls != 1 {
			t.Fatal("redirect response was accepted or followed", response, err, calls)
		}
		fetch.Release()
	}
}

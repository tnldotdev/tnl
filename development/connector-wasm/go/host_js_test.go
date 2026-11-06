//go:build js && wasm

package main

import (
	"context"
	"errors"
	"net"
	"os"
	"strings"
	"syscall/js"
	"testing"
	"time"
)

func testHostMethod(t *testing.T, object js.Value, name string, call func([]js.Value) any) {
	t.Helper()
	f := js.FuncOf(func(_ js.Value, args []js.Value) any { return call(args) })
	object.Set(name, f)
	t.Cleanup(f.Release)
}

func deferredHostPromise() (promise, resolve, reject js.Value) {
	executor := js.FuncOf(func(_ js.Value, args []js.Value) any { resolve, reject = args[0], args[1]; return nil })
	promise = js.Global().Get("Promise").New(executor)
	executor.Release()
	return
}

func rejectedHostPromise(name string) js.Value {
	err := js.Global().Get("Error").New("private-address:443 private-credential")
	err.Set("name", name)
	return js.Global().Get("Promise").Call("reject", err)
}

func TestHostReplacementDialPreservesSanitizedNetworkClass(t *testing.T) {
	for _, name := range []string{hostNetworkErrorName, "TypeError", "Error"} {
		t.Run(name, func(t *testing.T) {
			host := js.Global().Get("Object").New()
			testHostMethod(t, host, "dialTCP", func([]js.Value) any { return rejectedHostPromise(name) })
			_, err := hostDial(host)(t.Context(), "tcp", "replacement.test:443")
			var network net.Error
			if err == nil || errors.As(err, &network) != (name == hostNetworkErrorName) {
				t.Fatal("replacement dial lost network/terminal classification", err)
			}
			if strings.Contains(err.Error(), "private-") || strings.Contains(err.Error(), "replacement.test") {
				t.Fatal("host rejection exposed private details")
			}
		})
	}
	_, err := hostDial(js.Undefined())(t.Context(), "udp", "private-invalid-address")
	var network net.Error
	if err == nil || errors.As(err, &network) {
		t.Fatal("unsupported host transport was not terminal", err)
	}
}

func TestHostNetworkReadAndWriteRejectionsRemainTyped(t *testing.T) {
	socket := js.Global().Get("Object").New()
	for _, method := range []string{"read", "write"} {
		testHostMethod(t, socket, method, func([]js.Value) any { return rejectedHostPromise(hostNetworkErrorName) })
	}
	testHostMethod(t, socket, "close", func([]js.Value) any { return resolved(nil) })
	c := newHostConn(socket, "relay.test:443")
	defer c.Close()
	for _, operation := range []func() error{
		func() error { _, err := c.Read(make([]byte, 1)); return err },
		func() error { _, err := c.Write([]byte{1}); return err },
	} {
		var network net.Error
		if err := operation(); !errors.As(err, &network) || network.Timeout() {
			t.Fatal("network I/O lost its sanitized retryable type", err)
		}
	}
}

func TestHostCancelledReadPreservesCauseAndBoundsUnsettledCleanup(t *testing.T) {
	p, resolve, _ := deferredHostPromise()
	ctx, cancel := context.WithCancelCause(t.Context())
	sentinel := errors.New("fixture read cancelled")
	cancel(sentinel)
	value, err := await(ctx, p, func() {})
	if !value.IsUndefined() || !errors.Is(err, sentinel) || !errors.Is(err, errHostCleanup) {
		t.Fatal("unsettled read lost cancellation or cleanup failure", err)
	}
	resolve.Invoke(nil)
	if _, err := await(t.Context(), resolved(nil), func() {}); err != nil {
		t.Fatal(err)
	}
}

func TestHostCloseBoundsPendingIOAndRetriesCleanupWithoutReopening(t *testing.T) {
	socket := js.Global().Get("Object").New()
	reading, finishRead, _ := deferredHostPromise()
	closing, finishClose, _ := deferredHostPromise()
	started := make(chan struct{})
	closes := 0
	testHostMethod(t, socket, "read", func([]js.Value) any { close(started); return reading })
	testHostMethod(t, socket, "close", func([]js.Value) any {
		closes++
		if closes == 1 {
			return closing
		}
		finishRead.Invoke(nil)
		return resolved(nil)
	})
	c := newHostConn(socket, "relay.test:443")
	result := make(chan error, 1)
	go func() { _, err := c.Read(make([]byte, 1)); result <- err }()
	<-started
	if err := c.Close(); !errors.Is(err, errHostCleanup) {
		t.Fatal("never-settling host close was reported joined", err)
	}
	select {
	case err := <-result:
		if !errors.Is(err, net.ErrClosed) || !errors.Is(err, errHostCleanup) {
			t.Fatal("pending read did not retain close and cleanup failure", err)
		}
	case <-time.After(time.Second):
		t.Fatal("pending read exceeded bounded host cleanup")
	}
	if err := c.Close(); err != nil {
		t.Fatal("cleanup retry did not succeed", err)
	}
	if _, err := c.Read(make([]byte, 1)); !errors.Is(err, net.ErrClosed) {
		t.Fatal("cleanup retry reopened I/O", err)
	}
	if err := c.Close(); err != nil || closes != 2 {
		t.Fatal("successful cleanup was not idempotent", err)
	}
	finishClose.Invoke(nil)
	if _, err := await(t.Context(), resolved(nil), func() {}); err != nil {
		t.Fatal(err)
	}
}

func TestHostRejectedCloseCanBeRetried(t *testing.T) {
	socket := js.Global().Get("Object").New()
	calls := 0
	testHostMethod(t, socket, "close", func([]js.Value) any {
		calls++
		if calls == 1 {
			return rejectedHostPromise(hostNetworkErrorName)
		}
		return resolved(nil)
	})
	c := newHostConn(socket, "relay.test:443")
	if err := c.Close(); err != errHostNetwork {
		t.Fatal("first cleanup failure identity was lost", err)
	}
	if err := c.Close(); err != nil || calls != 2 {
		t.Fatal("rejected cleanup was cached permanently", err)
	}
}

func TestHostLateSettlementCannotInvokeReleasedCallbacks(t *testing.T) {
	console := js.Global().Get("console")
	original := console.Get("error")
	called := false
	record := js.FuncOf(func(js.Value, []js.Value) any { called = true; return nil })
	console.Set("error", record)
	defer func() { console.Set("error", original); record.Release() }()
	for _, rejected := range []bool{false, true} {
		promise, resolve, reject := deferredHostPromise()
		pending := watchPromise(promise)
		pending.abandon()
		if result := <-pending.result; !errors.Is(result.err, errHostCleanup) {
			t.Fatal("bounded promise did not report incomplete cleanup", result.err)
		}
		pending.release()
		if rejected {
			reject.Invoke(js.Global().Get("Error").New("private late detail"))
		} else {
			resolve.Invoke(nil)
		}
		if _, err := await(t.Context(), resolved(nil), func() {}); err != nil {
			t.Fatal(err)
		}
	}
	if called {
		t.Fatal("late original settlement invoked a released Go function")
	}
}

func TestHostIdleReadHasNoSettlementDeadline(t *testing.T) {
	socket := js.Global().Get("Object").New()
	reading, resolve, _ := deferredHostPromise()
	started := make(chan struct{})
	testHostMethod(t, socket, "read", func([]js.Value) any { close(started); return reading })
	testHostMethod(t, socket, "close", func([]js.Value) any { return resolved(nil) })
	c := newHostConn(socket, "relay.test:443")
	defer c.Close()
	result := make(chan error, 1)
	go func() {
		buffer := make([]byte, 1)
		n, err := c.Read(buffer)
		if err == nil && (n != 1 || buffer[0] != 42) {
			err = errors.New("idle read lost its eventual bytes")
		}
		result <- err
	}()
	<-started
	select {
	case err := <-result:
		t.Fatal("healthy idle read was bounded by the cleanup budget", err)
	case <-time.After(hostSettlementTimeout + 10*time.Millisecond):
	}
	bytes := js.Global().Get("Uint8Array").New(1)
	js.CopyBytesToJS(bytes, []byte{42})
	resolve.Invoke(bytes)
	if err := <-result; err != nil {
		t.Fatal(err)
	}
}

func resolved(value any) js.Value { return js.Global().Get("Promise").Call("resolve", value) }

func TestHostSocketCopiesBytesAndVerifiesBounds(t *testing.T) {
	for _, oversized := range []bool{false, true} {
		socket := js.Global().Get("Object").New()
		closed := 0
		testHostMethod(t, socket, "read", func(args []js.Value) any {
			n := args[0].Int()
			if oversized {
				n++
			}
			b := js.Global().Get("Uint8Array").New(n)
			js.CopyBytesToJS(b, []byte("read"))
			return resolved(b)
		})
		testHostMethod(t, socket, "write", func(args []js.Value) any {
			b := make([]byte, args[0].Length())
			js.CopyBytesToGo(b, args[0])
			if string(b) != "write" {
				t.Errorf("write = %q", b)
			}
			return resolved(nil)
		})
		testHostMethod(t, socket, "close", func([]js.Value) any { closed++; return resolved(nil) })
		c := newHostConn(socket, "relay.test:443")
		b := make([]byte, 4)
		if _, err := c.Write([]byte("write")); err != nil {
			t.Fatal(err)
		}
		n, err := c.Read(b)
		if oversized {
			if err == nil {
				t.Fatal("oversized host read accepted")
			}
		} else if err != nil || n != 4 || string(b) != "read" {
			t.Fatalf("read=%q,%d,%v", b, n, err)
		}
		if err := c.Close(); err != nil {
			t.Fatal(err)
		}
		if closed != 1 {
			t.Fatalf("host closed %d times", closed)
		}
	}
}

func TestHostSocketDeadlineClosesAndJoinsPendingRead(t *testing.T) {
	socket := js.Global().Get("Object").New()
	var resolve js.Value
	closed := 0
	testHostMethod(t, socket, "read", func([]js.Value) any {
		executor := js.FuncOf(func(_ js.Value, args []js.Value) any { resolve = args[0]; return nil })
		p := js.Global().Get("Promise").New(executor)
		executor.Release()
		return p
	})
	testHostMethod(t, socket, "close", func([]js.Value) any { closed++; resolve.Invoke(nil); return resolved(nil) })
	c := newHostConn(socket, "relay.test:443")
	_ = c.SetReadDeadline(time.Now().Add(10 * time.Millisecond))
	if _, err := c.Read(make([]byte, 1)); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("deadline error=%v", err)
	}
	_ = c.Close()
	if closed != 1 {
		t.Fatalf("host closed %d times", closed)
	}
}

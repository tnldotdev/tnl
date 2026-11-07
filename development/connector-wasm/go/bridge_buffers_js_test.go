//go:build js && wasm

package main

import (
	"context"
	"errors"
	"io"
	"net"
	"strconv"
	"syscall/js"
	"testing"
)

func testPromiseModes(t *testing.T, test func(*testing.T, bool)) {
	t.Helper()
	for _, compact := range []bool{false, true} {
		name := "baseline"
		if compact {
			name = "compact"
		}
		t.Run(name, func(t *testing.T) {
			before := hostWaiterCount()
			t.Cleanup(func() {
				if got := hostWaiterCount(); got != before {
					t.Fatalf("host promise waiters leaked: %d -> %d", before, got)
				}
			})
			test(t, compact)
		})
	}
}

func hostWaiterCount() int {
	hostWaiterMu.Lock()
	defer hostWaiterMu.Unlock()
	return len(hostWaiters)
}

func TestApplicationBufferReuseKeepsReturnedBytesOwned(t *testing.T) {
	testPromiseModes(t, func(t *testing.T, compact bool) {
		for _, reuse := range []bool{false, true} {
			t.Run(strconv.FormatBool(reuse), func(t *testing.T) {
				s, server := mainTestStream(t, "tcp", compact)
				s.owner.prepared.reuseBuffers = reuse
				before := counters
				go func() { _, _ = server.Write([]byte{1, 2, 3}); _, _ = server.Write([]byte{4, 5}) }()
				first, err := mainAwait(t, s.object.Call("read", 4096))
				if err != nil {
					t.Fatal(err)
				}
				second, err := mainAwait(t, s.object.Call("read", 4096))
				if err != nil {
					t.Fatal(err)
				}
				if first.Length() != 3 || first.Index(0).Int() != 1 || second.Length() != 2 || second.Index(0).Int() != 4 {
					t.Fatal("a later read overwrote returned JS bytes")
				}
				want := uint64(8192)
				if reuse {
					want = 4096
				}
				if got := counters.ApplicationReadAllocated - before.ApplicationReadAllocated; got != want {
					t.Fatalf("allocated %d, want %d", got, want)
				}
				wantCallbacks := uint64(2)
				if compact {
					wantCallbacks = 0
				}
				if got := counters.PromiseExecutors - before.PromiseExecutors; got != wantCallbacks {
					t.Fatalf("application promise executors = %d, want %d", got, wantCallbacks)
				}
				if got := counters.CallbackRegistrations - before.CallbackRegistrations; got != wantCallbacks {
					t.Fatalf("application Go callback registrations = %d, want %d", got, wantCallbacks)
				}
			})
		}
	})
}

func TestHostPromisesReduceGoCallbackSetupAndJoinPendingRead(t *testing.T) {
	testPromiseModes(t, func(t *testing.T, compact bool) {
		socket := js.Global().Get("Object").New()
		reading, finishRead, _ := deferredHostPromise()
		started := make(chan struct{})
		testHostMethod(t, socket, "read", func([]js.Value) any { close(started); return reading })
		testHostMethod(t, socket, "write", func([]js.Value) any { return resolved(nil) })
		testHostMethod(t, socket, "close", func([]js.Value) any { return resolved(nil) })
		c := newHostConn(socket, "relay.test:443", compact)
		defer c.Close()
		before := counters
		b := make([]byte, 1)
		done := make(chan error, 1)
		go func() {
			n, err := c.Read(b)
			if err == nil && (n != 1 || b[0] != 7) {
				err = errors.New("pending read lost bytes")
			}
			done <- err
		}()
		<-started
		select {
		case err := <-done:
			t.Fatal("read did not wait for its host promise", err)
		default:
		}
		bytes := js.Global().Get("Uint8Array").New(1)
		bytes.SetIndex(0, 7)
		finishRead.Invoke(bytes)
		if err := <-done; err != nil {
			t.Fatal(err)
		}
		if _, err := c.Write([]byte{8}); err != nil {
			t.Fatal(err)
		}
		if err := c.Close(); err != nil {
			t.Fatal(err)
		}
		if got := counters.PromiseWaits - before.PromiseWaits; got != 3 {
			t.Fatalf("host promise waits = %d, want 3", got)
		}
		wantExecutors, wantCallbacks, wantShared := uint64(3), uint64(9), uint64(0)
		if compact {
			wantExecutors, wantCallbacks, wantShared = 0, 0, 3
		}
		if got := counters.PromiseExecutors - before.PromiseExecutors; got != wantExecutors {
			t.Fatalf("host promise executors = %d, want %d", got, wantExecutors)
		}
		if got := counters.CallbackRegistrations - before.CallbackRegistrations; got != wantCallbacks {
			t.Fatalf("host Go callback registrations = %d, want %d", got, wantCallbacks)
		}
		if got := counters.SharedPromiseWaits - before.SharedPromiseWaits; got != wantShared {
			t.Fatalf("shared host promise waits = %d, want %d", got, wantShared)
		}
	})
}

func TestApplicationWriteBufferReuseKeepsBytes(t *testing.T) {
	testPromiseModes(t, func(t *testing.T, compact bool) {
		for _, reuse := range []bool{false, true} {
			t.Run(strconv.FormatBool(reuse), func(t *testing.T) {
				s, server := mainTestStream(t, "tcp", compact)
				s.owner.prepared.reuseBuffers = reuse
				before := counters.ApplicationWriteAllocated
				first := js.Global().Get("Uint8Array").New(3)
				js.CopyBytesToJS(first, []byte{1, 2, 3})
				pending := s.object.Call("write", first)
				b := make([]byte, 3)
				if _, err := io.ReadFull(server, b); err != nil || string(b) != string([]byte{1, 2, 3}) {
					t.Fatal("first write lost bytes", b, err)
				}
				if _, err := mainAwait(t, pending); err != nil {
					t.Fatal(err)
				}
				second := js.Global().Get("Uint8Array").New(2)
				js.CopyBytesToJS(second, []byte{4, 5})
				pending = s.object.Call("write", second)
				if _, err := io.ReadFull(server, b[:2]); err != nil || string(b[:2]) != string([]byte{4, 5}) {
					t.Fatal("reused write lost bytes", b, err)
				}
				if _, err := mainAwait(t, pending); err != nil {
					t.Fatal(err)
				}
				want := uint64(5)
				if reuse {
					want = 3
				}
				if got := counters.ApplicationWriteAllocated - before; got != want {
					t.Fatalf("allocated %d, want %d", got, want)
				}
			})
		}
	})
}

func TestCompactHostWaitersSeparateResultsAndIgnoreRetiredCallbacks(t *testing.T) {
	before := hostWaiterCount()
	firstPromise, finishFirst, _ := deferredHostPromise()
	secondPromise, _, rejectSecond := deferredHostPromise()
	first := watchPromise(firstPromise, true)
	defer first.release()
	hostWaiterMu.Lock()
	firstID := strconv.FormatUint(nextHostWaiterID, 10)
	hostWaiterMu.Unlock()
	savedResolve := hostPromiseDispatcher.Value.Call("bind", js.Null(), firstID, false)
	savedReject := hostPromiseDispatcher.Value.Call("bind", js.Null(), firstID, true)
	second := watchPromise(secondPromise, true)
	defer second.release()
	if got := hostWaiterCount(); got != before+2 {
		t.Fatalf("pending waiters = %d, want %d", got, before+2)
	}
	failure := js.Global().Get("Error").New("private late detail")
	failure.Set("name", hostNetworkErrorName)
	rejectSecond.Invoke(failure)
	if result := <-second.result; result.err != errHostNetwork {
		t.Fatal("shared dispatcher lost rejection classification", result.err)
	}
	select {
	case result := <-first.result:
		t.Fatal("second waiter settled the first", result)
	default:
	}
	finishFirst.Invoke(42)
	if result := <-first.result; result.err != nil || result.value.Int() != 42 {
		t.Fatal("shared dispatcher lost the first result", result)
	}
	first.release()
	second.release()
	savedResolve.Invoke(99)
	savedReject.Invoke(failure)
	select {
	case result := <-first.result:
		t.Fatal("saved callback delivered to a retired waiter", result)
	default:
	}
	if got := hostWaiterCount(); got != before {
		t.Fatalf("retired waiters retained: %d -> %d", before, got)
	}
}

func TestCancelledHostPromiseJoinsAndPreservesNetworkError(t *testing.T) {
	testPromiseModes(t, func(t *testing.T, compact bool) {
		pending, _, reject := deferredHostPromise()
		ctx, cancel := context.WithCancelCause(t.Context())
		cause := errors.New("fixture cancelled")
		cancel(cause)
		joined := false
		value, err := await(ctx, pending, func() {
			joined = true
			failure := js.Global().Get("Error").New("private-address:443")
			failure.Set("name", hostNetworkErrorName)
			reject.Invoke(failure)
		}, compact)
		var network net.Error
		if !value.IsUndefined() || !joined || !errors.Is(err, cause) || !errors.As(err, &network) || network.Timeout() {
			t.Fatal("cancellation lost its join, cause or network error", err)
		}
	})
}

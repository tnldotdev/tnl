//go:build js && wasm

package main

import (
	"bytes"
	"errors"
	"io"
	"net"
	"os"
	"runtime"
	"strings"
	"syscall/js"
	"testing"
	"time"
)

type hostPumpFixture struct {
	c       *hostConn
	socket  js.Value
	control js.Value
	receive js.Value
	writes  [][]byte
	resumes int
	closes  int
}

func newHostPumpFixture(t *testing.T) *hostPumpFixture {
	t.Helper()
	f := &hostPumpFixture{socket: js.Global().Get("Object").New(), control: js.Global().Get("Object").New()}
	testHostMethod(t, f.socket, "read", func([]js.Value) any {
		t.Error("pump used promise read")
		return resolved(nil)
	})
	testHostMethod(t, f.socket, "write", func([]js.Value) any {
		t.Error("pump used promise write")
		return resolved(nil)
	})
	testHostMethod(t, f.socket, "close", func([]js.Value) any { f.closes++; return resolved(nil) })
	testHostMethod(t, f.socket, "startPump", func(args []js.Value) any {
		f.receive = args[0]
		return f.control
	})
	testHostMethod(t, f.control, "resume", func([]js.Value) any { f.resumes++; return nil })
	testHostMethod(t, f.control, "write", func(args []js.Value) any {
		b := make([]byte, args[0].Length())
		js.CopyBytesToGo(b, args[0])
		f.writes = append(f.writes, b)
		f.receive.Invoke(2, len(b))
		return true
	})
	host := js.Global().Get("Object").New()
	testHostMethod(t, host, "dialTCP", func([]js.Value) any { return resolved(f.socket) })
	c, err := hostDial(host, true)(t.Context(), "tcp", "relay.test:443")
	if err != nil {
		t.Fatal(err)
	}
	f.c = c.(*hostConn)
	t.Cleanup(func() {
		if err := f.c.Close(); err != nil {
			t.Error(err)
		}
	})
	return f
}

func hostPumpBytes(b []byte) js.Value {
	v := js.Global().Get("Uint8Array").New(len(b))
	js.CopyBytesToJS(v, b)
	return v
}

func TestHostPumpReadsBoundedWindowAcrossSmallReadsAndFinalEOF(t *testing.T) {
	f := newHostPumpFixture(t)
	before := counters
	want := make([]byte, hostPumpByteCredit)
	for i := range want {
		want[i] = byte(i % 251)
	}
	f.receive.Invoke(1, hostPumpBytes(want[:19]))
	f.receive.Invoke(1, hostPumpBytes(want[19:]))
	var got []byte
	for len(got) < len(want) {
		b := make([]byte, 997)
		n, err := f.c.Read(b)
		if err != nil {
			t.Fatal(err)
		}
		got = append(got, b[:n]...)
		if len(got) < len(want) && f.resumes != 0 {
			t.Fatal("returned read credit before the window was drained")
		}
	}
	if !bytes.Equal(got, want) || f.resumes != 1 {
		t.Fatal("fragmented reads lost bytes or read credit")
	}
	f.receive.Invoke(1, hostPumpBytes([]byte{7, 8, 9}))
	f.receive.Invoke(3, nil)
	last, err := io.ReadAll(f.c)
	if err != nil || !bytes.Equal(last, []byte{7, 8, 9}) {
		t.Fatal("EOF discarded buffered bytes", last, err)
	}
	if _, err := f.c.Read(make([]byte, 1)); err != io.EOF {
		t.Fatal("EOF was not persistent", err)
	}
	if f.resumes != 1 || cap(f.c.pump.bytes) > hostPumpByteCredit {
		t.Fatal("read buffer or EOF credit was unbounded")
	}
	if counters.PromiseWaits != before.PromiseWaits || counters.CallbackRegistrations != before.CallbackRegistrations || counters.HostPumpReads-before.HostPumpReads != 3 || counters.HostReadBytes-before.HostReadBytes != hostPumpByteCredit+3 {
		t.Fatal("pump read created promise waiters or lost byte diagnostics")
	}
}

func TestHostPumpWritesSplitAtCreditWithoutPerOperationPromises(t *testing.T) {
	f := newHostPumpFixture(t)
	before := counters
	want := bytes.Repeat([]byte{0, 1, 255}, hostPumpByteCredit+7)
	n, err := f.c.Write(want)
	if err != nil || n != len(want) {
		t.Fatal("write did not complete", n, err)
	}
	if !bytes.Equal(bytes.Join(f.writes, nil), want) || len(f.writes) != 4 {
		t.Fatal("write did not preserve bounded chunks")
	}
	for _, chunk := range f.writes {
		if len(chunk) > hostPumpByteCredit {
			t.Fatal("write exceeded byte credit")
		}
	}
	if counters.PromiseWaits != before.PromiseWaits || counters.CallbackRegistrations != before.CallbackRegistrations || counters.HostPumpWrites-before.HostPumpWrites != 4 {
		t.Fatal("pump write created promise waiters or lost operation diagnostics")
	}
	if n, err := f.c.Write(nil); n != 0 || err != nil {
		t.Fatal("empty write did not settle", n, err)
	}
}

func TestHostPumpWriteFailurePreservesAcknowledgedBytesOnce(t *testing.T) {
	for _, fixture := range []struct {
		name      string
		completed int
		prefix    int
		network   bool
	}{
		{name: "partial acknowledgment before deadline", completed: 3},
		{name: "full acknowledgment before deadline", completed: 8},
		{name: "earlier window and partial acknowledgment before deadline", completed: 3, prefix: hostPumpByteCredit},
		{name: "partial acknowledgment before network error", completed: 3, network: true},
		{name: "full acknowledgment before network error", completed: 8, network: true},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			f := newHostPumpFixture(t)
			writes := 0
			testHostMethod(t, f.control, "write", func(args []js.Value) any {
				writes++
				if fixture.prefix > 0 && writes == 1 {
					f.receive.Invoke(2, args[0].Length())
					return true
				}
				f.receive.Invoke(2, fixture.completed)
				if fixture.network {
					reason := js.Global().Get("Error").New("private network failure")
					reason.Set("name", hostNetworkErrorName)
					f.receive.Invoke(4, reason)
				} else {
					_ = f.c.SetWriteDeadline(time.Now().Add(-time.Second))
				}
				return true
			})
			cause := error(os.ErrDeadlineExceeded)
			if fixture.network {
				cause = errHostNetwork
			}
			n, err := f.c.Write(make([]byte, fixture.prefix+8))
			if n != fixture.prefix+fixture.completed || !errors.Is(err, cause) {
				t.Fatal("write lost acknowledged bytes or its failure cause", n, err)
			}
			if fixture.network && err != errHostNetwork {
				t.Fatal("network failure lost its identity", err)
			}
			if f.c.pump.writeDone != 0 {
				t.Fatal("write retained already-counted acknowledgments")
			}
			if err := f.c.Close(); err != nil {
				t.Fatal(err)
			}
			f.receive.Invoke(2, 1)
			for range 2 {
				if n, err := f.c.Read(make([]byte, 1)); n != 0 || !errors.Is(err, net.ErrClosed) {
					t.Fatal("closed read returned bytes or reopened I/O", n, err)
				}
				if n, err := f.c.Write([]byte{1}); n != 0 || !errors.Is(err, net.ErrClosed) {
					t.Fatal("closed write counted an acknowledgment again", n, err)
				}
				if err := f.c.Close(); err != nil || f.closes != 1 || f.c.pump.writeDone != 0 {
					t.Fatal("repeated cleanup reopened acknowledgment accounting", err)
				}
			}
		})
	}
}

func TestHostPumpDeadlineChangesInterruptBlockedReadAndWrite(t *testing.T) {
	for _, read := range []bool{true, false} {
		name := "write"
		if read {
			name = "read"
		}
		t.Run(name, func(t *testing.T) {
			f := newHostPumpFixture(t)
			started := make(chan struct{})
			result := make(chan error, 1)
			deadline := f.c.SetWriteDeadline
			if read {
				deadline = f.c.SetReadDeadline
			} else {
				testHostMethod(t, f.control, "write", func([]js.Value) any { close(started); return true })
			}
			_ = deadline(time.Now().Add(25 * time.Millisecond))
			go func() {
				var err error
				if read {
					close(started)
					_, err = f.c.Read(make([]byte, 1))
				} else {
					_, err = f.c.Write([]byte{1})
				}
				result <- err
			}()
			<-started
			_ = deadline(time.Now().Add(time.Hour))
			select {
			case err := <-result:
				t.Fatal("extending the deadline failed", err)
			case <-time.After(40 * time.Millisecond):
			}
			_ = deadline(time.Time{})
			_ = deadline(time.Now().Add(-time.Second))
			select {
			case err := <-result:
				if !errors.Is(err, os.ErrDeadlineExceeded) {
					t.Fatal("changed deadline lost its cause", err)
				}
			case <-time.After(time.Second):
				t.Fatal("changed deadline did not wake the pump")
			}
			if f.closes != 1 {
				t.Fatal("deadline did not close and join the socket", f.closes)
			}
		})
	}
}

func TestHostPumpFailedCloseRetainsFencedOwnerUntilRetry(t *testing.T) {
	f := newHostPumpFixture(t)
	testHostMethod(t, f.socket, "close", func([]js.Value) any {
		f.closes++
		if f.closes == 1 {
			return rejectedHostPromise(hostCleanupErrorName)
		}
		return resolved(nil)
	})
	pump, close := f.c.pump, f.c.Close
	id := pump.id
	if err := close(); err != errHostCleanup {
		t.Fatal("cleanup failure lost its identity", err)
	}
	if hostPumps[id] != nil {
		t.Fatal("close fence retained its callback dispatch entry")
	}
	if f.c.pump != pump || f.c.closeSucceeded || f.c.closing != nil || !f.c.socket.Equal(f.socket) {
		t.Fatal("failed cleanup discarded or completed its retryable connection owner")
	}
	before := counters.HostPumpNotifications
	f.receive.Invoke(1, hostPumpBytes([]byte{1}))
	f.receive.Invoke(2, 1)
	f.receive.Invoke(4, js.Global().Get("Error").New("private late failure"))
	if counters.HostPumpNotifications != before || len(f.c.pump.bytes) != 0 {
		t.Fatal("late callback reopened a fenced pump")
	}
	if _, err := f.c.Read(make([]byte, 1)); !errors.Is(err, net.ErrClosed) {
		t.Fatal("failed close reopened reads", err)
	}
	if _, err := f.c.Write([]byte{1}); !errors.Is(err, net.ErrClosed) {
		t.Fatal("failed close reopened writes", err)
	}
	if err := close(); err != nil || f.closes != 2 {
		t.Fatal("cleanup retry failed", err)
	}
	if err := close(); err != nil || f.closes != 2 || !f.c.closeSucceeded {
		t.Fatal("successful cleanup was not idempotent", err)
	}
	if hostPumps[id] != nil {
		t.Fatal("successful cleanup retained its registry entry")
	}
	other := newHostPumpFixture(t)
	if other.c.pump.id <= id {
		t.Fatal("pump reused a retired numeric id")
	}
	f.receive.Invoke(1, hostPumpBytes([]byte{2}))
	if len(other.c.pump.bytes) != 0 {
		t.Fatal("stale callback reached a later stream")
	}
}

func TestHostPumpStartupFailureRetiresDispatchBeforeHostCleanupRetry(t *testing.T) {
	beforePumps, beforeWaiters := len(hostPumps), len(hostWaiters)
	host, socket := js.Global().Get("Object").New(), js.Global().Get("Object").New()
	var receiver js.Value
	closes := 0
	testHostMethod(t, socket, "read", func([]js.Value) any { return resolved(nil) })
	testHostMethod(t, socket, "write", func([]js.Value) any { return resolved(nil) })
	testHostMethod(t, socket, "startPump", func(args []js.Value) any {
		receiver = args[0]
		if len(hostPumps) != beforePumps+1 {
			t.Error("startup did not register its callback dispatch entry")
		}
		return js.Global().Get("Object").New()
	})
	testHostMethod(t, socket, "close", func([]js.Value) any {
		closes++
		if closes == 1 {
			return rejectedHostPromise(hostCleanupErrorName)
		}
		return resolved(nil)
	})
	testHostMethod(t, host, "dialTCP", func([]js.Value) any { return resolved(socket) })
	// the host retains its socket close reference even when dial returns no conn.
	host.Set("close", socket.Get("close"))
	c, err := hostDial(host, true)(t.Context(), "tcp", "relay.test:443")
	if c != nil || !errors.Is(err, errHostPumpContract) || !errors.Is(err, errHostCleanup) || closes != 1 {
		t.Fatal("invalid pump startup lost its startup or cleanup failure", err, closes)
	}
	if len(hostPumps) != beforePumps || len(hostWaiters) != beforeWaiters {
		t.Fatal("failed startup retained a callback registry entry without a connection owner")
	}
	notifications := counters.HostPumpNotifications
	receiver.Invoke(1, hostPumpBytes([]byte{1}))
	receiver.Invoke(4, js.Global().Get("Error").New("private late failure"))
	p, err := call(host, "close")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := await(t.Context(), p, func() {}, true); err != nil || closes != 2 {
		t.Fatal("host-owned close reference could not retry cleanup", err, closes)
	}
	receiver.Invoke(3, nil)
	if counters.HostPumpNotifications != notifications || len(hostPumps) != beforePumps || len(hostWaiters) != beforeWaiters {
		t.Fatal("late startup callbacks restored retired dispatch state")
	}
}

func TestHostPumpNetworkErrorsStaySanitizedAndRetryable(t *testing.T) {
	for _, name := range []string{hostNetworkErrorName, hostCleanupErrorName, "TypeError"} {
		t.Run(name, func(t *testing.T) {
			f := newHostPumpFixture(t)
			reason := js.Global().Get("Error").New("private-address private-credential")
			reason.Set("name", name)
			f.receive.Invoke(4, reason)
			for _, work := range []func() error{
				func() error { _, err := f.c.Read(make([]byte, 1)); return err },
				func() error { _, err := f.c.Write([]byte{1}); return err },
			} {
				err := work()
				var network net.Error
				if err == nil || errors.As(err, &network) != (name != "TypeError") || strings.Contains(err.Error(), "private-") {
					t.Fatal("pump error lost sanitized network classification", err)
				}
				if network != nil && network.Timeout() != (name == hostCleanupErrorName) {
					t.Fatal("pump error changed timeout identity")
				}
			}
		})
	}
}

func TestHostPumpCloseJoinsBlockedIOAndKeepsCleanupFailure(t *testing.T) {
	f := newHostPumpFixture(t)
	closing, _, reject := deferredHostPromise()
	closeStarted, writeStarted, readStarted := make(chan struct{}), make(chan struct{}), make(chan struct{})
	testHostMethod(t, f.socket, "close", func([]js.Value) any {
		f.closes++
		if f.closes == 1 {
			close(closeStarted)
			return closing
		}
		return resolved(nil)
	})
	testHostMethod(t, f.control, "write", func([]js.Value) any { close(writeStarted); return true })
	reads, writes, closes := make(chan error, 1), make(chan error, 1), make(chan error, 1)
	go func() { close(readStarted); _, err := f.c.Read(make([]byte, 1)); reads <- err }()
	go func() { _, err := f.c.Write([]byte{1}); writes <- err }()
	<-readStarted
	<-writeStarted
	go func() { closes <- f.c.Close() }()
	<-closeStarted
	// both I/O waiters must join the active close instead of reporting success.
	runtime.Gosched()
	for _, result := range []chan error{reads, writes, closes} {
		select {
		case err := <-result:
			t.Fatal("operation returned before pending cleanup settled", err)
		default:
		}
	}
	reason := js.Global().Get("Error").New("private cleanup failure")
	reason.Set("name", hostCleanupErrorName)
	reject.Invoke(reason)
	for _, result := range []chan error{reads, writes} {
		if err := <-result; !errors.Is(err, net.ErrClosed) || !errors.Is(err, errHostCleanup) {
			t.Fatal("blocked I/O lost close or cleanup failure", err)
		}
	}
	if err := <-closes; !errors.Is(err, errHostCleanup) {
		t.Fatal("close lost cleanup failure", err)
	}
	if err := f.c.Close(); err != nil || f.closes != 2 {
		t.Fatal("blocked I/O cleanup could not be retried", err)
	}
}

func TestHostPumpRejectsMalformedEventsWithoutBlockingCallback(t *testing.T) {
	for _, fixture := range []struct {
		name  string
		kind  any
		value any
	}{
		{"oversized data", 1, hostPumpBytes(make([]byte, hostPumpByteCredit+1))},
		{"empty data", 1, hostPumpBytes(nil)},
		{"nonbyte data", 1, "private malformed value"},
		{"unsolicited completion", 2, 1},
		{"nonnumber completion", 2, "1"},
		{"non-null EOF", 3, 1},
		{"unknown event", 5, nil},
		{"fractional event", 1.5, nil},
		{"nonnumber event", "1", nil},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			f := newHostPumpFixture(t)
			f.receive.Invoke(fixture.kind, fixture.value)
			if _, err := f.c.Read(make([]byte, 1)); !errors.Is(err, errHostPumpContract) {
				t.Fatal("malformed event did not fail the stream", err)
			}
		})
	}
	t.Run("aggregate byte bound", func(t *testing.T) {
		f := newHostPumpFixture(t)
		f.receive.Invoke(1, hostPumpBytes(make([]byte, hostPumpByteCredit)))
		f.receive.Invoke(1, hostPumpBytes([]byte{1}))
		b, err := io.ReadAll(f.c)
		if len(b) != hostPumpByteCredit || !errors.Is(err, errHostPumpContract) {
			t.Fatal("aggregate byte credit was exceeded", len(b), err)
		}
	})
}

func TestHostPumpRetiresWithoutPerIOGoroutinesOrRegistryLeaks(t *testing.T) {
	beforePumps, beforeWaiters := len(hostPumps), len(hostWaiters)
	beforeGoroutines := runtime.NumGoroutine()
	for range 16 {
		f := newHostPumpFixture(t)
		f.receive.Invoke(1, hostPumpBytes([]byte{1}))
		if _, err := f.c.Read(make([]byte, 1)); err != nil {
			t.Fatal(err)
		}
		if _, err := f.c.Write([]byte{2}); err != nil {
			t.Fatal(err)
		}
		if err := f.c.Close(); err != nil {
			t.Fatal(err)
		}
		f.receive.Invoke(3, nil)
	}
	if len(hostPumps) != beforePumps || len(hostWaiters) != beforeWaiters || runtime.NumGoroutine() != beforeGoroutines {
		t.Fatalf("pump leaked ownership: pumps=%d/%d waiters=%d/%d goroutines=%d/%d", len(hostPumps), beforePumps, len(hostWaiters), beforeWaiters, runtime.NumGoroutine(), beforeGoroutines)
	}
}

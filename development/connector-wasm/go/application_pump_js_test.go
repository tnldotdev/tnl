//go:build js && wasm

package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"syscall/js"
	"testing"
	"time"
)

func applicationTestTLS(t *testing.T) (*byteStream, *tls.Conn) {
	t.Helper()
	s, server := mainTestStream(t, "postgres")
	serverTrust, clientTrust := mainTestTLS(t)
	s.owner.prepared.trust = clientTrust
	secure := tls.Server(server, serverTrust)
	ready := make(chan error, 1)
	go func() {
		var request [8]byte
		if _, err := io.ReadFull(server, request[:]); err != nil {
			ready <- err
			return
		}
		if _, err := server.Write([]byte{'S'}); err != nil {
			ready <- err
			return
		}
		ready <- secure.HandshakeContext(t.Context())
	}()
	if _, err := mainAwait(t, s.object.Call("startTls")); err != nil {
		t.Fatal(err)
	}
	if err := <-ready; err != nil {
		t.Fatal(err)
	}
	return s, secure
}

type applicationTestEvent struct {
	kind  int
	value js.Value
}

func applicationTestReceiver(t *testing.T, s *byteStream) (js.Func, chan applicationTestEvent) {
	t.Helper()
	events := make(chan applicationTestEvent, 16)
	receive := js.FuncOf(func(_ js.Value, args []js.Value) any {
		select {
		case events <- applicationTestEvent{args[0].Int(), args[1]}:
		default:
			t.Error("application pump flooded receiver")
		}
		return nil
	})
	t.Cleanup(func() { _ = s.close(); receive.Release() })
	return receive, events
}

func applicationTestNext(t *testing.T, events <-chan applicationTestEvent, kind int) js.Value {
	t.Helper()
	select {
	case event := <-events:
		if event.kind != kind {
			t.Fatalf("application event = %d, want %d", event.kind, kind)
		}
		return event.value
	case <-time.After(3 * time.Second):
		t.Fatal("application pump did not notify")
		return js.Undefined()
	}
}

func applicationTestBytes(data []byte) js.Value {
	value := js.Global().Get("Uint8Array").New(len(data))
	js.CopyBytesToJS(value, data)
	return value
}

func applicationRegistrySize() int {
	applicationRegistryMu.Lock()
	defer applicationRegistryMu.Unlock()
	return len(applicationRegistry)
}

func TestApplicationPumpTLSGuardAndExclusiveOwnership(t *testing.T) {
	s, server := mainTestStream(t, "postgres")
	receive, _ := applicationTestReceiver(t, s)
	if !s.object.Call("pump", receive).IsNull() {
		t.Fatal("pump admitted application bytes before TLS")
	}
	upgrade := s.object.Call("startTls")
	var request [8]byte
	if _, err := io.ReadFull(server, request[:]); err != nil {
		t.Fatal(err)
	}
	if !s.object.Call("pump", receive).IsNull() {
		t.Fatal("pump admitted application bytes during TLS")
	}
	if _, err := mainAwait(t, s.object.Call("close")); err != nil {
		t.Fatal(err)
	}
	if _, err := mainAwait(t, upgrade); err == nil {
		t.Fatal("closed TLS upgrade succeeded")
	}

	secure, _ := applicationTestTLS(t)
	receive, _ = applicationTestReceiver(t, secure)
	if !secure.object.Call("pump", 1).IsNull() {
		t.Fatal("pump accepted a non-function receiver")
	}
	if secure.object.Call("pump", receive).IsNull() {
		t.Fatal("pump rejected a completed TLS upgrade")
	}
	if !secure.object.Call("pump", receive).IsNull() {
		t.Fatal("second pump took ownership")
	}
	for _, pending := range []js.Value{
		secure.object.Call("read", 1),
		secure.object.Call("write", applicationTestBytes([]byte{1})),
	} {
		if _, err := mainAwait(t, pending); err == nil {
			t.Fatal("promise I/O bypassed pump ownership")
		}
	}
}

func TestApplicationPumpBoundedWritesReadCreditsAndEOF(t *testing.T) {
	s, server := applicationTestTLS(t)
	receive, events := applicationTestReceiver(t, s)
	before := counters
	pump := s.object.Call("pump", receive)
	if pump.IsNull() {
		t.Fatal("pump setup failed")
	}
	// the first write stays active until its entire tls payload reaches the peer.
	for index, size := range []int{applicationPumpCapacity, applicationPumpCapacity, 9} {
		input := bytes.Repeat([]byte{byte(index + 1)}, size)
		value := applicationTestBytes(input)
		if !pump.Call("write", value).Bool() {
			t.Fatal("empty write queue rejected a bounded chunk")
		}
		value.SetIndex(0, 99)
		if pump.Call("write", applicationTestBytes([]byte{9})).Bool() {
			t.Fatal("queued and active bytes exceeded 64 kib")
		}
		select {
		case event := <-events:
			t.Fatal("enqueue acknowledged before peer received bytes", event.kind)
		default:
		}
		output := make([]byte, size)
		if _, err := io.ReadFull(server, output); err != nil || !bytes.Equal(input, output) {
			t.Fatal("pump write lost bytes or retained mutable JS input", err)
		}
		if got := applicationTestNext(t, events, applicationWritten).Int(); got != size {
			t.Fatalf("write completion = %d, want %d", got, size)
		}
	}
	for _, invalid := range []any{nil, 1, js.Global().Get("Uint8Array").New(applicationPumpCapacity + 1)} {
		if pump.Call("write", invalid).Bool() {
			t.Fatal("pump accepted invalid bytes")
		}
	}
	secondStarted, secondWritten := make(chan struct{}), make(chan struct{})
	go func() {
		_, _ = server.Write([]byte{1, 2, 3})
		close(secondStarted)
		_, _ = server.Write([]byte{4, 5})
		close(secondWritten)
	}()
	if got := counters.ApplicationPumpReads - before.ApplicationPumpReads; got != 0 {
		t.Fatal("pump read without a credit")
	}
	pump.Call("resume")
	first := applicationTestNext(t, events, applicationData)
	<-secondStarted
	select {
	case <-secondWritten:
		t.Fatal("pump read a second TLS record without another credit")
	default:
	}
	if got := counters.ApplicationPumpReads - before.ApplicationPumpReads; got != 1 {
		t.Fatalf("one credit started %d reads", got)
	}
	pump.Call("resume")
	second := applicationTestNext(t, events, applicationData)
	<-secondWritten
	if first.Length() != 3 || first.Index(0).Int() != 1 || second.Length() != 2 || second.Index(0).Int() != 4 {
		t.Fatal("read buffer reuse changed owned JS bytes")
	}
	ended := make(chan error, 1)
	go func() { ended <- server.CloseWrite() }()
	pump.Call("resume")
	if !applicationTestNext(t, events, applicationEOF).IsNull() {
		t.Fatal("EOF carried a payload")
	}
	if err := <-ended; err != nil {
		t.Fatal(err)
	}
	if counters.ApplicationPromises != before.ApplicationPromises || counters.CallbackRegistrations != before.CallbackRegistrations {
		t.Fatal("pump hot path created promises or per-operation Go callbacks")
	}
	if counters.ApplicationPumpStarts-before.ApplicationPumpStarts != 1 || counters.ApplicationPumpWrites-before.ApplicationPumpWrites != 3 || counters.ApplicationPumpReads-before.ApplicationPumpReads != 3 || counters.ApplicationPumpNotifications-before.ApplicationPumpNotifications != 6 {
		t.Fatal("pump counters lost operations")
	}
	if counters.ApplicationReadAllocated-before.ApplicationReadAllocated != applicationPumpCapacity || counters.ApplicationWriteAllocated-before.ApplicationWriteAllocated != applicationPumpCapacity {
		t.Fatal("pump did not reuse bounded buffers")
	}
	if counters.ApplicationReadBytes-before.ApplicationReadBytes != 5 || counters.ApplicationWriteBytes-before.ApplicationWriteBytes != applicationPumpCapacity*2+9 {
		t.Fatal("pump byte counters lost data")
	}
}

func TestApplicationPumpCancellationJoinsAndRetiresSavedMethods(t *testing.T) {
	before := applicationRegistrySize()
	s, _ := applicationTestTLS(t)
	ctx, cancel := context.WithCancel(t.Context())
	s.ctx = ctx
	receive, events := applicationTestReceiver(t, s)
	setup := s.object.Get("pump")
	pump := setup.Invoke(receive)
	write, resume := pump.Get("write"), pump.Get("resume")
	if !write.Invoke(applicationTestBytes(make([]byte, applicationPumpCapacity))).Bool() {
		t.Fatal("write was not accepted")
	}
	resume.Invoke()
	cancel()
	if !applicationTestNext(t, events, applicationError).IsNull() {
		t.Fatal("cancellation exposed an error payload")
	}
	if _, err := mainAwait(t, s.object.Call("close")); err != nil {
		t.Fatal(err)
	}
	if applicationRegistrySize() != before {
		t.Fatal("closed pump retained registry closures")
	}
	if write.Invoke(applicationTestBytes([]byte{1})).Bool() || !setup.Invoke(receive).IsNull() {
		t.Fatal("saved methods reopened a closed pump")
	}
	resume.Invoke()
	select {
	case event := <-events:
		t.Fatal("closed pump delivered a late or repeated event", event.kind)
	default:
	}

	// the retired numeric id must not target a later healthy sibling.
	sibling, peer := applicationTestTLS(t)
	if sibling.applicationID <= s.applicationID {
		t.Fatal("application ids were reused")
	}
	receiver, siblingEvents := applicationTestReceiver(t, sibling)
	healthy := sibling.object.Call("pump", receiver)
	resume.Invoke()
	if write.Invoke(applicationTestBytes([]byte{9})).Bool() {
		t.Fatal("retired write reached a healthy sibling")
	}
	if !healthy.Call("write", applicationTestBytes([]byte{7})).Bool() {
		t.Fatal("sibling was closed with its peer")
	}
	var output [1]byte
	if _, err := io.ReadFull(peer, output[:]); err != nil || output[0] != 7 {
		t.Fatal("healthy sibling lost bytes", err)
	}
	applicationTestNext(t, siblingEvents, applicationWritten)
}

type applicationFailConn struct{ net.Conn }

func (applicationFailConn) Read([]byte) (int, error)  { return 0, errors.New("private read detail") }
func (applicationFailConn) Write([]byte) (int, error) { return 0, errors.New("private write detail") }

func TestApplicationPumpConcurrentFailuresNotifyOnce(t *testing.T) {
	s, _ := applicationTestTLS(t)
	s.conn = applicationFailConn{s.conn}
	receive, events := applicationTestReceiver(t, s)
	pump := s.object.Call("pump", receive)
	pump.Call("write", applicationTestBytes([]byte{1}))
	pump.Call("resume")
	if !applicationTestNext(t, events, applicationError).IsNull() {
		t.Fatal("pump error included private details")
	}
	if _, err := mainAwait(t, s.object.Call("close")); err != nil {
		t.Fatal(err)
	}
	select {
	case event := <-events:
		t.Fatal("concurrent failures emitted another notification", event.kind)
	default:
	}
}

func TestApplicationPumpCloseInterruptsBlockedIO(t *testing.T) {
	s, server := applicationTestTLS(t)
	receive, events := applicationTestReceiver(t, s)
	pump := s.object.Call("pump", receive)
	pump.Call("write", applicationTestBytes(make([]byte, applicationPumpCapacity)))
	pump.Call("resume")
	// reading only the start of the first tls record leaves the writer blocked
	// on later records and the reader blocked waiting for any peer application data.
	var first [1]byte
	if _, err := io.ReadFull(server, first[:]); err != nil {
		t.Fatal(err)
	}
	if _, err := mainAwait(t, s.object.Call("close")); err != nil {
		t.Fatal(err)
	}
	select {
	case event := <-events:
		t.Fatal("explicit close delivered a late event", event.kind)
	default:
	}
}

func TestApplicationPumpReceiverExceptionDoesNotEscapeGo(t *testing.T) {
	s, server := applicationTestTLS(t)
	finished := js.Global().Get("Promise").Call("withResolvers")
	// a throwing js receiver must still acknowledge dispatcher delivery so close
	// can join the worker. only the one terminal error completes this fixture.
	receive := js.Global().Get("Function").New("finish", `return (kind, value) => {
		if (kind === 4) finish(value);
		throw new Error("private receiver detail");
	}`).Invoke(finished.Get("resolve"))
	pump := s.object.Call("pump", receive)
	pump.Call("resume")
	go func() { _, _ = server.Write([]byte{1}) }()
	if value, err := mainAwait(t, finished.Get("promise")); err != nil || !value.IsNull() {
		t.Fatal("receiver exception escaped or exposed an error payload", err)
	}
	if _, err := mainAwait(t, s.object.Call("close")); err != nil {
		t.Fatal(err)
	}
}

func TestApplicationPumpCloseJoinsQueuedDelivery(t *testing.T) {
	s, server := applicationTestTLS(t)
	closed := make(chan js.Value, 1)
	calls := 0
	receive := js.FuncOf(func(_ js.Value, args []js.Value) any {
		calls++
		// close is asynchronous; the callback must return before go can join it.
		select {
		case closed <- s.object.Call("close"):
		default:
			t.Error("closed stream received another callback")
		}
		return nil
	})
	defer receive.Release()
	pump := s.object.Call("pump", receive)
	pump.Call("resume")
	go func() { _, _ = server.Write([]byte{1}) }()
	select {
	case closing := <-closed:
		if _, err := mainAwait(t, closing); err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("notification could not close and join its pump")
	}
	if calls != 1 {
		t.Fatal("closed stream received another callback")
	}
}

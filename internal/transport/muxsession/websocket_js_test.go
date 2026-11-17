package muxsession

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"math"
	"net"
	"os"
	"runtime"
	"sync"
	"syscall/js"
	"testing"
	"time"
)

// the fake host never completes close automatically. these tests must release
// Go callbacks and blocked I/O without relying on a host close handshake.
func fakeHostWebSocket(t *testing.T) {
	t.Helper()
	original := js.Global().Get("WebSocket")
	js.Global().Call("eval", `
		globalThis.WebSocket = class extends EventTarget {
			static current;
			constructor(url, protocols) {
				super();
				this.url = url;
				this.protocol = protocols[0];
				this.extensions = "";
				this.readyState = 0;
				this.bufferedAmount = 0;
				this.sent = [];
				this.listeners = 0;
				globalThis.WebSocket.current = this;
			}
			addEventListener(...args) { this.listeners++; super.addEventListener(...args); }
			removeEventListener(...args) { this.listeners--; super.removeEventListener(...args); }
			start() { this.readyState = 1; this.dispatchEvent(new Event("open")); }
			receive(data) { this.dispatchEvent(new MessageEvent("message", {data})); }
			send(data) { this.sent.push(data.slice()); this.bufferedAmount += data.byteLength; }
			close() { this.readyState = 2; this.closed = true; }
		};
	`)
	t.Cleanup(func() { js.Global().Set("WebSocket", original) })
}

func fakeHostSocket() js.Value { return js.Global().Get("WebSocket").Get("current") }

func openFakeHostNetwork(t *testing.T) *hostWebSocketNetwork {
	t.Helper()
	fakeHostWebSocket(t)
	// constructing the host is synchronous; opening is a later event turn.
	ready := js.FuncOf(func(js.Value, []js.Value) any { fakeHostSocket().Call("start"); return nil })
	defer ready.Release()
	js.Global().Call("setTimeout", ready, 0)
	network, err := dialHostWebSocket(t.Context(), "wss://relay.test:443"+WebSocketPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = network.Close() })
	return network
}

func hostBinary(p []byte) js.Value {
	array := js.Global().Get("Uint8Array").New(len(p))
	js.CopyBytesToJS(array, p)
	return array.Get("buffer")
}

func TestWASMWebSocketHostPolicy(t *testing.T) {
	fakeHostWebSocket(t)
	for _, test := range []struct {
		name      string
		connector WebSocketConnector
		endpoint  Endpoint
		code      string
	}{
		{"native TLS", WebSocketConnector{TLSConfig: &tls.Config{}}, Endpoint{"relay.test:443", "relay.test"}, "host_options_unsupported"},
		{"insecure TLS", WebSocketConnector{TLSConfig: &tls.Config{InsecureSkipVerify: true}}, Endpoint{"relay.test:443", "relay.test"}, "host_options_unsupported"},
		{"native dialer", WebSocketConnector{Config: WebSocketConfig{Dialer: new(net.Dialer)}}, Endpoint{"relay.test:443", "relay.test"}, "host_options_unsupported"},
		{"native proxy", WebSocketConnector{Config: WebSocketConfig{DisableProxy: true}}, Endpoint{"relay.test:443", "relay.test"}, "host_options_unsupported"},
		{"hostname override", WebSocketConnector{}, Endpoint{"127.0.0.1:443", "relay.test"}, "endpoint_invalid"},
		{"plaintext URL", WebSocketConnector{}, Endpoint{"ws://relay.test:443", "relay.test"}, "endpoint_invalid"},
		{"invalid port", WebSocketConnector{}, Endpoint{"relay.test:0", "relay.test"}, "endpoint_invalid"},
		{"missing server", WebSocketConnector{}, Endpoint{"relay.test:443", ""}, "endpoint_invalid"},
		{"URL syntax", WebSocketConnector{}, Endpoint{"relay.test/path:443", "relay.test/path"}, "endpoint_invalid"},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := test.connector.Connect(t.Context(), test.endpoint)
			var failure *WebSocketError
			if !errors.As(err, &failure) || failure.Code != test.code {
				t.Fatalf("expected %s, got %v", test.code, err)
			}
		})
	}
	if !fakeHostSocket().IsUndefined() {
		t.Fatal("invalid options reached the host constructor")
	}
}

func TestWASMWebSocketSessionCapabilitiesAndSetupCancellation(t *testing.T) {
	fakeHostWebSocket(t)
	ready := js.FuncOf(func(js.Value, []js.Value) any { fakeHostSocket().Call("start"); return nil })
	defer ready.Release()
	js.Global().Call("setTimeout", ready, 0)
	ctx, cancel := context.WithCancel(t.Context())
	session, err := (WebSocketConnector{}).Connect(ctx, Endpoint{"relay.test:443", "relay.test"})
	cancel()
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := session.(AcceptedPeer); ok {
		t.Fatal("host session invented native peer metadata")
	}
	if _, ok := session.(DatagramSession); ok {
		t.Fatal("host session advertised UDP datagrams")
	}
	if fakeHostSocket().Get("url").String() != "wss://relay.test:443"+WebSocketPath ||
		fakeHostSocket().Get("binaryType").String() != "arraybuffer" {
		t.Fatal("host connection lost WSS path or binary transport")
	}
	select {
	case <-session.Done():
		t.Fatal("setup cancellation stopped the established session")
	default:
	}
	if err := session.Close(); err != nil {
		t.Fatal(err)
	}
	if fakeHostSocket().Get("listeners").Int() != 0 {
		t.Fatal("close leaked Go callbacks")
	}
}

func TestWASMWebSocketUsesYamuxReceiptsWhenHostHasNoCapacitySignal(t *testing.T) {
	fakeHostWebSocket(t)
	ready := js.FuncOf(func(js.Value, []js.Value) any {
		fakeHostSocket().Set("bufferedAmount", js.Undefined())
		fakeHostSocket().Call("start")
		return nil
	})
	defer ready.Release()
	js.Global().Call("setTimeout", ready, 0)
	session, err := (WebSocketConnector{}).Connect(t.Context(), Endpoint{"relay.test:443", "relay.test"})
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	yamux := session.(hostWebSocketSession).Session.(*yamuxSession)
	receipts, ok := yamux.network.(*yamuxReceiptConn)
	if !ok || !receipts.Conn.(*hostWebSocketNetwork).receipts {
		t.Fatal("unobservable host capacity bypassed the receipt budget")
	}
}

func TestWASMWebSocketReadBoundsAndByteChunks(t *testing.T) {
	t.Run("chunks", func(t *testing.T) {
		network := openFakeHostNetwork(t)
		payload := bytes.Repeat([]byte("x"), WebSocketMaxBytes+1)
		for _, part := range [][]byte{payload[:1], payload[1:WebSocketMaxBytes], payload[WebSocketMaxBytes:]} {
			fakeHostSocket().Call("receive", hostBinary(part))
		}
		got := make([]byte, len(payload))
		if _, err := io.ReadFull(network, got); err != nil || !bytes.Equal(got, payload) {
			t.Fatal("message boundaries changed byte stream", err)
		}
	})
	for _, kind := range []string{"text", "oversized", "byte budget", "message budget"} {
		t.Run(kind, func(t *testing.T) {
			network := openFakeHostNetwork(t)
			switch kind {
			case "text":
				fakeHostSocket().Call("receive", "not binary")
			case "oversized":
				fakeHostSocket().Call("receive", hostBinary(make([]byte, WebSocketMaxBytes+1)))
			case "byte budget":
				for range webSocketBufferedBytes/WebSocketMaxBytes + 1 {
					fakeHostSocket().Call("receive", hostBinary(make([]byte, WebSocketMaxBytes)))
				}
			case "message budget":
				for range webSocketReadMessages + 1 {
					fakeHostSocket().Call("receive", hostBinary([]byte{1}))
				}
			}
			if _, err := network.Read(make([]byte, 1)); err == nil {
				t.Fatal("invalid or unbounded input accepted")
			}
			if fakeHostSocket().Get("listeners").Int() != 0 {
				t.Fatal("input rejection leaked callbacks")
			}
		})
	}
}

func TestWASMWebSocketWriteBackpressureAndDeadline(t *testing.T) {
	network := openFakeHostNetwork(t)
	payload := make([]byte, 2*WebSocketMaxBytes+1)
	if n, err := network.Write(payload); err != nil || n != len(payload) {
		t.Fatal(n, err)
	}
	sent := fakeHostSocket().Get("sent")
	if sent.Length() != 3 || sent.Index(0).Get("byteLength").Int() != WebSocketMaxBytes {
		t.Fatal("writes were not bounded binary chunks")
	}
	fakeHostSocket().Set("bufferedAmount", webSocketBufferedBytes)
	_ = network.SetWriteDeadline(time.Now().Add(20 * time.Millisecond))
	if n, err := network.Write([]byte("blocked")); n != 0 || !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatal("backpressure ignored write deadline", n, err)
	}
	if sent.Length() != 3 {
		t.Fatal("write exceeded host buffer budget")
	}
	_ = network.SetWriteDeadline(time.Time{})
	// a host drain allows the blocked write to proceed on a later poll.
	drain := js.FuncOf(func(js.Value, []js.Value) any { fakeHostSocket().Set("bufferedAmount", 0); return nil })
	defer drain.Release()
	js.Global().Call("setTimeout", drain, 0)
	if n, err := network.Write([]byte("drained")); n != 7 || err != nil {
		t.Fatal(n, err)
	}
}

func TestWASMWebSocketCloseUnblocksIOWithoutHostHandshake(t *testing.T) {
	network := openFakeHostNetwork(t)
	fakeHostSocket().Set("bufferedAmount", webSocketBufferedBytes)
	read := make(chan error, 1)
	write := make(chan error, 1)
	go func() { _, err := network.Read(make([]byte, 1)); read <- err }()
	go func() { _, err := network.Write([]byte("blocked")); write <- err }()
	awaitHostIO(t, &network.readMu)
	awaitHostIO(t, &network.writeMu)
	if err := network.Close(); err != nil {
		t.Fatal(err)
	}
	for _, completed := range []<-chan error{read, write} {
		select {
		case err := <-completed:
			if !errors.Is(err, net.ErrClosed) {
				t.Fatal(err)
			}
		case <-time.After(time.Second):
			t.Fatal("close did not release I/O")
		}
	}
	if fakeHostSocket().Get("listeners").Int() != 0 {
		t.Fatal("close leaked Go callbacks")
	}
}

func awaitHostIO(t *testing.T, lock *sync.Mutex) {
	t.Helper()
	for range 1000 {
		if !lock.TryLock() {
			return
		}
		lock.Unlock()
		runtime.Gosched()
	}
	t.Fatal("host I/O did not start")
}

func TestWASMWebSocketReadDeadlineCanBeCleared(t *testing.T) {
	network := openFakeHostNetwork(t)
	_ = network.SetReadDeadline(time.Now().Add(-time.Second))
	if _, err := network.Read(make([]byte, 1)); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatal(err)
	}
	_ = network.SetReadDeadline(time.Time{})
	fakeHostSocket().Call("receive", hostBinary([]byte("x")))
	var got [1]byte
	if n, err := network.Read(got[:]); n != 1 || err != nil || got[0] != 'x' {
		t.Fatal(n, err, got)
	}
}

func TestWASMWebSocketReadDeadlineInterruptsBlockedRead(t *testing.T) {
	network := openFakeHostNetwork(t)
	result := make(chan error, 1)
	go func() { _, err := network.Read(make([]byte, 1)); result <- err }()
	awaitHostIO(t, &network.readMu)
	_ = network.SetReadDeadline(time.Now().Add(-time.Second))
	select {
	case err := <-result:
		if !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("deadline change did not interrupt blocked read")
	}
}

func TestWASMWebSocketRemoteClosePreservesQueuedBytes(t *testing.T) {
	network := openFakeHostNetwork(t)
	fakeHostSocket().Call("receive", hostBinary([]byte("final bytes")))
	network.finish(io.EOF)
	got, err := io.ReadAll(network)
	if err != nil || string(got) != "final bytes" {
		t.Fatal("remote close discarded received bytes", string(got), err)
	}
}

func TestWASMWebSocketCannotInventSendCapacity(t *testing.T) {
	for _, amount := range []any{js.Undefined(), -1, math.NaN(), math.Inf(1)} {
		network := openFakeHostNetwork(t)
		fakeHostSocket().Set("bufferedAmount", amount)
		if _, err := network.Write([]byte("not sent")); err == nil {
			t.Fatal("unobservable send budget accepted", amount)
		}
		if fakeHostSocket().Get("sent").Length() != 0 {
			t.Fatal("sent without observable capacity", amount)
		}
	}
}

func TestWASMWebSocketHostCloseFailureIsPreserved(t *testing.T) {
	network := openFakeHostNetwork(t)
	js.Global().Call("eval", `WebSocket.current.close = () => { throw new Error("secret host details"); };`)
	if err := network.Close(); err == nil || err.Error() != "muxsession: host websocket operation failed" {
		t.Fatal("lost close failure or leaked host details", err)
	}
	if fakeHostSocket().Get("listeners").Int() != 0 {
		t.Fatal("failed host close retained Go callbacks")
	}
}

func TestWASMWebSocketAcceptFailsClosed(t *testing.T) {
	accepted, remote := net.Pipe()
	defer remote.Close()
	session, err := AcceptWebSocket(t.Context(), accepted, &tls.Config{}, WebSocketConfig{})
	if session != nil || !errors.Is(err, errors.ErrUnsupported) {
		t.Fatal("host accepted transport without source or TLS authority", session, err)
	}
	if _, err := remote.Write([]byte("closed")); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatal("unsupported accept leaked supplied connection", err)
	}
}

func TestWASMWebSocketDialCancellationAndHostFailures(t *testing.T) {
	for _, kind := range []string{"cancel", "wrong protocol", "compression", "invalid send budget", "error"} {
		t.Run(kind, func(t *testing.T) {
			fakeHostWebSocket(t)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			event := js.FuncOf(func(js.Value, []js.Value) any {
				switch kind {
				case "cancel":
					cancel()
				case "wrong protocol":
					fakeHostSocket().Set("protocol", "")
					fakeHostSocket().Call("start")
				case "compression":
					fakeHostSocket().Set("extensions", "permessage-deflate")
					fakeHostSocket().Call("start")
				case "invalid send budget":
					fakeHostSocket().Set("bufferedAmount", math.NaN())
					fakeHostSocket().Call("start")
				case "error":
					fakeHostSocket().Call("dispatchEvent", js.Global().Get("Event").New("error"))
				}
				return nil
			})
			defer event.Release()
			js.Global().Call("setTimeout", event, 0)
			_, err := dialHostWebSocket(ctx, "wss://relay.test:443"+WebSocketPath)
			if err == nil || kind == "cancel" && !errors.Is(err, context.Canceled) {
				t.Fatal("failed setup accepted", err)
			}
			if kind == "invalid send budget" && !errors.Is(err, errors.ErrUnsupported) {
				t.Fatal("invalid host send budget was not rejected explicitly", err)
			}
			if fakeHostSocket().Get("listeners").Int() != 0 || !fakeHostSocket().Get("closed").Bool() {
				t.Fatal("failed setup retained host callbacks or socket")
			}
		})
	}
}

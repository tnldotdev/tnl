//go:build js && wasm

package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"strings"
	"syscall/js"
	"testing"
	"time"
)

// these fixtures exercise only JS resource dispatch and the application pipe;
// they do not stand in for connector preparation or a real publisher.
func mainTestStream(t *testing.T, protocol string) (*byteStream, net.Conn) {
	t.Helper()
	app, server := net.Pipe()
	eof := make(chan struct{})
	raw := &applicationConn{Conn: app, eof: eof}
	h := &handle{prepared: &prepared{protocol: protocol, hostname: "service.test", trust: &tls.Config{}}, streams: make(map[*byteStream]struct{})}
	s := &byteStream{owner: h, ctx: t.Context(), conn: raw, raw: raw, eof: eof, done: make(chan struct{})}
	close(s.done)
	h.streams[s] = struct{}{}
	s.export()
	t.Cleanup(func() { _ = s.close(); _ = server.Close() })
	return s, server
}

func mainAwait(t *testing.T, p js.Value) (js.Value, error) {
	t.Helper()
	if p.IsUndefined() || p.IsNull() || p.Get("then").Type() != js.TypeFunction {
		t.Fatal("exported method did not return a Promise")
	}
	type result struct {
		value js.Value
		err   error
	}
	done := make(chan result, 1)
	resolve := js.FuncOf(func(_ js.Value, args []js.Value) any { done <- result{value: args[0]}; return nil })
	reject := js.FuncOf(func(_ js.Value, args []js.Value) any {
		done <- result{err: errors.New(args[0].Get("message").String())}
		return nil
	})
	defer resolve.Release()
	defer reject.Release()
	p.Call("then", resolve, reject)
	select {
	case r := <-done:
		return r.value, r.err
	case <-time.After(3 * time.Second):
		t.Fatal("exported Promise did not settle")
		return js.Undefined(), context.DeadlineExceeded
	}
}

func registrySize() int { methodMu.Lock(); defer methodMu.Unlock(); return len(methodRegistry) }

func TestSavedStreamMethodsRemainPromisesAfterClose(t *testing.T) {
	before := registrySize()
	s, _ := mainTestStream(t, "tcp")
	read, write, upgrade, closeMethod := s.object.Get("read"), s.object.Get("write"), s.object.Get("startTls"), s.object.Get("close")
	if _, err := mainAwait(t, closeMethod.Invoke()); err != nil {
		t.Fatal(err)
	}
	for _, p := range []js.Value{read.Invoke(1), write.Invoke(js.Global().Get("Uint8Array").New(1)), upgrade.Invoke()} {
		if _, err := mainAwait(t, p); err == nil {
			t.Fatal("saved method used a closed stream")
		}
	}
	if _, err := mainAwait(t, closeMethod.Invoke()); err != nil {
		t.Fatal("saved close was not idempotent", err)
	}
	if got := registrySize(); got != before {
		t.Fatalf("closed stream retained registry entries: %d -> %d", before, got)
	}
}

func TestSavedHandleCloseRetriesFailureBeforeRetiringMethods(t *testing.T) {
	before := registrySize()
	calls := 0
	b := testBackend(t, func() int {
		calls++
		if calls == 1 {
			return http.StatusServiceUnavailable
		}
		return http.StatusNoContent
	})
	h := &handle{prepared: &prepared{backend: b}, streams: make(map[*byteStream]struct{})}
	// this fixture starts after joined transport cleanup, isolating the exported
	// close/retry boundary without manufacturing another connector engine.
	h.once.Do(func() { h.closed = true })
	h.object = js.Global().Get("Object").New()
	bind(h.object, "close", &h.funcs, func([]js.Value) (any, error) { return nil, h.close() })
	bind(h.object, "open", &h.funcs, func([]js.Value) (any, error) { return h.open() })
	closeMethod, open := h.object.Get("close"), h.object.Get("open")
	if _, err := mainAwait(t, closeMethod.Invoke()); err == nil {
		t.Fatal("close hid failed revocation")
	}
	if registrySize() != before+1 {
		t.Fatal("failed close discarded its retry owner")
	}
	if _, err := mainAwait(t, open.Invoke()); err == nil {
		t.Fatal("failed cleanup reopened a retired connection")
	}
	if _, err := mainAwait(t, closeMethod.Invoke()); err != nil {
		t.Fatal(err)
	}
	if _, err := mainAwait(t, closeMethod.Invoke()); err != nil {
		t.Fatal("saved handle close was not idempotent", err)
	}
	if registrySize() != before || calls != 2 {
		t.Fatal("successful retry leaked methods or repeated revocation")
	}
}

func TestConcurrentStreamCloseJoinsPendingRead(t *testing.T) {
	s, _ := mainTestStream(t, "tcp")
	read := s.object.Call("read", 1)
	closeMethod := s.object.Get("close")
	first, second := closeMethod.Invoke(), closeMethod.Invoke()
	if _, err := mainAwait(t, first); err != nil {
		t.Fatal(err)
	}
	if _, err := mainAwait(t, second); err != nil {
		t.Fatal(err)
	}
	if _, err := mainAwait(t, read); err == nil {
		t.Fatal("closed pending read became a clean EOF")
	}
}

func TestPostgresRejectsIOBeforeTLSAndConcurrentUpgrade(t *testing.T) {
	s, server := mainTestStream(t, "postgres")
	if _, err := mainAwait(t, s.object.Call("read", 1)); err == nil {
		t.Fatal("postgres read started before TLS")
	}
	if _, err := mainAwait(t, s.object.Call("write", js.Global().Get("Uint8Array").New(1))); err == nil {
		t.Fatal("postgres write started before TLS")
	}
	upgrade := s.object.Call("startTls")
	var request [8]byte
	if _, err := io.ReadFull(server, request[:]); err != nil {
		t.Fatal(err)
	}
	if _, err := mainAwait(t, s.object.Call("startTls")); err == nil {
		t.Fatal("concurrent upgrade was admitted")
	}
	if _, err := mainAwait(t, s.object.Call("read", 1)); err == nil {
		t.Fatal("read blocked behind an incomplete TLS upgrade")
	}
	if _, err := mainAwait(t, s.object.Call("close")); err != nil {
		t.Fatal(err)
	}
	if _, err := mainAwait(t, upgrade); err == nil {
		t.Fatal("closed upgrade succeeded")
	}
}

func mainTestTLS(t *testing.T) (*tls.Config, *tls.Config) {
	t.Helper()
	public, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert := &x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: []string{"service.test"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, public, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	return &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}, MinVersion: tls.VersionTLS13}, &tls.Config{RootCAs: pool, ServerName: "service.test", MinVersion: tls.VersionTLS13}
}

func TestStreamCleanHalfCloseDoesNotSwallowTLSTruncation(t *testing.T) {
	plain, _ := mainTestStream(t, "tcp")
	close(plain.eof)
	_ = plain.raw.SetReadDeadline(time.Now())
	if value, err := mainAwait(t, plain.object.Call("read", 1)); err != nil || !value.IsNull() {
		t.Fatalf("clean half-close = %v, %v", value, err)
	}
	s, server := mainTestStream(t, "postgres")
	serverTrust, clientTrust := mainTestTLS(t)
	clientTLS := tls.Client(s.raw, clientTrust)
	serverTLS := tls.Server(server, serverTrust)
	handshake := make(chan error, 1)
	go func() { handshake <- serverTLS.HandshakeContext(t.Context()) }()
	if err := clientTLS.HandshakeContext(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := <-handshake; err != nil {
		t.Fatal(err)
	}
	s.conn, s.phase = clientTLS, streamSecure
	sent := make(chan struct{})
	go func() {
		defer close(sent)
		_, _ = server.Write([]byte{23, 3, 3, 0, 16, 0, 0})
		close(s.eof)
		_ = s.raw.SetReadDeadline(time.Now())
	}()
	if _, err := mainAwait(t, s.object.Call("read", 64)); err == nil || !strings.Contains(err.Error(), "unexpected EOF") {
		t.Fatalf("TLS truncation was swallowed: %v", err)
	}
	<-sent
}

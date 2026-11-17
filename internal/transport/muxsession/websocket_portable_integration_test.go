package muxsession_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/testutil"
	"github.com/tnldotdev/tnl/internal/testutil/visitorfixture"
	"github.com/tnldotdev/tnl/internal/transport/muxsession"
	"github.com/tnldotdev/tnl/internal/transport/tunnel"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

func TestIntegrationWebSocketPortableClient(t *testing.T) {
	testWebSocketPortableClient(t, "../../../packages/ts/test/fixtures/relay-websocket-native.ts", "")
}

func TestIntegrationWebSocketWASMClient(t *testing.T) {
	testWebSocketWASMClient(t, "testdata/websocket-wasm.ts")
}

func TestIntegrationWebSocketWorkerdClient(t *testing.T) {
	testWebSocketWASMClient(t, "testdata/websocket-workerd.ts")
}

func testWebSocketWASMClient(t *testing.T, fixture string) {
	t.Helper()
	testutil.RequireTestTier(t, testutil.TestTierIntegration)
	wasm := filepath.Join(t.TempDir(), "websocket.wasm")
	build := exec.CommandContext(t.Context(), "go", "build", "-o", wasm, "./testdata/websocketwasm")
	build.Env = append(os.Environ(), "GOOS=js", "GOARCH=wasm")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build executable WASM fixture: %v\n%s", err, output)
	}
	testWebSocketPortableClient(t, fixture, wasm)
}

func testWebSocketPortableClient(t *testing.T, fixture, wasm string) {
	t.Helper()
	testutil.RequireTestTier(t, testutil.TestTierIntegration)
	certificate := visitorfixture.Certificate(t, "localhost")
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		connection, err := listener.Accept()
		if err != nil {
			done <- err
			return
		}
		stop := context.AfterFunc(ctx, func() { _ = connection.Close() })
		defer stop()
		transport, err := muxsession.AcceptWebSocket(ctx, connection, &tls.Config{Certificates: []tls.Certificate{certificate}}, muxsession.WebSocketConfig{})
		if err != nil {
			if setup, ok := err.(*muxsession.WebSocketError); ok {
				t.Logf("fixture websocket setup: code=%s cause=%v", setup.Code, setup.Err)
			}
			done <- err
			return
		}
		defer transport.Close()
		state := transport.(muxsession.AcceptedPeer).TLSConnectionState()
		hybrid := fixture != "testdata/websocket-workerd.ts"
		if state.Version != tls.VersionTLS13 || hybrid && state.CurveID != tls.X25519MLKEM768 ||
			!hybrid && state.CurveID != tls.X25519 && state.CurveID != tls.CurveP256 {
			done <- io.ErrUnexpectedEOF
			return
		}
		t.Logf("outer WSS negotiated TLS 1.3 with %s", state.CurveID)
		session, _, err := tunnel.Accept(ctx, transport, func(_ context.Context, hello tunnelv1.Message) error {
			if hello.Role != tunnelv1.Ingress || hello.Credential != "portable-fixture-only" {
				return &tunnel.ProtocolError{Code: tunnelv1.Unauthenticated}
			}
			return nil
		})
		if err != nil {
			done <- err
			return
		}
		var workers sync.WaitGroup
		defer func() { _ = session.Close(); workers.Wait() }()
		results := make(chan error, 3)
		for range 2 {
			stream, err := transport.AcceptStream(ctx)
			if err != nil {
				done <- err
				return
			}
			workers.Go(func() {
				defer stream.Close()
				data, err := io.ReadAll(stream)
				if err == nil {
					_, err = stream.Write(data)
				}
				if err == nil {
					err = stream.CloseWrite()
				}
				results <- err
			})
		}
		workers.Go(func() {
			stream, err := transport.OpenStream(ctx)
			if err != nil {
				results <- err
				return
			}
			defer stream.Close()
			_, err = io.WriteString(stream, "server-open")
			if err == nil {
				err = stream.CloseWrite()
			}
			var response []byte
			if err == nil {
				response, err = io.ReadAll(stream)
			}
			if err == nil && string(response) != "server-open" {
				err = io.ErrUnexpectedEOF
			}
			results <- err
		})
		workers.Wait()
		for range 3 {
			if err := <-results; err != nil {
				done <- err
				return
			}
		}
		// CloseWrite queues a FIN; it does not prove the client received the
		// response. let the client finish reading before retiring its transport.
		select {
		case <-transport.Done():
		case <-ctx.Done():
			done <- context.Cause(ctx)
			return
		}
		done <- nil
	}()
	var hello bytes.Buffer
	if err := tunnelv1.WriteControl(&hello, tunnelv1.Message{Type: tunnelv1.Hello, ProtocolVersion: tunnelv1.Version, Role: tunnelv1.Ingress, Credential: "portable-fixture-only"}); err != nil {
		t.Fatal(err)
	}
	_, port, _ := net.SplitHostPort(listener.Addr().String())
	leaf, err := x509.ParseCertificate(certificate.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	pin := sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
	parameters := map[string]any{"server": "wss://localhost:" + port + muxsession.WebSocketPath, "hello": hello.Bytes(), "spki": base64.StdEncoding.EncodeToString(pin[:])}
	if wasm != "" {
		parameters["wasm"] = wasm
		parameters["wasmExec"] = filepath.Join(runtime.GOROOT(), "lib", "wasm", "wasm_exec.js")
	}
	if fixture == "testdata/websocket-workerd.ts" {
		parameters["certificate"] = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Raw}))
	}
	input, err := json.Marshal(parameters)
	if err != nil {
		t.Fatal(err)
	}
	command := exec.CommandContext(ctx, "node", fixture)
	command.Stdin = bytes.NewReader(input)
	output, runErr := command.CombinedOutput()
	cancel()
	_ = listener.Close()
	serverErr := <-done
	if runErr != nil || serverErr != nil || string(output) != "ok\n" {
		t.Fatalf("portable WebSocket conformance: process=%v server=%v output=%s", runErr, serverErr, output)
	}
}

package muxsession_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os/exec"
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
		if state.Version != tls.VersionTLS13 || state.CurveID != tls.X25519MLKEM768 {
			done <- fmt.Errorf("Chrome relay TLS: want TLS 1.3 with X25519MLKEM768, got version %#x with %s", state.Version, state.CurveID)
			return
		}
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
			var response []byte
			if err == nil {
				response, err = io.ReadAll(stream)
			}
			if err == nil && string(response) != "server-open" {
				err = fmt.Errorf("server-open stream did not receive the complete echo")
			}
			// the FIN acknowledges that Go consumed the browser's echo.
			if err == nil {
				err = stream.CloseWrite()
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
		// the browser must observe every response before the server closes.
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
	input, err := json.Marshal(map[string]any{"server": "wss://localhost:" + port + muxsession.WebSocketPath, "hello": hello.Bytes(), "spki": base64.StdEncoding.EncodeToString(pin[:])})
	if err != nil {
		t.Fatal(err)
	}
	command := exec.CommandContext(ctx, "node", "../../../packages/ts/test/fixtures/relay-websocket-native.ts")
	command.Stdin = bytes.NewReader(input)
	output, runErr := command.CombinedOutput()
	if runErr != nil {
		cancel()
		_ = listener.Close()
	}
	serverErr := <-done
	if runErr != nil || serverErr != nil || string(output) != "ok\n" {
		t.Fatalf("portable WebSocket conformance: process=%v server=%v output=%s", runErr, serverErr, output)
	}
}

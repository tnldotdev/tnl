package muxsession

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
)

func webSocketTestListener(t *testing.T) (net.Listener, *tls.Config, *tls.Config) {
	t.Helper()
	server, client := testTLSConfigs(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	return listener, server, client
}

func TestWebSocketSessionSurvivesSetupCancellation(t *testing.T) {
	listener, serverTLS, clientTLS := webSocketTestListener(t)
	setup, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	type result struct {
		session Session
		err     error
	}
	accepted := make(chan result, 1)
	go func() {
		connection, err := listener.Accept()
		if err != nil {
			accepted <- result{err: err}
			return
		}
		session, err := AcceptWebSocket(setup, connection, serverTLS, WebSocketConfig{})
		accepted <- result{session, err}
	}()
	client, err := (WebSocketConnector{TLSConfig: clientTLS, Config: WebSocketConfig{DisableProxy: true}}).Connect(setup,
		Endpoint{Address: listener.Addr().String(), ServerName: "relay.test"})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	server := <-accepted
	if server.err != nil {
		t.Fatal(server.err)
	}
	defer server.session.Close()
	cancel()
	peer := server.session.(AcceptedPeer)
	state := peer.TLSConnectionState()
	if state.ServerName != "relay.test" || state.NegotiatedProtocol != "" && state.NegotiatedProtocol != "http/1.1" ||
		state.CurveID != tls.X25519MLKEM768 || state.Version != tls.VersionTLS13 {
		t.Fatal("lost accepted transport TLS facts", state)
	}
	if _, ok := peer.RemoteAddr().(*net.TCPAddr); !ok {
		t.Fatal("lost socket source authority")
	}
	if _, ok := server.session.(DatagramSession); ok {
		t.Fatal("WSS advertised datagrams")
	}
	stream, err := client.OpenStream(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	incoming, err := server.session.AcceptStream(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer incoming.Close()
	payload := bytes.Repeat([]byte("portable"), 20000)
	written := make(chan error, 1)
	go func() { _, err := stream.Write(payload); written <- errors.Join(err, stream.CloseWrite()) }()
	got, err := io.ReadAll(incoming)
	if err != nil || !bytes.Equal(got, payload) {
		t.Fatal("lost chunked stream bytes", err, len(got))
	}
	if err := <-written; err != nil {
		t.Fatal(err)
	}
}

func TestWebSocketUsesConnectProxyWithoutExposingCredentials(t *testing.T) {
	listener, serverTLS, roots := webSocketTestListener(t)
	accepted := make(chan error, 1)
	go func() {
		connection, err := listener.Accept()
		if err != nil {
			accepted <- err
			return
		}
		session, err := AcceptWebSocket(t.Context(), connection, serverTLS, WebSocketConfig{})
		if session != nil {
			defer session.Close()
			<-session.Done()
		}
		accepted <- err
	}()
	var workers sync.WaitGroup
	connect := make(chan string, 1)
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodConnect || request.Host != "relay.test:443" ||
			request.Header.Get("Proxy-Authorization") != "Basic dXNlcjpzZWNyZXQ=" {
			t.Error("incorrect CONNECT destination or authentication")
			http.Error(w, "denied", http.StatusProxyAuthRequired)
			return
		}
		connect <- request.Host
		target, err := net.Dial("tcp", listener.Addr().String())
		if err != nil {
			t.Error(err)
			return
		}
		connection, buffered, err := w.(http.Hijacker).Hijack()
		if err != nil {
			_ = target.Close()
			t.Error(err)
			return
		}
		_, _ = buffered.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n")
		_ = buffered.Flush()
		workers.Go(func() {
			defer connection.Close()
			defer target.Close()
			copied := make(chan struct{})
			go func() { defer close(copied); _, _ = io.Copy(target, buffered); _ = target.Close() }()
			_, _ = io.Copy(connection, target)
			_ = connection.Close()
			<-copied
		})
	}))
	defer proxy.Close()
	t.Setenv("HTTPS_PROXY", "http://user:secret@"+proxy.Listener.Addr().String())
	t.Setenv("NO_PROXY", "")
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	client, err := (WebSocketConnector{TLSConfig: roots}).Connect(ctx, Endpoint{Address: "relay.test:443", ServerName: "relay.test"})
	if err != nil {
		t.Fatal(err)
	}
	if host := <-connect; host != "relay.test:443" {
		t.Fatal(host)
	}
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	workers.Wait()
	if err := <-accepted; err != nil {
		t.Fatal(err)
	}
}

func TestWebSocketRejectsInvalidUpgradeAndBoundsHTTPSetup(t *testing.T) {
	for _, kind := range []string{"wrong_path", "missing_subprotocol", "wrong_host", "headers_only", "malformed"} {
		t.Run(kind, func(t *testing.T) {
			listener, serverTLS, roots := webSocketTestListener(t)
			setup, cancel := context.WithTimeout(t.Context(), time.Second)
			defer cancel()
			result := make(chan error, 1)
			go func() {
				connection, err := listener.Accept()
				if err != nil {
					result <- err
					return
				}
				session, err := AcceptWebSocket(setup, connection, serverTLS, WebSocketConfig{})
				if session != nil {
					_ = session.Close()
				}
				result <- err
			}()
			trust, err := transportTLSConfigForALPN(roots, "relay.test", false, "http/1.1")
			if err != nil {
				t.Fatal(err)
			}
			connection, err := (&tls.Dialer{Config: trust}).DialContext(setup, "tcp", listener.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer connection.Close()
			if kind == "headers_only" {
				cancel()
			} else if kind == "malformed" {
				_, _ = io.WriteString(connection, "not-http\r\n\r\n")
			} else {
				path, host, subprotocol := WebSocketPath, "relay.test", WebSocketProtocol
				switch kind {
				case "wrong_path":
					path = "/"
				case "wrong_host":
					host = "other.test"
				case "missing_subprotocol":
					subprotocol = ""
				}
				request, _ := http.NewRequest(http.MethodGet, "https://"+host+path, nil)
				request.Header.Set("Connection", "Upgrade")
				request.Header.Set("Upgrade", "websocket")
				request.Header.Set("Sec-WebSocket-Version", "13")
				request.Header.Set("Sec-WebSocket-Key", "MDEyMzQ1Njc4OWFiY2RlZg==")
				request.Header.Set("Sec-WebSocket-Protocol", subprotocol)
				if err := request.Write(connection); err != nil {
					t.Fatal(err)
				}
				response, err := http.ReadResponse(bufio.NewReader(connection), request)
				if err != nil {
					t.Fatal(err)
				}
				_ = response.Body.Close()
				if response.StatusCode != http.StatusBadRequest {
					t.Fatal(response.StatusCode)
				}
			}
			if err := <-result; err == nil {
				t.Fatal("invalid setup accepted")
			}
		})
	}
}

func TestWebSocketBinaryChunksAndReadLimit(t *testing.T) {
	for _, kind := range []string{"chunks", "text", "oversized"} {
		t.Run(kind, func(t *testing.T) {
			accepted := make(chan *websocket.Conn, 1)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				connection, err := websocket.Accept(w, r, nil)
				if err != nil {
					t.Error(err)
					return
				}
				accepted <- connection
			}))
			defer server.Close()
			client, _, err := websocket.Dial(t.Context(), server.URL, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer client.CloseNow()
			client.CloseRead(t.Context())
			connection := <-accepted
			defer connection.CloseNow()
			network := websocket.NetConn(t.Context(), connection, websocket.MessageBinary)
			connection.SetReadLimit(WebSocketMaxBytes)
			payload := bytes.Repeat([]byte("x"), WebSocketMaxBytes+1)
			written := make(chan error, 1)
			go func() {
				if kind == "chunks" {
					for _, chunk := range [][]byte{payload[:1], payload[1:WebSocketMaxBytes], payload[WebSocketMaxBytes:]} {
						if err := client.Write(t.Context(), websocket.MessageBinary, chunk); err != nil {
							written <- err
							return
						}
					}
					written <- nil
				} else {
					message := websocket.MessageBinary
					if kind == "text" {
						message = websocket.MessageText
					}
					written <- client.Write(t.Context(), message, payload)
				}
			}()
			got := make([]byte, len(payload))
			_, err = io.ReadFull(network, got)
			if kind == "chunks" {
				if err != nil || !bytes.Equal(got, payload) {
					t.Fatal("message boundaries changed byte stream", err)
				}
			} else if err == nil {
				// streaming readers detect an oversized message when the next read
				// crosses its limit, including the one-byte lookahead.
				_, err = network.Read(make([]byte, 1))
				if err == nil {
					t.Fatal("invalid binary transport accepted")
				}
			}
			<-written
		})
	}
}

func TestWebSocketFailureClassificationPreservesCauseAndSafeOutput(t *testing.T) {
	cause := errors.New("secret proxy response body")
	for _, test := range []struct {
		code   string
		status int
		cause  error
		retry  bool
	}{
		{"upgrade_failed", 503, cause, true},
		{"upgrade_failed", 429, cause, true},
		{"upgrade_failed", 401, cause, false},
		{"upgrade_failed", 307, cause, false},
		{"upgrade_failed", 0, io.EOF, true},
		{"upgrade_failed", 0, context.Canceled, false},
		{"subprotocol_invalid", 101, cause, false},
	} {
		problem := &WebSocketError{Code: test.code, Status: test.status, Err: test.cause}
		if problem.Retryable() != test.retry || !errors.Is(problem, test.cause) ||
			problem.Error() != "relay websocket "+test.code {
			t.Fatal("lost classification, cause, or safe output", problem)
		}
	}
}

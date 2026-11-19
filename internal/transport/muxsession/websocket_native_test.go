//go:build !js

package muxsession

import (
	"context"
	"crypto/tls"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"
	"time"

	"github.com/coder/websocket"
)

func TestWebSocketNativeTrustIsRequired(t *testing.T) {
	for _, trust := range []*tls.Config{nil, {InsecureSkipVerify: true}} {
		session, err := (WebSocketConnector{TLSConfig: trust}).Connect(t.Context(), Endpoint{
			Address: "relay.test:443", ServerName: "relay.test",
		})
		var problem *WebSocketError
		if session != nil || !errors.As(err, &problem) || problem.Code != "trust_required" {
			t.Fatal("native connector bypassed transport trust", session, err)
		}
	}
}

func TestWebSocketServerTLSFallbackIsLocalAndClonesDynamicConfig(t *testing.T) {
	base := &tls.Config{MinVersion: tls.VersionTLS12, CurvePreferences: []tls.CurveID{tls.CurveP256}}
	selected := base.Clone()
	base.GetConfigForClient = func(*tls.ClientHelloInfo) (*tls.Config, error) { return selected, nil }
	wss, err := webSocketServerTLSConfig(base)
	if err != nil {
		t.Fatal(err)
	}
	dynamic, err := wss.GetConfigForClient(&tls.ClientHelloInfo{})
	if err != nil {
		t.Fatal(err)
	}
	for _, config := range []*tls.Config{wss, dynamic} {
		if config.MinVersion != tls.VersionTLS13 ||
			!slices.Equal(config.CurvePreferences, []tls.CurveID{tls.X25519MLKEM768, tls.X25519, tls.CurveP256, tls.CurveP384}) ||
			!slices.Equal(config.NextProtos, []string{"http/1.1"}) {
			t.Fatal("WSS fallback policy lost TLS version, hybrid preference or ALPN", config)
		}
	}
	for _, config := range []*tls.Config{base, selected} {
		if config.MinVersion != tls.VersionTLS12 || !slices.Equal(config.CurvePreferences, []tls.CurveID{tls.CurveP256}) {
			t.Fatal("WSS fallback mutated caller trust")
		}
	}
	for _, server := range []bool{false, true} {
		strict, err := transportTLSConfigForALPN(base, "relay.test", server, ALPN)
		if err != nil {
			t.Fatal(err)
		}
		dynamic, err := strict.GetConfigForClient(&tls.ClientHelloInfo{})
		if err != nil {
			t.Fatal(err)
		}
		for _, config := range []*tls.Config{strict, dynamic} {
			if config.MinVersion != tls.VersionTLS13 || !slices.Equal(config.CurvePreferences, []tls.CurveID{tls.X25519MLKEM768}) {
				t.Fatal("WSS fallback escaped into native transport TLS", config)
			}
		}
	}
}

func TestWebSocketNativeClientStillRequiresHybridTLS(t *testing.T) {
	serverTLS, roots := testTLSConfigs(t)
	serverTLS.MinVersion = tls.VersionTLS13
	serverTLS.CurvePreferences = []tls.CurveID{tls.X25519}
	listener, err := tls.Listen("tcp", "127.0.0.1:0", serverTLS)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		connection, err := listener.Accept()
		if err != nil {
			done <- err
			return
		}
		defer connection.Close()
		done <- connection.(*tls.Conn).HandshakeContext(ctx)
	}()
	session, err := (WebSocketConnector{TLSConfig: roots, Config: WebSocketConfig{DisableProxy: true}}).Connect(ctx, Endpoint{
		Address: listener.Addr().String(), ServerName: "relay.test",
	})
	if session != nil {
		_ = session.Close()
	}
	serverErr := <-done
	if err == nil || serverErr == nil {
		t.Fatal("native WSS client downgraded to classical key agreement", err)
	}
}

func TestWebSocketNativePeerMetadataIsRequired(t *testing.T) {
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
	connection := <-accepted
	session, err := newWebSocketSession(t.Context(), connection, nil, false, 0)
	var problem *WebSocketError
	if session != nil || !errors.As(err, &problem) || problem.Code != "peer_required" {
		t.Fatal("native session invented socket metadata", session, err)
	}
}

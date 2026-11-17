package muxsession

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
)

// WebSocketPath and WebSocketProtocol define the portable relay byte transport.
// binary messages are arbitrary chunks of yamux, never application boundaries.
const (
	WebSocketPath     = "/tnl/v1/connect"
	WebSocketProtocol = "tnl-yamux-v1"
	WebSocketMaxBytes = 64 << 10
)

// WebSocketConfig bounds a yamux session over an RFC 6455 binary connection.
// private forwarding explicitly disables environment proxies on native platforms.
// js/wasm rejects Dialer and DisableProxy: the host owns dialing and proxies.
type WebSocketConfig struct {
	MaxIncomingStreams int
	Dialer             *net.Dialer
	DisableProxy       bool
}

// WebSocketConnector uses native TLS policy or, on js/wasm, host-managed WSS.
// js/wasm requires a nil TLSConfig; custom roots, TLS hooks and key agreement
// cannot be configured or attested through the host WebSocket API.
type WebSocketConnector struct {
	TLSConfig *tls.Config
	Config    WebSocketConfig
}

// WebSocketError classifies setup failures without exposing response bodies.
type WebSocketError struct {
	Code   string
	Status int
	Err    error
}

func (e *WebSocketError) Error() string { return "relay websocket " + e.Code }
func (e *WebSocketError) Unwrap() error { return e.Err }

// Retryable distinguishes proxy/server outages from certificate and protocol
// rejection. an HTTP upgrade never conveys a tnl authorization decision.
func (e *WebSocketError) Retryable() bool {
	if e.Code != "upgrade_failed" {
		return false
	}
	if e.Status != 0 {
		return e.Status == http.StatusTooManyRequests || e.Status >= 500 && e.Status <= 599
	}
	var certificate *tls.CertificateVerificationError
	if errors.As(e.Err, &certificate) {
		return false
	}
	var operation *net.OpError
	var dns *net.DNSError
	return errors.As(e.Err, &operation) || errors.As(e.Err, &dns) ||
		errors.Is(e.Err, context.DeadlineExceeded) || errors.Is(e.Err, io.EOF) || errors.Is(e.Err, io.ErrUnexpectedEOF)
}

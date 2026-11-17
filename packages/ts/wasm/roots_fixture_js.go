//go:build js && wasm && tnlwasmtest

package main

import (
	"context"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"reflect"
	"syscall/js"

	quic "github.com/quic-go/quic-go"
	connectorstream "github.com/tnldotdev/tnl/internal/connector/stream"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/transport/tunnel"
)

// fixture diagnostics contain only Go type names and fixed failure markers,
// never error text, wire bodies, addresses, tokens, keys, or credentials.
func reportFixtureFailure(err error) {
	global := js.Global()
	events := global.Get("__tnlWasmFixtureDiagnostics")
	if events.IsUndefined() {
		events = global.Get("Array").New()
		global.Set("__tnlWasmFixtureDiagnostics", events)
	}
	if events.Length() >= 16 {
		return
	}
	types := []any{}
	resets := []any{}
	var visit func(error)
	visit = func(err error) {
		if err == nil || len(types) >= 64 {
			return
		}
		types = append(types, reflect.TypeOf(err).String())
		if reset, ok := err.(*quic.StreamError); ok && reset != nil {
			resets = append(resets, map[string]any{"remote": reset.Remote, "code": uint64(reset.ErrorCode)})
		}
		switch e := err.(type) {
		case interface{ Unwrap() []error }:
			for _, child := range e.Unwrap() {
				visit(child)
			}
		case interface{ Unwrap() error }:
			visit(e.Unwrap())
		}
	}
	visit(err)
	diagnostic := map[string]any{"types": types, "resets": resets, "canceled": errors.Is(err, context.Canceled), "deadline": errors.Is(err, context.DeadlineExceeded), "closed": errors.Is(err, net.ErrClosed), "pipe_closed": errors.Is(err, io.ErrClosedPipe), "eof": errors.Is(err, io.EOF), "terminal_failed": errors.Is(err, tunnel.ErrConnectorTerminalFailed), "service_unavailable": errors.Is(err, connectorstream.ErrServiceConnection)}
	if reason, _, ok := failure.Describe(err); ok {
		diagnostic["reason"] = string(reason)
	}
	events.Call("push", diagnostic)
}

// only the controlled fixture artifact accepts a host-supplied test issuer.
// production artifacts have no API for replacing the bundled WebPKI roots.
func fixtureServiceRoots(host js.Value) (*x509.CertPool, error) {
	value := bridgeGet(host, "__tnlTestServiceRootPEM")
	if value.IsUndefined() || value.IsNull() {
		return nil, nil
	}
	if value.Type() != js.TypeString || len(value.String()) > 64<<10 {
		return nil, errArguments
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM([]byte(value.String())) {
		return nil, errArguments
	}
	return pool, nil
}

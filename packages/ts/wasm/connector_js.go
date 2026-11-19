//go:build js && wasm

package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"sync"
	"syscall/js"

	connectorsession "github.com/tnldotdev/tnl/internal/connector/session"
	connectorstream "github.com/tnldotdev/tnl/internal/connector/stream"
	"github.com/tnldotdev/tnl/internal/transport/muxsession"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type deploymentOptions struct {
	connectorsession.DeploymentOptions
}

type deploymentHandle struct {
	deployment  *connectorsession.Deployment
	ctx         context.Context
	stop        func()
	trust       *tls.Config
	mu          sync.Mutex
	closed      bool
	pending     sync.WaitGroup
	connections map[*connectionHandle]struct{}
	bindings    map[string]*connectionHandle
	gates       map[string]chan struct{}
	methods     methodSet
	once        sync.Once
	err         error
}

func registerConnector(api js.Value) {
	var functions methodSet
	bind(api, "createDeployment", &functions, func(args []js.Value) (any, error) {
		if len(args) < 2 || len(args) > 3 || args[0].Type() != js.TypeObject || args[1].Type() != js.TypeObject {
			return nil, errArguments
		}
		encoded := js.Global().Get("JSON").Call("stringify", args[0])
		if encoded.Type() != js.TypeString || len(encoded.String()) > 64<<10 {
			return nil, errArguments
		}
		var options deploymentOptions
		decoder := json.NewDecoder(bytes.NewBufferString(encoded.String()))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&options); err != nil {
			return nil, errArguments
		}
		host := args[1]
		if bridgeGet(host, "fetch").Type() != js.TypeFunction || !bridgeGet(host, "WebSocket").Equal(js.Global().Get("WebSocket")) {
			return nil, errArguments
		}
		ctx, stop, err := signalContext(runtimeContext, argumentSignal(args, 2))
		if err != nil {
			return nil, err
		}
		httpClient := &http.Client{Transport: &fetchTransport{fetch: bridgeGet(host, "fetch")}}
		deployment, err := connectorsession.NewDeployment(options.DeploymentOptions, httpClient)
		if err != nil {
			stop()
			return nil, err
		}
		trust, err := serviceTrust(host)
		if err != nil {
			stop()
			return nil, err
		}
		h := &deploymentHandle{deployment: deployment, ctx: ctx, stop: stop, trust: trust, connections: map[*connectionHandle]struct{}{}, bindings: map[string]*connectionHandle{}, gates: map[string]chan struct{}{}}
		runtimeMu.Lock()
		if runtimeClosed || len(runtimeResources) >= 32 {
			runtimeMu.Unlock()
			stop()
			return nil, errCapacity
		}
		runtimeResources[h] = struct{}{}
		runtimeMu.Unlock()
		return h.export(), nil
	})
}

func (h *deploymentHandle) enter() error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed || h.ctx.Err() != nil {
		return context.Canceled
	}
	h.pending.Add(1)
	return nil
}
func metadata(connection connectorSession) map[string]any {
	service := connection.Metadata()
	return map[string]any{"key": service.Id, "protocol": string(service.Protocol), "hostname": service.Endpoint.Hostname}
}
func (h *deploymentHandle) export() js.Value {
	object := js.Global().Get("Object").New()
	bind(object, "resolve", &h.methods, func(args []js.Value) (any, error) {
		if len(args) < 1 || args[0].Type() != js.TypeString {
			return nil, errArguments
		}
		if err := h.enter(); err != nil {
			return nil, err
		}
		defer h.pending.Done()
		ctx, stop, err := signalContext(h.ctx, argumentSignal(args, 1))
		if err != nil {
			return nil, err
		}
		defer stop()
		service, err := h.deployment.SelectService(ctx, args[0].String())
		if err != nil {
			return nil, operationError(ctx, err)
		}
		return map[string]any{"key": service.Id, "protocol": string(service.Protocol), "hostname": service.Endpoint.Hostname}, nil
	})
	bind(object, "connect", &h.methods, func(args []js.Value) (any, error) {
		if len(args) < 1 || len(args) > 2 || args[0].Type() != js.TypeString {
			return nil, errArguments
		}
		if err := h.enter(); err != nil {
			return nil, err
		}
		defer h.pending.Done()
		ctx, stop, err := signalContext(h.ctx, argumentSignal(args, 1))
		if err != nil {
			return nil, err
		}
		defer stop()
		name := args[0].String()
		if _, err := h.deployment.ServiceProtocol(name); err != nil {
			return nil, err
		}
		h.mu.Lock()
		gate := h.gates[name]
		if gate == nil && len(h.gates) < 32 {
			gate = make(chan struct{}, 1)
			h.gates[name] = gate
		}
		h.mu.Unlock()
		if gate == nil {
			return nil, errCapacity
		}
		select {
		case gate <- struct{}{}:
		case <-ctx.Done():
			return nil, operationError(ctx, context.Cause(ctx))
		}
		defer func() { <-gate }()
		selected, err := h.deployment.SelectService(ctx, name)
		if err != nil {
			return nil, operationError(ctx, err)
		}
		if ctx.Err() != nil {
			return nil, operationError(ctx, context.Cause(ctx))
		}
		h.mu.Lock()
		current := h.bindings[name]
		h.mu.Unlock()
		if current != nil {
			current.mu.Lock()
			usable := !current.closed && current.connection.Context().Err() == nil
			current.mu.Unlock()
			old := current.connection.Metadata()
			if usable && sameBinding(old, selected) {
				return current.object, nil
			}
			if err := current.close(); err != nil {
				return nil, &connectorstream.CleanupError{Err: err}
			}
		}
		lifetime, cancel := context.WithCancel(h.ctx)
		connection, err := h.deployment.Connect(lifetime, ctx, name, connectorstream.Config{
			ServiceTLS: h.trust, WebSocketOnly: true, RelayWebSocket: muxsession.WebSocketConnector{},
		})
		if err != nil {
			cancel()
			return nil, operationError(ctx, err)
		}
		child := &connectionHandle{owner: h, connection: connection, name: name, stop: cancel, streams: map[*streamHandle]struct{}{}, bodies: map[*responseBody]struct{}{}}
		child.object = child.export()
		h.mu.Lock()
		closed := h.closed || h.ctx.Err() != nil
		if !closed {
			h.connections[child] = struct{}{}
			h.bindings[name] = child
		}
		h.mu.Unlock()
		if closed {
			return nil, errors.Join(context.Canceled, child.close())
		}
		return child.object, nil
	})
	bind(object, "close", &h.methods, func([]js.Value) (any, error) { return nil, h.close() })
	return object
}

func sameBinding(old, next controlv1.ServiceSummary) bool {
	return old.Id == next.Id && old.Protocol == next.Protocol && old.TrustRevision == next.TrustRevision &&
		old.Endpoint != nil && next.Endpoint != nil && old.Endpoint.Hostname == next.Endpoint.Hostname
}
func (h *deploymentHandle) close() error {
	h.once.Do(func() {
		h.mu.Lock()
		h.closed = true
		h.mu.Unlock()
		h.stop()
		h.pending.Wait()
		h.mu.Lock()
		children := make([]*connectionHandle, 0, len(h.connections))
		for child := range h.connections {
			children = append(children, child)
		}
		h.mu.Unlock()
		for _, child := range children {
			h.err = errors.Join(h.err, child.close())
		}
		h.methods.retire()
		runtimeMu.Lock()
		delete(runtimeResources, h)
		runtimeMu.Unlock()
	})
	return h.err
}

type connectionHandle struct {
	owner      *deploymentHandle
	connection connectorSession
	stop       func()
	name       string
	object     js.Value
	mu         sync.Mutex
	closed     bool
	pending    sync.WaitGroup
	streams    map[*streamHandle]struct{}
	bodies     map[*responseBody]struct{}
	methods    methodSet
	once       sync.Once
	err        error
}

type connectorSession interface {
	Context() context.Context
	Metadata() controlv1.ServiceSummary
	Open(context.Context) (*connectorsession.Conn, error)
	Fetch(*http.Request) (*http.Response, error)
	Close() error
}

func (h *connectionHandle) enter() error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed {
		return context.Canceled
	}
	if len(h.streams)+len(h.bodies) >= 64 {
		return errCapacity
	}
	h.pending.Add(1)
	return nil
}
func (h *connectionHandle) export() js.Value {
	object := js.Global().Get("Object").New()
	object.Set("metadata", metadata(h.connection))
	bind(object, "open", &h.methods, func(args []js.Value) (any, error) {
		if len(args) > 1 {
			return nil, errArguments
		}
		if err := h.enter(); err != nil {
			return nil, err
		}
		defer h.pending.Done()
		ctx, stop, err := signalContext(h.connection.Context(), argumentSignal(args, 0))
		if err != nil {
			return nil, err
		}
		stream, err := h.connection.Open(ctx)
		if err != nil {
			err = operationError(ctx, err)
			stop()
			return nil, err
		}
		child := &streamHandle{owner: h, stream: stream, ctx: ctx, stop: stop}
		h.mu.Lock()
		closed := h.closed
		if !closed {
			h.streams[child] = struct{}{}
		}
		h.mu.Unlock()
		if closed {
			return nil, errors.Join(context.Canceled, child.close())
		}
		return child.export(), nil
	})
	bind(object, "fetch", &h.methods, h.fetch)
	bind(object, "close", &h.methods, func([]js.Value) (any, error) { return nil, h.close() })
	return object
}
func (h *connectionHandle) close() error {
	h.once.Do(func() {
		h.mu.Lock()
		h.closed = true
		streams := make([]*streamHandle, 0, len(h.streams))
		for stream := range h.streams {
			streams = append(streams, stream)
		}
		bodies := make([]*responseBody, 0, len(h.bodies))
		for body := range h.bodies {
			bodies = append(bodies, body)
		}
		h.mu.Unlock()
		h.stop()
		h.err = h.connection.Close()
		for _, stream := range streams {
			h.err = errors.Join(h.err, stream.close())
		}
		for _, body := range bodies {
			h.err = errors.Join(h.err, body.close())
		}
		h.pending.Wait()
		h.methods.retire()
		h.owner.mu.Lock()
		delete(h.owner.connections, h)
		if h.owner.bindings[h.name] == h {
			delete(h.owner.bindings, h.name)
		}
		h.owner.mu.Unlock()
	})
	return h.err
}

type streamHandle struct {
	owner           *connectionHandle
	stream          *connectorsession.Conn
	ctx             context.Context
	stop            func()
	readMu, writeMu sync.Mutex
	methods         methodSet
	once            sync.Once
	err             error
}

func (h *streamHandle) export() js.Value {
	object := js.Global().Get("Object").New()
	bind(object, "read", &h.methods, func(args []js.Value) (any, error) {
		if len(args) != 1 || args[0].Type() != js.TypeNumber || args[0].Float() != float64(args[0].Int()) || args[0].Int() < 1 || args[0].Int() > chunkBytes {
			return nil, errArguments
		}
		if !h.readMu.TryLock() {
			return nil, errCapacity
		}
		defer h.readMu.Unlock()
		data := make([]byte, args[0].Int())
		n, err := h.stream.Read(data)
		if n > 0 {
			return jsBytes(data[:n]), nil
		}
		if err == io.EOF {
			return nil, nil
		}
		return nil, operationError(h.ctx, err)
	})
	bind(object, "write", &h.methods, func(args []js.Value) (any, error) {
		if len(args) != 1 || !isBytes(args[0]) || bridgeByteLength(args[0]) > chunkBytes {
			return nil, errArguments
		}
		if !h.writeMu.TryLock() {
			return nil, errCapacity
		}
		defer h.writeMu.Unlock()
		data := make([]byte, bridgeByteLength(args[0]))
		js.CopyBytesToGo(data, args[0])
		for len(data) > 0 {
			n, err := h.stream.Write(data)
			if err != nil {
				return nil, operationError(h.ctx, err)
			}
			if n == 0 {
				return nil, io.ErrNoProgress
			}
			data = data[n:]
		}
		return nil, nil
	})
	bind(object, "startTls", &h.methods, func(args []js.Value) (any, error) {
		if len(args) != 0 {
			return nil, errArguments
		}
		if !h.readMu.TryLock() {
			return nil, errCapacity
		}
		defer h.readMu.Unlock()
		if !h.writeMu.TryLock() {
			return nil, errCapacity
		}
		defer h.writeMu.Unlock()
		return nil, operationError(h.ctx, h.stream.StartTLS(h.ctx, nil))
	})
	bind(object, "closeWrite", &h.methods, func([]js.Value) (any, error) { return nil, h.stream.CloseWrite() })
	bind(object, "close", &h.methods, func([]js.Value) (any, error) { return nil, h.close() })
	return object
}
func (h *streamHandle) close() error {
	h.once.Do(func() {
		h.err = h.stream.Close()
		h.stop()
		h.methods.retire()
		h.owner.mu.Lock()
		delete(h.owner.streams, h)
		h.owner.mu.Unlock()
	})
	return h.err
}
func jsBytes(data []byte) js.Value {
	bytes := js.Global().Get("Uint8Array").New(len(data))
	js.CopyBytesToJS(bytes, data)
	return bytes
}

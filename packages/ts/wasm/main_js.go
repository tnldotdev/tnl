//go:build js && wasm

package main

import (
	"context"
	"errors"
	"net"
	"strconv"
	"sync"
	"syscall/js"

	"github.com/tnldotdev/tnl/internal/client/auth"
	connectorstream "github.com/tnldotdev/tnl/internal/connector/stream"
	"github.com/tnldotdev/tnl/internal/failure"
)

const chunkBytes = 64 << 10

var errArguments = errors.New("invalid WASM arguments")
var errCapacity = errors.New("WASM resource capacity reached")
var runtimeContext, runtimeCancel = context.WithCancel(context.Background())
var runtimeMu sync.Mutex
var runtimeClosed bool

type runtimeResource interface{ close() error }

var runtimeResources = map[runtimeResource]struct{}{}
var runtimeWork sync.WaitGroup
var operationSlots = make(chan struct{}, 128)
var cleanupSlots = make(chan struct{}, 128)
var dispatcher js.Func
var dispatcherOnce sync.Once
var methodMu sync.Mutex
var nextMethod uint64
var methods = map[string]map[string]func([]js.Value) (any, error){}

type methodSet struct{ id string }

// bound methods retain an id, not a separate Go callback per resource. retiring
// an id releases resource closures while saved close methods remain idempotent.
func bind(object js.Value, name string, set *methodSet, work func([]js.Value) (any, error)) {
	initializeDispatcher()
	methodMu.Lock()
	if set.id == "" {
		nextMethod++
		set.id = strconv.FormatUint(nextMethod, 10)
		methods[set.id] = map[string]func([]js.Value) (any, error){}
	}
	methods[set.id][name] = work
	methodMu.Unlock()
	object.Set(name, dispatcher.Value.Call("bind", js.Null(), set.id, name))
}
func (s methodSet) retire() {
	methodMu.Lock()
	delete(methods, s.id)
	methodMu.Unlock()
}
func initializeDispatcher() {
	dispatcherOnce.Do(func() {
		dispatcher = js.FuncOf(func(_ js.Value, args []js.Value) any {
			if len(args) < 2 {
				return promise(func() (any, error) { return nil, errArguments })
			}
			name := args[1].String()
			methodMu.Lock()
			work := methods[args[0].String()][name]
			methodMu.Unlock()
			if work == nil {
				return promise(func() (any, error) {
					if name == "close" {
						return nil, nil
					}
					return nil, net.ErrClosed
				})
			}
			runtimeMu.Lock()
			if runtimeClosed {
				runtimeMu.Unlock()
				return promise(func() (any, error) { return nil, net.ErrClosed })
			}
			slots := operationSlots
			if name == "close" || name == "cancel" {
				slots = cleanupSlots
			}
			select {
			case slots <- struct{}{}:
			default:
				runtimeMu.Unlock()
				return promise(func() (any, error) { return nil, errCapacity })
			}
			runtimeWork.Add(1)
			runtimeMu.Unlock()
			// writes own their bytes before yielding to user JavaScript.
			values, captureErr := captureArguments(name, args[2:])
			return promiseFinally(func() (any, error) {
				if captureErr != nil {
					return nil, captureErr
				}
				value, err := work(values)
				if (name == "close" || name == "cancel") && err != nil {
					err = &connectorstream.CleanupError{Err: err}
				}
				return value, err
			}, func() { <-slots; runtimeWork.Done() })
		})
	})
}

func safeError(err error) js.Value {
	reportFixtureFailure(err)
	code := "sdk.connection_unavailable"
	var cleanup *connectorstream.CleanupError
	switch {
	case errors.As(err, &cleanup):
		code = "sdk.cleanup_failed"
	case errors.Is(err, errArguments):
		code = "sdk.configuration_invalid"
	case errors.Is(err, errCapacity):
		code = "sdk.client_capacity"
	case errors.Is(err, auth.ErrDeploymentCredential):
		code = "sdk.authentication_required"
	default:
		if reason, _, ok := failure.Describe(err); ok && reason == failure.Authentication {
			code = "sdk.authentication_required"
		}
	}
	value := js.Global().Get("Error").New(code)
	value.Set("code", code)
	if onlyOwnedCancellation(err) {
		value.Set("name", "AbortError")
	}
	return value
}

type ownedCancellation struct{ cause error }

func (e *ownedCancellation) Error() string { return "WASM operation canceled" }
func (e *ownedCancellation) Unwrap() error { return e.cause }
func operationError(ctx context.Context, err error) error {
	if ctx.Err() != nil && onlyCancellation(err) {
		return &ownedCancellation{cause: err}
	}
	return err
}
func onlyCancellation(err error) bool {
	if err == context.Canceled {
		return true
	}
	if err == nil {
		return false
	}
	switch e := err.(type) {
	case *connectorstream.CleanupError:
		return false
	case interface{ Unwrap() []error }:
		children := e.Unwrap()
		if len(children) == 0 {
			return false
		}
		for _, child := range children {
			if !onlyCancellation(child) {
				return false
			}
		}
		return true
	case interface{ Unwrap() error }:
		return onlyCancellation(e.Unwrap())
	}
	return false
}
func onlyOwnedCancellation(err error) bool {
	switch e := err.(type) {
	case *ownedCancellation:
		return onlyCancellation(e.cause)
	case *connectorstream.CleanupError:
		return false
	case interface{ Unwrap() []error }:
		children := e.Unwrap()
		if len(children) == 0 {
			return false
		}
		for _, child := range children {
			if !onlyOwnedCancellation(child) {
				return false
			}
		}
		return true
	case interface{ Unwrap() error }:
		return onlyOwnedCancellation(e.Unwrap())
	}
	return false
}

func promise(work func() (any, error)) js.Value { return promiseFinally(work, nil) }
func promiseFinally(work func() (any, error), after func()) js.Value {
	executor := js.FuncOf(func(_ js.Value, args []js.Value) any {
		resolve, reject := args[0], args[1]
		go func() {
			defer func() {
				if recovered := recover(); recovered != nil {
					reject.Invoke(safeError(errArguments))
				}
				if after != nil {
					after()
				}
			}()
			value, err := work()
			if err != nil {
				reject.Invoke(safeError(err))
			} else {
				resolve.Invoke(value)
			}
		}()
		return nil
	})
	value := js.Global().Get("Promise").New(executor)
	executor.Release()
	return value
}

func main() {
	initializeDispatcher()
	api := js.Global().Get("Object").New()
	registerConnector(api)
	// publisher composition registers alongside connector composition here.
	done := make(chan struct{})
	var once sync.Once
	finishRuntime := js.FuncOf(func(js.Value, []js.Value) any {
		once.Do(func() { close(done) })
		return nil
	})
	closing := js.Undefined()
	closeRuntime := js.FuncOf(func(js.Value, []js.Value) any {
		if !closing.IsUndefined() {
			return closing
		}
		closing = promiseFinally(func() (any, error) {
			if err := shutdown(); err != nil {
				return nil, &connectorstream.CleanupError{Err: err}
			}
			return nil, nil
		}, func() {
			// exit only after the originating JS callback and Promise constructor
			// return. wasm_exec clears its instance immediately when main exits.
			js.Global().Call("queueMicrotask", finishRuntime)
		})
		return closing
	})
	api.Set("close", closeRuntime)
	api.Set("shutdown", closeRuntime)
	js.Global().Set("tnlWasm", api)
	<-done
	methodMu.Lock()
	clear(methods)
	methodMu.Unlock()
	closeRuntime.Release()
	finishRuntime.Release()
	dispatcher.Release()
}

var shutdownOnce sync.Once
var shutdownErr error

func shutdown() error {
	shutdownOnce.Do(func() {
		runtimeMu.Lock()
		runtimeClosed = true
		resources := make([]runtimeResource, 0, len(runtimeResources))
		for resource := range runtimeResources {
			resources = append(resources, resource)
		}
		runtimeMu.Unlock()
		runtimeCancel()
		for _, resource := range resources {
			shutdownErr = errors.Join(shutdownErr, resource.close())
		}
		runtimeWork.Wait()
	})
	return shutdownErr
}

func isBytes(value js.Value) bool {
	return value.Type() == js.TypeObject && !value.IsNull() &&
		js.Global().Get("ArrayBuffer").Call("isView", value).Bool() &&
		js.Global().Get("Uint8Array").Get("prototype").Call("isPrototypeOf", value).Bool()
}

// Value.Get executes a JS accessor outside wasm_exec's exception boundary.
// Reflect.get through Call converts the exception to a catchable Go panic;
// never read or format that exception, which may contain host credentials.
func bridgeGet(value js.Value, key string) (result js.Value) {
	defer func() {
		if recover() != nil {
			panic(errArguments)
		}
	}()
	return js.Global().Get("Reflect").Call("get", value, key)
}
func bridgeByteLength(value js.Value) int {
	length := bridgeGet(value, "byteLength")
	if length.Type() != js.TypeNumber || length.Float() != float64(length.Int()) || length.Int() < 0 {
		panic(errArguments)
	}
	return length.Int()
}
func bridgeSubarray(value js.Value, start, end int) js.Value {
	return js.Global().Get("Uint8Array").Get("prototype").Get("subarray").Call("call", value, start, end)
}
func captureArguments(name string, args []js.Value) (values []js.Value, err error) {
	defer func() {
		if recover() != nil {
			err = errArguments
		}
	}()
	values = append([]js.Value(nil), args...)
	if name == "write" && len(values) == 1 && isBytes(values[0]) && bridgeByteLength(values[0]) <= chunkBytes {
		values[0] = js.Global().Get("Uint8Array").Get("prototype").Get("slice").Call("call", values[0])
	}
	return values, nil
}

// an AbortSignal remains attached until its Go resource or operation joins.
func signalContext(parent context.Context, signal js.Value) (ctx context.Context, stop func(), result error) {
	ctx, cancel := context.WithCancel(parent)
	var onAbort js.Func
	attached := false
	defer func() {
		if recover() != nil {
			cancel()
			if attached {
				onAbort.Release()
			}
			ctx, stop, result = nil, nil, errArguments
		}
	}()
	if signal.IsUndefined() || signal.IsNull() {
		return ctx, cancel, nil
	}
	if signal.Type() != js.TypeObject || signal.IsNull() {
		cancel()
		return nil, nil, errArguments
	}
	// trusted built-ins validate the native signal brand and cannot be replaced
	// by a supplied object's callback-retaining accessors or cleanup methods.
	prototype := js.Global().Get("AbortSignal").Get("prototype")
	descriptor := js.Global().Get("Object").Call("getOwnPropertyDescriptor", prototype, "aborted")
	aborted := descriptor.Get("get")
	_ = aborted.Call("call", signal).Bool()
	events := js.Global().Get("EventTarget").Get("prototype")
	add, remove := events.Get("addEventListener"), events.Get("removeEventListener")
	onAbort = js.FuncOf(func(js.Value, []js.Value) any { cancel(); return nil })
	attached = true
	add.Call("call", signal, "abort", onAbort)
	if aborted.Call("call", signal).Bool() {
		cancel()
	}
	var once sync.Once
	return ctx, func() {
		once.Do(func() { cancel(); defer onAbort.Release(); remove.Call("call", signal, "abort", onAbort) })
	}, nil
}

func argumentSignal(args []js.Value, index int) js.Value {
	if len(args) <= index {
		return js.Undefined()
	}
	value := args[index]
	if value.Type() == js.TypeObject && !value.IsNull() && bridgeGet(value, "signal").Type() == js.TypeObject {
		return bridgeGet(value, "signal")
	}
	return value
}

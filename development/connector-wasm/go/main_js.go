//go:build js && wasm

package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"strconv"
	"sync"
	"syscall/js"
	"time"
)

var exported []js.Func
var dispatcher js.Func
var dispatcherOnce sync.Once
var methodMu sync.Mutex
var nextMethodID uint64
var methodRegistry = make(map[string]registeredMethods)

type registeredMethods struct {
	compact bool
	work    map[string]func([]js.Value) (any, error)
}

type methodSet struct {
	id      string
	compact bool
}

var compactConstructorsOnce sync.Once
var compactPromiseConstructor, compactBytesConstructor js.Value

func initializeCompactConstructors() {
	compactConstructorsOnce.Do(func() {
		compactPromiseConstructor = js.Global().Get("Promise")
		compactBytesConstructor = js.Global().Get("Uint8Array")
	})
}

func bytesConstructor(compact bool) js.Value {
	if compact {
		initializeCompactConstructors()
		return compactBytesConstructor
	}
	return js.Global().Get("Uint8Array")
}

// bound JS functions retain only an immutable id, never a per-resource Go Func.
// retired ids reject saved read/write refs and make saved close refs idempotent.
// deleting a registry entry releases every resource closure without invalidating
// the JS function that an application may have saved before close.
func initializeDispatcher() {
	dispatcherOnce.Do(func() {
		counters.PersistentCallbacks++
		dispatcher = js.FuncOf(func(_ js.Value, args []js.Value) any {
			id, name := args[0].String(), args[1].String()
			// retain the mode in bound JS arguments too, so saved methods need no
			// registry tombstone after their resource has joined and retired.
			compact := args[2].Bool()
			methodMu.Lock()
			methods, exists := methodRegistry[id]
			work := methods.work[name]
			if exists {
				compact = methods.compact
			}
			methodMu.Unlock()
			if work == nil {
				return promise(func() (any, error) {
					if name == "close" {
						return nil, nil
					}
					return nil, net.ErrClosed
				}, compact)
			}
			return promise(func() (any, error) { return work(args[3:]) }, compact)
		})
	})
}

func (m methodSet) retire() {
	methodMu.Lock()
	delete(methodRegistry, m.id)
	methodMu.Unlock()
}

func promise(work func() (any, error), compact ...bool) js.Value {
	counters.ApplicationPromises++
	if len(compact) == 1 && compact[0] {
		initializeCompactConstructors()
		deferred := compactPromiseConstructor.Call("withResolvers")
		resolve, reject := deferred.Get("resolve"), deferred.Get("reject")
		go settleApplicationPromise(work, resolve, reject)
		return deferred.Get("promise")
	}
	counters.PromiseExecutors++
	counters.CallbackRegistrations++
	executor := js.FuncOf(func(_ js.Value, args []js.Value) any {
		resolve, reject := args[0], args[1]
		go settleApplicationPromise(work, resolve, reject)
		return nil
	})
	p := js.Global().Get("Promise").New(executor)
	executor.Release()
	return p
}

// both modes retain one application goroutine per operation; only callback
// setup changes. completion and backpressure stay owned by the operation.
func settleApplicationPromise(work func() (any, error), resolve, reject js.Value) {
	value, err := work()
	if err != nil {
		reject.Invoke(js.Global().Get("Error").New(err.Error()))
	} else {
		resolve.Invoke(value)
	}
}

func main() {
	initializeDispatcher()
	counters.PersistentCallbacks++
	prepareFunc := js.FuncOf(func(_ js.Value, args []js.Value) any {
		if len(args) < 2 || len(args) > 3 {
			return promise(func() (any, error) { return nil, errors.New("prepare requires options and host") })
		}
		// copy options synchronously; the host remains scoped to this preparation.
		encoded := js.Global().Get("JSON").Call("stringify", args[0]).String()
		host := args[1]
		signal := js.Undefined()
		if len(args) == 3 {
			signal = args[2]
		}
		return promise(func() (any, error) {
			ctx, cancel := context.WithCancelCause(context.Background())
			if !signal.IsUndefined() && !signal.IsNull() {
				counters.CallbackRegistrations++
				onAbort := js.FuncOf(func(js.Value, []js.Value) any { cancel(context.Canceled); return nil })
				signal.Call("addEventListener", "abort", onAbort)
				defer func() { signal.Call("removeEventListener", "abort", onAbort); onAbort.Release() }()
				if signal.Get("aborted").Bool() {
					cancel(context.Canceled)
				}
			}
			var o options
			if err := json.Unmarshal([]byte(encoded), &o); err != nil {
				cancel(err)
				return nil, err
			}
			p, err := prepare(ctx, o, hostDial(host, o.CompactPromises))
			if err != nil {
				cancel(err)
				return nil, err
			}
			h := &handle{prepared: p, cancel: cancel, streams: make(map[*byteStream]struct{})}
			return h.export(), nil
		})
	})
	counters.PersistentCallbacks++
	diagnosticFunc := js.FuncOf(func(js.Value, []js.Value) any { return diagnostics() })
	exported = append(exported, prepareFunc, dispatcher, diagnosticFunc)
	js.Global().Set("tnlConnectorWasm", map[string]any{"prepare": prepareFunc, "diagnostics": diagnosticFunc})
	select {}
}

type handle struct {
	prepared *prepared
	cancel   context.CancelCauseFunc
	mu       sync.Mutex
	closed   bool
	streams  map[*byteStream]struct{}
	work     sync.WaitGroup
	once     sync.Once
	closeErr error
	object   js.Value
	funcs    methodSet
	released sync.Once
}

func bind(object js.Value, name string, methods *methodSet, work func([]js.Value) (any, error)) {
	initializeDispatcher()
	methodMu.Lock()
	if methods.id == "" {
		nextMethodID++
		methods.id = strconv.FormatUint(nextMethodID, 10)
		methodRegistry[methods.id] = registeredMethods{compact: methods.compact, work: make(map[string]func([]js.Value) (any, error))}
	}
	methodRegistry[methods.id].work[name] = work
	methodMu.Unlock()
	object.Set(name, dispatcher.Value.Call("bind", js.Null(), methods.id, name, methods.compact))
}

func (h *handle) export() js.Value {
	h.funcs.compact = h.prepared.compactPromises
	h.object = js.Global().Get("Object").New()
	js.Global().Get("Object").Call("defineProperty", h.object, "selectedRelayAddress", map[string]any{"value": h.prepared.session.SelectedRelayAddress(), "writable": false, "enumerable": true})
	bind(h.object, "open", &h.funcs, func([]js.Value) (any, error) { return h.open() })
	bind(h.object, "close", &h.funcs, func([]js.Value) (any, error) { return nil, h.close() })
	return h.object
}

type arrivalConn struct {
	net.Conn
	ready chan struct{}
	once  sync.Once
	end   func() error
}

func (c *arrivalConn) arrived()                    { c.once.Do(func() { close(c.ready) }) }
func (c *arrivalConn) Read(b []byte) (int, error)  { c.arrived(); return c.Conn.Read(b) }
func (c *arrivalConn) Write(b []byte) (int, error) { c.arrived(); return c.Conn.Write(b) }
func (c *arrivalConn) CloseWrite() error           { return c.end() }

func (h *handle) open() (any, error) {
	h.mu.Lock()
	if h.closed || h.prepared.session.Context().Err() != nil {
		h.mu.Unlock()
		return nil, net.ErrClosed
	}
	app, local := net.Pipe()
	eof := make(chan struct{})
	raw := &applicationConn{Conn: app, eof: eof}
	s := &byteStream{owner: h, ctx: h.prepared.session.Context(), conn: raw, raw: raw, done: make(chan struct{}), eof: eof}
	h.streams[s] = struct{}{}
	h.work.Add(1)
	h.mu.Unlock()
	arrival := &arrivalConn{Conn: local, ready: make(chan struct{}), end: func() error {
		s.eofOnce.Do(func() { close(s.eof); _ = app.SetReadDeadline(time.Now()) })
		return nil
	}}
	go func() {
		defer h.work.Done()
		s.forwardErr = h.prepared.session.Forward(h.prepared.session.Context(), arrival)
		_ = local.Close()
		close(s.done)
	}()
	select {
	case <-arrival.ready:
	case <-s.done:
		_ = s.close()
		return nil, errors.Join(errors.New("connector WASM: stream admission failed"), s.forwardErr)
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed {
		return nil, net.ErrClosed
	}
	return s.export(), nil
}

func (h *handle) close() error {
	h.once.Do(func() {
		h.mu.Lock()
		h.closed = true
		streams := make([]*byteStream, 0, len(h.streams))
		for s := range h.streams {
			streams = append(streams, s)
		}
		h.mu.Unlock()
		if h.cancel != nil {
			h.cancel(context.Canceled)
		}
		h.prepared.backend.cancel(context.Canceled)
		h.closeErr = h.prepared.session.Close()
		for _, s := range streams {
			h.closeErr = errors.Join(h.closeErr, s.close())
		}
		h.work.Wait()
	})
	err := errors.Join(h.closeErr, h.prepared.backend.close())
	if err == nil {
		h.released.Do(func() {
			h.funcs.retire()
		})
	}
	return err
}

type byteStream struct {
	owner                   *handle
	ctx                     context.Context
	conn                    net.Conn
	raw                     net.Conn
	readMu, writeMu         sync.Mutex
	mu                      sync.Mutex
	closed                  bool
	operations              sync.WaitGroup
	phase                   streamPhase
	eof                     chan struct{}
	eofOnce                 sync.Once
	done                    chan struct{}
	forwardErr              error // read only after done closes.
	readBuffer, writeBuffer []byte
	once                    sync.Once
	object                  js.Value
	funcs                   methodSet
}

type streamPhase uint8

const (
	streamPlain streamPhase = iota
	streamUpgrading
	streamSecure
)

// translate only the synthetic half-close deadline below TLS, where the TLS
// record reader can distinguish a boundary EOF from a truncated record.
type applicationConn struct {
	net.Conn
	eof <-chan struct{}
}

func (c *applicationConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	if n == 0 && errors.Is(err, os.ErrDeadlineExceeded) {
		select {
		case <-c.eof:
			return 0, io.EOF
		default:
		}
	}
	return n, err
}

func (s *byteStream) enter() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return net.ErrClosed
	}
	if s.owner.prepared.protocol == "postgres" && s.phase != streamSecure {
		return errors.New("connector WASM: postgres requires completed startTls before application I/O")
	}
	s.operations.Add(1)
	return nil
}

func (s *byteStream) export() js.Value {
	s.funcs.compact = s.owner.prepared.compactPromises
	s.object = js.Global().Get("Object").New()
	bind(s.object, "read", &s.funcs, func(args []js.Value) (any, error) {
		if err := s.enter(); err != nil {
			return nil, err
		}
		defer s.operations.Done()
		if len(args) != 1 || args[0].Type() != js.TypeNumber || args[0].Float() != float64(args[0].Int()) || args[0].Int() < 1 || args[0].Int() > 1<<20 {
			return nil, errors.New("read max must be an integer between 1 and 1048576")
		}
		s.readMu.Lock()
		defer s.readMu.Unlock()
		counters.ApplicationReads++
		max := args[0].Int()
		b := s.readBuffer
		if cap(b) < max {
			b = make([]byte, max)
			counters.ApplicationReadAllocated += uint64(max)
		}
		b = b[:max]
		if s.owner.prepared.reuseBuffers {
			s.readBuffer = b
		}
		n, err := s.conn.Read(b)
		if n > 0 {
			counters.ApplicationReadBytes += uint64(n)
			v := bytesConstructor(s.owner.prepared.compactPromises).New(n)
			js.CopyBytesToJS(v, b[:n])
			return v, nil
		}
		if err == io.EOF {
			return nil, nil
		}
		return nil, s.ioError(err)
	})
	bind(s.object, "write", &s.funcs, func(args []js.Value) (any, error) {
		if err := s.enter(); err != nil {
			return nil, err
		}
		defer s.operations.Done()
		if len(args) != 1 || !args[0].InstanceOf(bytesConstructor(s.owner.prepared.compactPromises)) || args[0].Length() > 1<<20 {
			return nil, errors.New("write requires Uint8Array of at most 1048576 bytes")
		}
		s.writeMu.Lock()
		defer s.writeMu.Unlock()
		counters.ApplicationWrites++
		size := args[0].Length()
		b := s.writeBuffer
		if cap(b) < size {
			b = make([]byte, size)
			counters.ApplicationWriteAllocated += uint64(size)
		}
		b = b[:size]
		if s.owner.prepared.reuseBuffers {
			s.writeBuffer = b
		}
		js.CopyBytesToGo(b, args[0])
		counters.ApplicationWriteBytes += uint64(len(b))
		for len(b) > 0 {
			n, err := s.conn.Write(b)
			if err != nil {
				return nil, s.ioError(err)
			}
			b = b[n:]
		}
		return nil, nil
	})
	bind(s.object, "startTls", &s.funcs, func([]js.Value) (any, error) {
		s.mu.Lock()
		if s.closed || s.phase != streamPlain || s.owner.prepared.protocol != "postgres" {
			s.mu.Unlock()
			return nil, errors.New("startTls requires an unupgraded postgres stream")
		}
		s.phase = streamUpgrading
		s.operations.Add(1)
		s.mu.Unlock()
		defer s.operations.Done()
		trust := s.owner.prepared.trust.Clone()
		trust.ServerName = s.owner.prepared.hostname
		secure, err := postgresTLS(s.ctx, s.conn, trust)
		if err != nil {
			return nil, err
		}
		s.mu.Lock()
		s.conn, s.phase = secure, streamSecure
		s.mu.Unlock()
		return nil, nil
	})
	bind(s.object, "close", &s.funcs, func([]js.Value) (any, error) { return nil, s.close() })
	return s.object
}

func (s *byteStream) ioError(err error) error {
	select {
	case <-s.done:
		return errors.Join(err, s.forwardErr)
	default:
		return err
	}
}

func (s *byteStream) close() error {
	s.once.Do(func() {
		s.mu.Lock()
		s.closed = true
		s.mu.Unlock()
		// close the raw pipe first so TLS close-notify and active operations cannot
		// prevent joined forwarding. closing one child never closes its sibling.
		_ = s.raw.Close()
		<-s.done
		s.operations.Wait()
		s.owner.mu.Lock()
		delete(s.owner.streams, s)
		s.owner.mu.Unlock()
		s.funcs.retire()
	})
	return nil
}

//go:build js && wasm

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"sync"
	"syscall/js"
	"time"
)

type jsResult struct {
	value js.Value
	err   error
}

// these names match host.ts. only explicitly classified transport failures are
// retryable; arbitrary host rejections and coding errors remain terminal.
const hostNetworkErrorName = "TnlHostNetworkError"
const hostCleanupErrorName = "TnlHostCleanupError"

// aborting local byte I/O should settle promptly, not consume a network timeout.
// this five-second grace matches the native connector cleanup ceiling. healthy
// idle operations never start this timer; only abort/deadline/close does.
const hostSettlementTimeout = 5 * time.Second

type hostNetworkError struct{}

func (*hostNetworkError) Error() string   { return "connector WASM: host TCP operation failed" }
func (*hostNetworkError) Timeout() bool   { return false }
func (*hostNetworkError) Temporary() bool { return true }

type hostCleanupError struct{}

func (*hostCleanupError) Error() string {
	return "connector WASM: host cleanup did not settle within five seconds"
}
func (*hostCleanupError) Timeout() bool   { return true }
func (*hostCleanupError) Temporary() bool { return true }

var errHostNetwork = &hostNetworkError{}
var errHostCleanup = &hostCleanupError{}

func hostRejection(value js.Value) (result error) {
	result = errors.New("connector WASM: host operation rejected")
	defer func() { _ = recover() }() // a host error getter is not trusted either.
	if value.Type() != js.TypeObject || value.IsNull() {
		return result
	}
	switch value.Get("name").String() {
	case hostNetworkErrorName:
		return errHostNetwork
	case hostCleanupErrorName:
		return errHostCleanup
	}
	return result
}

type hostPromise struct {
	result  <-chan jsResult
	abandon func()
	release func()
}

// race before installing Go callbacks. after the bounded race settles, a late
// original promise invokes only native JavaScript promise reactions, never a
// released js.Func. a timed-out host operation is not claimed to have joined.
func watchPromise(p js.Value, compact ...bool) hostPromise {
	counters.PromiseWaits++
	if len(compact) == 1 && compact[0] {
		return watchCompactPromise(p)
	}
	var rejectGate js.Value
	counters.PromiseExecutors++
	counters.CallbackRegistrations++
	executor := js.FuncOf(func(_ js.Value, args []js.Value) any {
		rejectGate = args[1]
		return nil
	})
	gate := js.Global().Get("Promise").New(executor)
	executor.Release()
	raced := js.Global().Get("Promise").Call("race", []any{p, gate})
	ch := make(chan jsResult, 1)
	counters.CallbackRegistrations += 2
	resolve := js.FuncOf(func(_ js.Value, args []js.Value) any {
		ch <- jsResult{value: args[0]}
		return nil
	})
	reject := js.FuncOf(func(_ js.Value, args []js.Value) any {
		// host errors may contain addresses or credentials. keep them private.
		ch <- jsResult{err: hostRejection(args[0])}
		return nil
	})
	raced.Call("then", resolve, reject)
	return hostPromise{result: ch, release: func() { resolve.Release(); reject.Release() }, abandon: func() {
		err := js.Global().Get("Error").New("connector host cleanup did not settle")
		err.Set("name", hostCleanupErrorName)
		rejectGate.Invoke(err)
	}}
}

var hostPromiseDispatcherOnce sync.Once
var hostPromiseDispatcher js.Func
var hostWaiterMu sync.Mutex
var nextHostWaiterID uint64
var hostWaiters = make(map[string]chan jsResult)

func initializeHostPromiseDispatcher() {
	hostPromiseDispatcherOnce.Do(func() {
		counters.PersistentCallbacks++
		hostPromiseDispatcher = js.FuncOf(func(_ js.Value, args []js.Value) any {
			hostWaiterMu.Lock()
			ch := hostWaiters[args[0].String()]
			hostWaiterMu.Unlock()
			if ch == nil {
				return nil
			}
			result := jsResult{value: args[2]}
			if args[1].Bool() {
				result = jsResult{err: hostRejection(args[2])}
			}
			select {
			case ch <- result:
			default:
			}
			return nil
		})
	})
}

func watchCompactPromise(p js.Value) hostPromise {
	initializeCompactConstructors()
	initializeHostPromiseDispatcher()
	counters.SharedPromiseWaits++
	gate := compactPromiseConstructor.Call("withResolvers")
	rejectGate := gate.Get("reject")
	// keep the same native race as baseline. abandoning a waiter consumes late
	// settlement without invoking any Go callback associated with that operation.
	raced := compactPromiseConstructor.Call("race", []any{p, gate.Get("promise")})
	ch := make(chan jsResult, 1)
	hostWaiterMu.Lock()
	nextHostWaiterID++
	id := strconv.FormatUint(nextHostWaiterID, 10)
	hostWaiters[id] = ch
	hostWaiterMu.Unlock()
	resolve := hostPromiseDispatcher.Value.Call("bind", js.Null(), id, false)
	reject := hostPromiseDispatcher.Value.Call("bind", js.Null(), id, true)
	raced.Call("then", resolve, reject)
	return hostPromise{result: ch, release: func() {
		hostWaiterMu.Lock()
		delete(hostWaiters, id)
		hostWaiterMu.Unlock()
	}, abandon: func() {
		err := js.Global().Get("Error").New("connector host cleanup did not settle")
		err.Set("name", hostCleanupErrorName)
		rejectGate.Invoke(err)
	}}
}

func (p hostPromise) settle(cancel func() error) (jsResult, error) {
	finished := make(chan struct{})
	timer := time.AfterFunc(hostSettlementTimeout, func() { defer close(finished); p.abandon() })
	err := cancel()
	result := <-p.result
	if !timer.Stop() {
		<-finished
	}
	return result, err
}

func await(ctx context.Context, promise js.Value, cancel func(), compact ...bool) (js.Value, error) {
	p := watchPromise(promise, compact...)
	defer p.release()
	select {
	case result := <-p.result:
		if cause := context.Cause(ctx); cause != nil {
			cancel()
			return result.value, errors.Join(cause, result.err)
		}
		return result.value, result.err
	case <-ctx.Done():
		result, _ := p.settle(func() error { cancel(); return nil })
		return result.value, errors.Join(context.Cause(ctx), result.err)
	}
}

func call(object js.Value, method string, args ...any) (value js.Value, err error) {
	defer func() {
		if caught := recover(); caught != nil {
			if rejected, ok := caught.(js.Error); ok {
				err = hostRejection(rejected.Value)
			} else {
				err = fmt.Errorf("connector WASM: host %s failed", method)
			}
		}
	}()
	return object.Call(method, args...), nil
}

func hostDial(host js.Value, compact ...bool) func(context.Context, string, string) (net.Conn, error) {
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		if network != "tcp" {
			return nil, errors.New("connector WASM: host supports TCP only")
		}
		if ctx.Err() != nil {
			return nil, errors.Join(net.ErrClosed, context.Cause(ctx))
		}
		abort := js.Global().Get("AbortController").New()
		p, err := call(host, "dialTCP", address, abort.Get("signal"))
		if err != nil {
			return nil, err
		}
		socket, err := await(ctx, p, func() { abort.Call("abort") }, compact...)
		if err != nil {
			if !socket.IsUndefined() && !socket.IsNull() {
				c := newHostConn(socket, address, compact...)
				err = errors.Join(err, c.Close())
			}
			return nil, err
		}
		if socket.Type() != js.TypeObject || socket.Get("read").Type() != js.TypeFunction || socket.Get("write").Type() != js.TypeFunction || socket.Get("close").Type() != js.TypeFunction {
			return nil, errors.New("connector WASM: host returned an invalid socket")
		}
		return newHostConn(socket, address, compact...), nil
	}
}

type hostConn struct {
	socket          js.Value
	remote          string
	readMu          sync.Mutex
	writeMu         sync.Mutex
	mu              sync.Mutex
	readAt, writeAt time.Time
	changed         chan struct{}
	done            chan struct{}
	closeFence      sync.Once
	closeMu         sync.Mutex
	closing         *hostCloseAttempt
	closeSucceeded  bool
	compact         bool
}

type hostCloseAttempt struct {
	done chan struct{}
	err  error
}

func newHostConn(socket js.Value, remote string, compact ...bool) *hostConn {
	return &hostConn{socket: socket, remote: remote, changed: make(chan struct{}), done: make(chan struct{}), compact: len(compact) == 1 && compact[0]}
}

func (c *hostConn) wait(p js.Value, read bool) (js.Value, error) {
	pending := watchPromise(p, c.compact)
	defer pending.release()
	stop := func(cause error) (js.Value, error) {
		result, cleanup := pending.settle(c.Close)
		return js.Undefined(), errors.Join(cause, result.err, cleanup)
	}
	for {
		c.mu.Lock()
		at, changed := c.writeAt, c.changed
		if read {
			at = c.readAt
		}
		c.mu.Unlock()
		if !at.IsZero() && !time.Now().Before(at) {
			return stop(os.ErrDeadlineExceeded)
		}
		var timer *time.Timer
		var expired <-chan time.Time
		if !at.IsZero() {
			timer = time.NewTimer(time.Until(at))
			expired = timer.C
		}
		stopTimer := func() {
			if timer != nil {
				timer.Stop()
			}
		}
		select {
		case result := <-pending.result:
			stopTimer()
			return result.value, result.err
		case <-changed:
			stopTimer()
		case <-c.done:
			stopTimer()
			return stop(net.ErrClosed)
		case <-expired:
			return stop(os.ErrDeadlineExceeded)
		}
	}
}

func (c *hostConn) Read(data []byte) (int, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()
	if len(data) == 0 {
		return 0, nil
	}
	select {
	case <-c.done:
		return 0, net.ErrClosed
	default:
	}
	counters.HostReads++
	p, err := call(c.socket, "read", len(data))
	if err != nil {
		return 0, err
	}
	v, err := c.wait(p, true)
	if err != nil {
		return 0, err
	}
	return c.readResult(data, v)
}

func (c *hostConn) readResult(data []byte, v js.Value) (int, error) {
	if v.IsNull() {
		return 0, io.EOF
	}
	if !v.InstanceOf(bytesConstructor(c.compact)) || v.Length() == 0 || v.Length() > len(data) {
		_ = c.Close()
		return 0, errors.New("connector WASM: host read violated byte bounds")
	}
	n := js.CopyBytesToGo(data, v)
	counters.HostReadBytes += uint64(n)
	return n, nil
}

func (c *hostConn) Write(data []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	select {
	case <-c.done:
		return 0, net.ErrClosed
	default:
	}
	bytes := bytesConstructor(c.compact).New(len(data))
	counters.HostWrites++
	counters.HostWriteBytes += uint64(len(data))
	js.CopyBytesToJS(bytes, data)
	p, err := call(c.socket, "write", bytes)
	if err != nil {
		return 0, err
	}
	if _, err = c.wait(p, false); err != nil {
		return 0, err
	}
	return len(data), nil
}

func (c *hostConn) Close() error {
	c.closeFence.Do(func() { close(c.done) })
	c.closeMu.Lock()
	if c.closeSucceeded {
		c.closeMu.Unlock()
		return nil
	}
	if pending := c.closing; pending != nil {
		c.closeMu.Unlock()
		<-pending.done
		return pending.err
	}
	attempt := &hostCloseAttempt{done: make(chan struct{})}
	c.closing = attempt
	c.closeMu.Unlock()
	p, err := call(c.socket, "close")
	if err == nil {
		pending := watchPromise(p, c.compact)
		defer pending.release()
		result, _ := pending.settle(func() error { return nil })
		err = result.err
	}
	c.closeMu.Lock()
	attempt.err = err
	c.closeSucceeded = err == nil
	c.closing = nil
	close(attempt.done)
	c.closeMu.Unlock()
	return err
}

type hostAddr string

func (hostAddr) Network() string         { return "tcp" }
func (a hostAddr) String() string        { return string(a) }
func (c *hostConn) LocalAddr() net.Addr  { return hostAddr("wasm") }
func (c *hostConn) RemoteAddr() net.Addr { return hostAddr(c.remote) }
func (c *hostConn) deadline(read, write bool, at time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if read {
		c.readAt = at
	}
	if write {
		c.writeAt = at
	}
	close(c.changed)
	c.changed = make(chan struct{})
	return nil
}
func (c *hostConn) SetDeadline(at time.Time) error      { return c.deadline(true, true, at) }
func (c *hostConn) SetReadDeadline(at time.Time) error  { return c.deadline(true, false, at) }
func (c *hostConn) SetWriteDeadline(at time.Time) error { return c.deadline(false, true, at) }

//go:build js && wasm

package main

import (
	"errors"
	"io"
	"net"
	"sync"
	"syscall/js"
)

const hostPumpByteCredit = 64 * 1024
const maxHostPumpID = 1<<53 - 1

var errHostPumpContract = errors.New("connector WASM: host pump violated byte bounds or event contract")
var hostPumpDispatcherOnce sync.Once
var hostPumpDispatcher js.Func
var hostPumpMu sync.Mutex
var nextHostPumpID uint64
var hostPumps = make(map[uint64]*hostPump)

type hostPump struct {
	id      uint64
	control js.Value
	compact bool
	mu      sync.Mutex
	closed  bool
	err     error
	eof     bool
	// read credit is returned only after this window has been fully consumed.
	bytes        []byte
	offset       int
	writePending int
	writeDone    int
	readReady    chan struct{}
	writeReady   chan struct{}
}

func initializeHostPumpDispatcher() {
	hostPumpDispatcherOnce.Do(func() {
		counters.PersistentCallbacks++
		hostPumpDispatcher = js.FuncOf(func(_ js.Value, args []js.Value) any {
			if len(args) != 3 || args[0].Type() != js.TypeNumber {
				return nil
			}
			id := args[0].Float()
			if id < 1 || id > maxHostPumpID || id != float64(uint64(id)) {
				return nil
			}
			hostPumpMu.Lock()
			pump := hostPumps[uint64(id)]
			hostPumpMu.Unlock()
			if pump != nil {
				pump.receive(args[1], args[2])
			}
			return nil
		})
	})
}

func (c *hostConn) startHostPump() error {
	initializeHostPumpDispatcher()
	p := &hostPump{compact: c.compact, readReady: make(chan struct{}, 1), writeReady: make(chan struct{}, 1)}
	hostPumpMu.Lock()
	if nextHostPumpID == maxHostPumpID {
		hostPumpMu.Unlock()
		return errors.New("connector WASM: host pump identifiers exhausted")
	}
	nextHostPumpID++
	p.id = nextHostPumpID
	hostPumps[p.id] = p
	hostPumpMu.Unlock()
	c.pump = p
	// the bound JS closure retains only a numeric id. retired and failed-close
	// callbacks never invoke a released Go function or reopen a stopped pump.
	receiver := hostPumpDispatcher.Value.Call("bind", js.Null(), float64(p.id))
	control, err := call(c.socket, "startPump", receiver)
	if err != nil {
		return err
	}
	if control.Type() != js.TypeObject || control.IsNull() || control.Get("write").Type() != js.TypeFunction || control.Get("resume").Type() != js.TypeFunction {
		return errHostPumpContract
	}
	p.control = control
	counters.HostPumpStarts++
	return nil
}

func signalHostPump(ready chan struct{}) {
	select {
	case ready <- struct{}{}:
	default:
	}
}

func (p *hostPump) receive(kind, value js.Value) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed || p.err != nil {
		return
	}
	counters.HostPumpNotifications++
	// malformed host values fail the stream without blocking the JS callback.
	defer func() {
		if recover() != nil {
			p.fail(errHostPumpContract)
		}
	}()
	if kind.Type() != js.TypeNumber {
		p.fail(errHostPumpContract)
		return
	}
	switch kind.Float() {
	case 1:
		if p.eof || !value.InstanceOf(bytesConstructor(p.compact)) || value.Length() == 0 || value.Length() > hostPumpByteCredit-len(p.bytes) {
			p.fail(errHostPumpContract)
			return
		}
		if p.bytes == nil {
			p.bytes = make([]byte, 0, hostPumpByteCredit)
		}
		start := len(p.bytes)
		p.bytes = p.bytes[:start+value.Length()]
		js.CopyBytesToGo(p.bytes[start:], value)
		counters.HostPumpReads++
		signalHostPump(p.readReady)
	case 2:
		if value.Type() != js.TypeNumber || value.Float() <= 0 || value.Float() > float64(p.writePending) || value.Float() != float64(value.Int()) {
			p.fail(errHostPumpContract)
			return
		}
		n := value.Int()
		p.writePending -= n
		p.writeDone += n
		signalHostPump(p.writeReady)
	case 3:
		if !value.IsNull() {
			p.fail(errHostPumpContract)
			return
		}
		p.eof = true
		signalHostPump(p.readReady)
	case 4:
		p.fail(hostRejection(value))
	default:
		p.fail(errHostPumpContract)
	}
}

// caller holds p.mu; these channels only announce readiness and never queue data.
func (p *hostPump) fail(err error) {
	p.err = err
	signalHostPump(p.readReady)
	signalHostPump(p.writeReady)
}

func (p *hostPump) stop() {
	p.mu.Lock()
	p.closed = true
	p.bytes = nil
	p.offset = 0
	p.mu.Unlock()
}

func (p *hostPump) retire() {
	hostPumpMu.Lock()
	delete(hostPumps, p.id)
	hostPumpMu.Unlock()
}

func (c *hostConn) readPump(data []byte) (int, error) {
	p := c.pump
	for {
		if _, err := waitHostEvent(c, (<-chan struct{})(p.readReady), true); err != nil {
			return 0, errors.Join(err, c.Close())
		}
		p.mu.Lock()
		if p.closed {
			p.mu.Unlock()
			return 0, errors.Join(net.ErrClosed, c.Close())
		}
		if p.offset < len(p.bytes) {
			n := copy(data, p.bytes[p.offset:])
			p.offset += n
			drained := p.offset == len(p.bytes)
			if drained {
				p.bytes = p.bytes[:0]
				p.offset = 0
			}
			resume := drained && !p.eof && p.err == nil
			if !drained || p.eof || p.err != nil {
				signalHostPump(p.readReady)
			}
			p.mu.Unlock()
			counters.HostReadBytes += uint64(n)
			if resume {
				if _, err := call(p.control, "resume"); err != nil {
					p.mu.Lock()
					p.fail(err)
					p.mu.Unlock()
				}
			}
			return n, nil
		}
		err := p.err
		if err == nil && p.eof {
			err = io.EOF
		}
		if err != nil {
			signalHostPump(p.readReady)
		}
		p.mu.Unlock()
		if err != nil {
			return 0, err
		}
	}
}

func (c *hostConn) writePump(data []byte) (int, error) {
	p := c.pump
	written := 0
	for written < len(data) {
		n := min(len(data)-written, hostPumpByteCredit)
		p.mu.Lock()
		err := p.err
		if p.closed {
			p.mu.Unlock()
			return written, errors.Join(net.ErrClosed, c.Close())
		}
		if err != nil {
			p.mu.Unlock()
			return written, err
		}
		p.writePending = n
		p.writeDone = 0
		p.mu.Unlock()
		bytes := bytesConstructor(c.compact).New(n)
		js.CopyBytesToJS(bytes, data[written:written+n])
		accepted, err := call(p.control, "write", bytes)
		if err == nil && (accepted.Type() != js.TypeBoolean || !accepted.Bool()) {
			err = errHostPumpContract
		}
		if err != nil {
			p.mu.Lock()
			p.fail(err)
			p.mu.Unlock()
			return written, err
		}
		counters.HostPumpWrites++
		for {
			if _, err := waitHostEvent(c, (<-chan struct{})(p.writeReady), false); err != nil {
				cleanup := c.Close()
				p.mu.Lock()
				completed := p.writeDone
				p.writeDone = 0
				p.mu.Unlock()
				return written + completed, errors.Join(err, cleanup)
			}
			p.mu.Lock()
			completed, err := p.writeDone, p.err
			p.writeDone = 0
			if p.closed {
				p.mu.Unlock()
				return written + completed, errors.Join(net.ErrClosed, c.Close())
			}
			pending := p.writePending
			p.mu.Unlock()
			written += completed
			if err != nil {
				return written, err
			}
			if pending == 0 {
				break
			}
		}
	}
	return written, nil
}

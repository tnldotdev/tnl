//go:build js && wasm

package main

import (
	"io"
	"sync"
	"syscall/js"
)

const applicationPumpCapacity = 64 * 1024

const (
	applicationPumpSetup = iota
	applicationPumpWrite
	applicationPumpResume
	applicationPumpDeliver
)

const (
	applicationData = iota + 1
	applicationWritten
	applicationEOF
	applicationError
)

var applicationDispatcherOnce sync.Once
var applicationDispatcher js.Func
var applicationRegistryMu sync.Mutex
var applicationNextID uint64
var applicationRegistry = make(map[uint64]*byteStream)

type applicationNotification struct {
	kind  int
	value any
	ack   chan bool
}

// each direction retains one reusable 64 kib buffer. the write token covers
// both queued and active bytes; a read requires an explicit chunk credit.
type applicationPump struct {
	stream        *byteStream
	receive       js.Value
	delivery      js.Value
	writeBuffer   []byte
	readBuffer    []byte
	writeFree     chan struct{}
	writes        chan int
	readCredit    chan struct{}
	notifications chan applicationNotification
	stopped       chan struct{}
	stopOnce      sync.Once
	failOnce      sync.Once
}

func initializeApplicationDispatcher() {
	applicationDispatcherOnce.Do(func() {
		counters.PersistentCallbacks++
		applicationDispatcher = js.FuncOf(func(_ js.Value, args []js.Value) (result any) {
			// validation and receiver exceptions must not escape a go callback.
			defer func() { _ = recover() }()
			if len(args) < 2 {
				return nil
			}
			operation := args[1].Int()
			if operation == applicationPumpWrite {
				result = false
			}
			applicationRegistryMu.Lock()
			s := applicationRegistry[uint64(args[0].Float())]
			applicationRegistryMu.Unlock()
			if s == nil {
				return result
			}
			if operation == applicationPumpSetup {
				return s.startApplicationPump(args[2:])
			}
			s.mu.Lock()
			p := s.application
			s.mu.Unlock()
			if p == nil {
				return result
			}
			switch operation {
			case applicationPumpWrite:
				return p.enqueue(args[2:])
			case applicationPumpResume:
				if p.active() {
					select {
					case p.readCredit <- struct{}{}:
					default:
					}
				}
			case applicationPumpDeliver:
				p.deliver()
			}
			return result
		})
	})
}

func (s *byteStream) applicationMethod(operation int) js.Value {
	return applicationDispatcher.Value.Call("bind", js.Null(), float64(s.applicationID), operation)
}

func (s *byteStream) exportApplicationPump() {
	initializeApplicationDispatcher()
	applicationRegistryMu.Lock()
	applicationNextID++
	s.applicationID = applicationNextID
	applicationRegistry[s.applicationID] = s
	applicationRegistryMu.Unlock()
	s.object.Set("pump", s.applicationMethod(applicationPumpSetup))
}

func (s *byteStream) startApplicationPump(args []js.Value) any {
	if len(args) != 1 || args[0].Type() != js.TypeFunction {
		return nil
	}
	// no js calls or waiting operations run while holding the stream lock.
	s.mu.Lock()
	valid := !s.closed && s.phase == streamSecure && !s.legacyIO && s.application == nil && s.ctx.Err() == nil
	s.mu.Unlock()
	if !valid {
		return nil
	}
	control := js.Global().Get("Object").New()
	control.Set("write", s.applicationMethod(applicationPumpWrite))
	control.Set("resume", s.applicationMethod(applicationPumpResume))
	p := &applicationPump{
		stream: s, receive: args[0], delivery: s.applicationMethod(applicationPumpDeliver),
		writeBuffer: make([]byte, applicationPumpCapacity), readBuffer: make([]byte, applicationPumpCapacity),
		writeFree: make(chan struct{}, 1), writes: make(chan int, 1), readCredit: make(chan struct{}, 1),
		notifications: make(chan applicationNotification, 3), stopped: make(chan struct{}),
	}
	p.writeFree <- struct{}{}
	s.mu.Lock()
	if s.closed || s.application != nil || s.legacyIO || s.ctx.Err() != nil {
		s.mu.Unlock()
		return nil
	}
	s.application = p
	s.operations.Add(3)
	s.mu.Unlock()
	counters.ApplicationPumpStarts++
	counters.ApplicationReadAllocated += applicationPumpCapacity
	counters.ApplicationWriteAllocated += applicationPumpCapacity
	go p.readLoop()
	go p.writeLoop()
	go func() {
		defer s.operations.Done()
		select {
		case <-s.ctx.Done():
			p.fail(make(chan bool, 1))
		case <-p.stopped:
		}
	}()
	return control
}

func (p *applicationPump) active() bool {
	select {
	case <-p.stopped:
		return false
	default:
		return p.stream.ctx.Err() == nil
	}
}

func (p *applicationPump) stop() { p.stopOnce.Do(func() { close(p.stopped) }) }

func (p *applicationPump) enqueue(args []js.Value) (accepted bool) {
	if !p.active() || len(args) != 1 || !args[0].InstanceOf(bytesConstructor(p.stream.funcs.compact)) {
		return false
	}
	size := args[0].Length()
	if size < 1 || size > applicationPumpCapacity {
		return false
	}
	select {
	case <-p.writeFree:
	default:
		return false
	}
	defer func() {
		if !accepted {
			select {
			case p.writeFree <- struct{}{}:
			default:
			}
		}
	}()
	js.CopyBytesToGo(p.writeBuffer[:size], args[0])
	select {
	case p.writes <- size:
		counters.ApplicationPumpWrites++
		return true
	default:
		return false
	}
}

// the dispatcher invokes receive from a microtask, after the scheduling go call
// has returned. each worker joins delivery before reusing its notification slot.
func (p *applicationPump) notify(kind int, value any, ack chan bool) bool {
	p.stream.mu.Lock()
	closed := p.stream.closed
	p.stream.mu.Unlock()
	if closed {
		return false
	}
	p.notifications <- applicationNotification{kind: kind, value: value, ack: ack}
	if _, err := call(js.Global(), "queueMicrotask", p.delivery); err != nil {
		return false
	}
	return <-ack
}

func (p *applicationPump) deliver() {
	var event applicationNotification
	select {
	case event = <-p.notifications:
	default:
		return
	}
	delivered := false
	defer func() {
		_ = recover()
		select {
		case event.ack <- delivered:
		default:
		}
	}()
	p.stream.mu.Lock()
	closed := p.stream.closed
	p.stream.mu.Unlock()
	if closed || (event.kind != applicationError && !p.active()) {
		return
	}
	counters.ApplicationPumpNotifications++
	p.receive.Invoke(event.kind, event.value)
	delivered = true
}

func (p *applicationPump) fail(ack chan bool) {
	p.failOnce.Do(func() {
		p.stop()
		_ = p.stream.raw.Close()
		p.notify(applicationError, nil, ack)
	})
}

func (p *applicationPump) readLoop() {
	defer p.stream.operations.Done()
	ack := make(chan bool, 1)
	for {
		select {
		case <-p.stopped:
			return
		case <-p.readCredit:
		}
		if !p.active() {
			return
		}
		counters.ApplicationPumpReads++
		counters.ApplicationReads++
		n, err := p.stream.conn.Read(p.readBuffer)
		if n > 0 {
			counters.ApplicationReadBytes += uint64(n)
			bytes := bytesConstructor(p.stream.funcs.compact).New(n)
			js.CopyBytesToJS(bytes, p.readBuffer[:n])
			if !p.notify(applicationData, bytes, ack) {
				p.fail(ack)
				return
			}
		}
		if err == io.EOF {
			if !p.notify(applicationEOF, nil, ack) {
				p.fail(ack)
			}
			return
		}
		if err != nil || n == 0 {
			p.fail(ack)
			return
		}
	}
}

func (p *applicationPump) writeLoop() {
	defer p.stream.operations.Done()
	ack := make(chan bool, 1)
	for {
		var size int
		select {
		case <-p.stopped:
			return
		case size = <-p.writes:
		}
		if !p.active() {
			return
		}
		counters.ApplicationWrites++
		bytes := p.writeBuffer[:size]
		for len(bytes) > 0 {
			n, err := p.stream.conn.Write(bytes)
			counters.ApplicationWriteBytes += uint64(n)
			if err != nil || n == 0 {
				p.fail(ack)
				return
			}
			bytes = bytes[n:]
		}
		p.writeFree <- struct{}{}
		if !p.notify(applicationWritten, size, ack) {
			p.fail(ack)
			return
		}
	}
}

package publisher

import (
	"bufio"
	"errors"
	"io"
	"sync"
	"time"

	"github.com/mediocregopher/radix/v4/resp"
	"github.com/mediocregopher/radix/v4/resp/resp3"
	"github.com/tnldotdev/tnl/internal/inspection"
)

const (
	redisInspectionChunkSize = 4 << 10
	redisInspectionQueueSize = 16
	redisInspectionPending   = 32
	redisInspectionVerbLimit = 64
)

type redisCall struct {
	command string
	started time.Time
}

// redisInspector observes complete command outcomes without reading arguments
// into the project journal or slowing the visitor stream. a full queue stops
// observation for this connection; forwarding continues unchanged.
type redisInspector struct {
	mu         sync.Mutex
	client     chan []byte
	server     chan []byte
	ready      chan struct{}
	clientDone chan struct{}
	serverDone chan struct{}
	pending    []redisCall
	stopped    bool
	observe    func(RedisObservation)
}

func newRedisInspector(observe func(RedisObservation)) *redisInspector {
	r := &redisInspector{
		client: make(chan []byte, redisInspectionQueueSize), server: make(chan []byte, redisInspectionQueueSize),
		ready: make(chan struct{}, 1), clientDone: make(chan struct{}), serverDone: make(chan struct{}), observe: observe,
	}
	go r.readCommands()
	go r.readReplies()
	return r
}

func (r *redisInspector) clientBytes(data []byte) { r.enqueue(r.client, data) }
func (r *redisInspector) serverBytes(data []byte) { r.enqueue(r.server, data) }

func (r *redisInspector) enqueue(queue chan []byte, data []byte) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.stopped {
		return
	}
	for len(data) > 0 {
		size := min(len(data), redisInspectionChunkSize)
		chunk := append([]byte(nil), data[:size]...)
		select {
		case queue <- chunk:
			data = data[size:]
		default:
			r.stopLocked()
			return
		}
	}
}

func (r *redisInspector) stop() {
	r.mu.Lock()
	r.stopLocked()
	r.mu.Unlock()
}

func (r *redisInspector) drain() {
	r.stop()
	<-r.clientDone
	<-r.serverDone
}

func (r *redisInspector) stopLocked() {
	if r.stopped {
		return
	}
	r.stopped = true
	close(r.client)
	close(r.server)
}

type redisQueueReader struct {
	queue   <-chan []byte
	current []byte
}

func (r *redisQueueReader) Read(data []byte) (int, error) {
	for len(r.current) == 0 {
		chunk, ok := <-r.queue
		if !ok {
			return 0, io.EOF
		}
		r.current = chunk
	}
	count := copy(data, r.current)
	r.current = r.current[count:]
	return count, nil
}

type redisVerb struct{ bytes []byte }

func (v *redisVerb) Write(data []byte) (int, error) {
	if len(v.bytes)+len(data) > redisInspectionVerbLimit {
		return 0, errors.New("redis command name exceeds inspection limit")
	}
	v.bytes = append(v.bytes, data...)
	return len(data), nil
}

func (v *redisVerb) name() (string, bool) {
	if len(v.bytes) == 0 {
		return "", false
	}
	for index, value := range v.bytes {
		if value >= 'a' && value <= 'z' {
			value -= 'a' - 'A'
			v.bytes[index] = value
		}
		if value >= 'A' && value <= 'Z' || value >= '0' && value <= '9' || value == '.' || value == '_' || value == '-' {
			continue
		}
		return "", false
	}
	return string(v.bytes), true
}

func (r *redisInspector) readCommands() {
	defer close(r.clientDone)
	reader := bufio.NewReaderSize(&redisQueueReader{queue: r.client}, 512)
	opts := resp.NewOpts()
	opts.DisableErrorBubbling = true
	for {
		var header resp3.ArrayHeader
		if err := header.UnmarshalRESP(reader, opts); err != nil {
			r.stop()
			return
		}
		if header.StreamedArrayHeader || header.NumElems < 1 || header.NumElems > 64 {
			r.stop()
			return
		}
		var verb redisVerb
		if err := resp3.Unmarshal(reader, &verb, opts); err != nil {
			r.stop()
			return
		}
		name, valid := verb.name()
		if !valid {
			r.stop()
			return
		}
		for range header.NumElems - 1 {
			if err := resp3.Unmarshal(reader, nil, opts); err != nil {
				r.stop()
				return
			}
		}
		// RESP2 subscription arrays and monitor output are unsolicited replies.
		// stop before they can be attributed to an unrelated command.
		switch name {
		case "SUBSCRIBE", "PSUBSCRIBE", "SSUBSCRIBE", "MONITOR":
			r.stop()
			return
		}
		r.mu.Lock()
		if len(r.pending) >= redisInspectionPending {
			r.stopLocked()
			r.mu.Unlock()
			return
		}
		r.pending = append(r.pending, redisCall{command: name, started: time.Now().UTC()})
		r.mu.Unlock()
		select {
		case r.ready <- struct{}{}:
		default:
		}
	}
}

func (r *redisInspector) takePending() (redisCall, bool) {
	for {
		r.mu.Lock()
		if len(r.pending) > 0 {
			call := r.pending[0]
			r.pending[0] = redisCall{}
			r.pending = r.pending[1:]
			r.mu.Unlock()
			return call, true
		}
		r.mu.Unlock()
		select {
		case <-r.ready:
		case <-r.clientDone:
			r.mu.Lock()
			remaining := len(r.pending)
			r.mu.Unlock()
			if remaining == 0 {
				return redisCall{}, false
			}
		}
	}
}

func (r *redisInspector) readReplies() {
	defer close(r.serverDone)
	reader := bufio.NewReaderSize(&redisQueueReader{queue: r.server}, 512)
	opts := resp.NewOpts()
	opts.DisableErrorBubbling = true
	for {
		prefix, err := reader.Peek(1)
		if err != nil {
			r.stop()
			return
		}
		if resp3.Prefix(prefix[0]) == resp3.AttributeHeaderPrefix {
			if err := resp3.DiscardAttribute(reader, opts); err != nil {
				r.stop()
				return
			}
			continue
		}
		push := resp3.Prefix(prefix[0]) == resp3.PushHeaderPrefix
		failed := resp3.Prefix(prefix[0]) == resp3.SimpleErrorPrefix || resp3.Prefix(prefix[0]) == resp3.BlobErrorPrefix
		if err := resp3.Unmarshal(reader, nil, opts); err != nil {
			r.stop()
			return
		}
		if push {
			continue
		}
		call, ok := r.takePending()
		if !ok {
			r.stop()
			return
		}
		result := inspection.ResultOK
		if failed {
			result = inspection.ResultError
		}
		r.observe(RedisObservation{ReceivedAt: call.started, Command: call.command, Result: result, Duration: time.Since(call.started)})
	}
}

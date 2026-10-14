package publisher

import (
	"bufio"
	"errors"
	"io"
	"strconv"
	"sync"
	"time"

	"github.com/tnldotdev/tnl/internal/inspection"
)

const (
	redisInspectionChunkSize  = 4 << 10
	redisInspectionQueueSize  = 16
	redisInspectionPending    = 32
	redisInspectionVerbLimit  = 64
	redisInspectionFrameLimit = 1 << 20
)

// RedisObservation contains only the command name and the outcome of its reply.
type RedisObservation struct {
	ReceivedAt time.Time
	Command    string
	Result     inspection.Result
	Duration   time.Duration
}

type redisCall struct {
	command string
	started time.Time
}

// the two bounded queues keep parsing off the forwarding path. once inspection
// cannot keep up, it stops for this connection; forwarding remains unchanged.
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
	if !r.stopped {
		r.stopped = true
		close(r.client)
		close(r.server)
	}
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

var errRedisOpaque = errors.New("redis inspection: unsupported or oversized frame")

// redisFrameReader never retains argument or reply data. its line, depth, item
// count, and total frame budgets also bound malformed and fragmented frames.
type redisFrameReader struct {
	reader *bufio.Reader
	budget int
}

func (r *redisFrameReader) line() ([]byte, error) {
	line, err := r.reader.ReadSlice('\n')
	if err != nil || len(line) < 2 || line[len(line)-2] != '\r' || len(line) > r.budget {
		return nil, errRedisOpaque
	}
	r.budget -= len(line)
	return line[:len(line)-2], nil
}

func (r *redisFrameReader) count(allowNull bool) (int, error) {
	line, err := r.line()
	if err != nil {
		return 0, err
	}
	n, err := strconv.Atoi(string(line))
	if err != nil || n < 0 && !(allowNull && n == -1) || n > 64 {
		return 0, errRedisOpaque
	}
	return n, nil
}

func (r *redisFrameReader) prefix() (byte, error) {
	if r.budget == 0 {
		return 0, errRedisOpaque
	}
	p, err := r.reader.ReadByte()
	r.budget--
	return p, err
}

func (r *redisFrameReader) bulk(limit int, capture bool) ([]byte, error) {
	line, err := r.line()
	if err != nil {
		return nil, err
	}
	if string(line) == "-1" && !capture {
		return nil, nil
	}
	n, err := strconv.Atoi(string(line))
	if err != nil || n < 0 || n > limit || n+2 > r.budget {
		return nil, errRedisOpaque
	}
	var value []byte
	if capture {
		value = make([]byte, n)
		_, err = io.ReadFull(r.reader, value)
	} else {
		_, err = io.CopyN(io.Discard, r.reader, int64(n))
	}
	if err != nil {
		return nil, err
	}
	var end [2]byte
	if _, err := io.ReadFull(r.reader, end[:]); err != nil || end != [2]byte{'\r', '\n'} {
		return nil, errRedisOpaque
	}
	r.budget -= n + 2
	return value, nil
}

func (r *redisFrameReader) value(depth int) error {
	if depth > 8 {
		return errRedisOpaque
	}
	p, err := r.prefix()
	if err != nil {
		return err
	}
	switch p {
	case '+', '-', ':', ',', '(', '#', '_':
		_, err = r.line()
		return err
	case '$', '!', '=':
		_, err = r.bulk(redisInspectionFrameLimit, false)
		return err
	case '*', '~', '>', '%', '|':
		count, err := r.count(p == '*')
		if err != nil {
			return err
		}
		if p == '%' || p == '|' {
			count *= 2
		}
		for range count {
			if err := r.value(depth + 1); err != nil {
				return err
			}
		}
		return nil
	default:
		return errRedisOpaque
	}
}

func parseRedisCommand(reader *bufio.Reader) (string, error) {
	r := redisFrameReader{reader: reader, budget: redisInspectionFrameLimit}
	p, err := r.prefix()
	if err != nil || p != '*' {
		return "", errRedisOpaque
	}
	count, err := r.count(false)
	if err != nil || count == 0 {
		return "", errRedisOpaque
	}
	p, err = r.prefix()
	if err != nil || p != '$' {
		return "", errRedisOpaque
	}
	verb, err := r.bulk(redisInspectionVerbLimit, true)
	if err != nil || len(verb) == 0 {
		return "", errRedisOpaque
	}
	for i, value := range verb {
		if value >= 'a' && value <= 'z' {
			value -= 'a' - 'A'
			verb[i] = value
		}
		if value >= 'A' && value <= 'Z' || value >= '0' && value <= '9' || value == '.' || value == '_' || value == '-' {
			continue
		}
		return "", errRedisOpaque
	}
	for range count - 1 {
		if err := r.value(0); err != nil {
			return "", err
		}
	}
	return string(verb), nil
}

func (r *redisInspector) readCommands() {
	defer close(r.clientDone)
	reader := bufio.NewReaderSize(&redisQueueReader{queue: r.client}, 512)
	for {
		name, err := parseRedisCommand(reader)
		if err != nil {
			r.stop()
			return
		}
		// RESP2 subscriptions and monitor mode produce unattributable replies.
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
			return redisCall{}, false
		}
	}
}

func (r *redisInspector) readReplies() {
	defer close(r.serverDone)
	reader := bufio.NewReaderSize(&redisQueueReader{queue: r.server}, 512)
	for {
		frame := redisFrameReader{reader: reader, budget: redisInspectionFrameLimit}
		prefix, err := reader.Peek(1)
		if err != nil {
			r.stop()
			return
		}
		kind := prefix[0]
		if err := frame.value(0); err != nil {
			r.stop()
			return
		}
		if kind == '|' || kind == '>' { // attributes and RESP3 push are not command replies.
			continue
		}
		call, ok := r.takePending()
		if !ok {
			r.stop()
			return
		}
		result := inspection.ResultOK
		if kind == '-' || kind == '!' {
			result = inspection.ResultError
		}
		r.observe(RedisObservation{ReceivedAt: call.started, Command: call.command, Result: result, Duration: time.Since(call.started)})
	}
}

package muxsession

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"time"
)

const (
	yamuxHeaderBytes    = 12
	yamuxReceiptBytes   = 256 << 10
	yamuxReceiptFrames  = 256
	yamuxReceiptTimeout = 10 * time.Second
	yamuxReceiptFirstID = uint32(1 << 31)
	yamuxReceiptData    = 0
	yamuxReceiptPing    = 2
	yamuxReceiptSYN     = 1
	yamuxReceiptACK     = 2
)

// yamuxReceiptConn bounds submission to hosts whose WebSocket.send is
// synchronous and has no bufferedAmount. the existing yamux sender writes one
// complete frame per Write; this adapter verifies that contract. before either
// budget is exceeded, it writes an ordinary yamux PING at that frame boundary
// and waits for its exact ACK, which acknowledges the preceding byte prefix.
//
// at most 256 KiB and 257 yamux frames (including the receipt request) can be
// submitted without a peer receipt. both data and control frames spend budget.
// streams, flow control, ping replies, and all received bytes remain with yamux.
// receipt IDs use the upper half of the ping namespace and never wrap or reuse.
//
// the receipt request is written directly, not queued through Session.Ping:
// the yamux sender is the blocked caller and cannot service its own ping queue.
// only outbound host clients use this adapter; their native relay peer's sender
// is not receipt-gated. no second multiplexer or remote extension is required.
type yamuxReceiptConn struct {
	net.Conn
	writeMu    sync.Mutex
	sentBytes  int
	sentFrames int
	byteLimit  int
	frameLimit int
	nextID     uint32

	mu        sync.Mutex
	pendingID uint32
	pending   chan struct{}
	deadline  time.Time
	wake      chan struct{}
	done      chan struct{}
	closeOnce sync.Once
	closeErr  error

	// only the yamux reader calls Read. this framing tap locates PING ACKs
	// without interpreting, buffering, or routing stream data.
	header      [yamuxHeaderBytes]byte
	headerUsed  int
	payloadLeft uint32
}

func newYamuxReceiptConn(network net.Conn) *yamuxReceiptConn {
	return &yamuxReceiptConn{
		Conn: network, byteLimit: yamuxReceiptBytes, frameLimit: yamuxReceiptFrames,
		nextID: yamuxReceiptFirstID, wake: make(chan struct{}, 1), done: make(chan struct{}),
	}
}

func (c *yamuxReceiptConn) Write(p []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if err := validateYamuxReceiptWrite(p); err != nil {
		return 0, errors.Join(err, c.Close())
	}
	if len(p) > c.byteLimit-yamuxHeaderBytes {
		return 0, errors.Join(errors.New("muxsession: yamux frame exceeds host send budget"), c.Close())
	}
	if c.sentBytes+len(p) > c.byteLimit-yamuxHeaderBytes || c.sentFrames >= c.frameLimit {
		if err := c.receipt(); err != nil {
			return 0, errors.Join(err, c.Close())
		}
		c.sentBytes, c.sentFrames = 0, 0
	}
	n, err := c.Conn.Write(p)
	if err == nil && n != len(p) {
		err = io.ErrShortWrite
	}
	if err != nil {
		return n, errors.Join(err, c.Close())
	}
	c.sentBytes += n
	c.sentFrames++
	return n, nil
}

func validateYamuxReceiptWrite(p []byte) error {
	if len(p) < yamuxHeaderBytes || p[0] != 0 || p[1] > 3 {
		return errors.New("muxsession: host write requires a complete yamux frame")
	}
	size := 0
	if p[1] == yamuxReceiptData {
		length := binary.BigEndian.Uint32(p[8:12])
		if length > WebSocketMaxBytes {
			return errors.New("muxsession: yamux data frame exceeds host frame budget")
		}
		size = int(length)
	}
	if len(p) != yamuxHeaderBytes+size {
		return errors.New("muxsession: host write requires one complete yamux frame")
	}
	if p[1] == yamuxReceiptPing && binary.BigEndian.Uint16(p[2:4])&yamuxReceiptSYN != 0 &&
		binary.BigEndian.Uint32(p[8:12]) >= yamuxReceiptFirstID {
		return errors.New("muxsession: yamux ping namespace exhausted")
	}
	return nil
}

func (c *yamuxReceiptConn) receipt() error {
	if c.nextID < yamuxReceiptFirstID {
		return errors.New("muxsession: yamux receipt namespace exhausted")
	}
	id := c.nextID
	c.nextID++
	ack := make(chan struct{})
	c.mu.Lock()
	c.pendingID, c.pending = id, ack
	c.mu.Unlock()
	defer func() {
		c.mu.Lock()
		c.pending = nil
		c.mu.Unlock()
	}()
	var ping [yamuxHeaderBytes]byte
	ping[1] = yamuxReceiptPing
	binary.BigEndian.PutUint16(ping[2:4], yamuxReceiptSYN)
	binary.BigEndian.PutUint32(ping[8:12], id)
	if n, err := c.Conn.Write(ping[:]); err != nil {
		return err
	} else if n != len(ping) {
		return io.ErrShortWrite
	}
	limit := time.Now().Add(yamuxReceiptTimeout)
	for {
		c.mu.Lock()
		at := c.deadline
		c.mu.Unlock()
		if at.IsZero() || at.After(limit) {
			at = limit
		}
		if !time.Now().Before(at) {
			return os.ErrDeadlineExceeded
		}
		timer := time.NewTimer(time.Until(at))
		select {
		case <-ack:
			timer.Stop()
			return nil
		case <-c.done:
			timer.Stop()
			return net.ErrClosed
		case <-c.wake:
			timer.Stop()
		case <-timer.C:
		}
	}
}

func (c *yamuxReceiptConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	for remaining := p[:n]; len(remaining) > 0; {
		if c.payloadLeft > 0 {
			skip := uint32(min(uint64(len(remaining)), uint64(c.payloadLeft)))
			remaining = remaining[int(skip):]
			c.payloadLeft -= skip
			continue
		}
		size := copy(c.header[c.headerUsed:], remaining)
		remaining = remaining[size:]
		c.headerUsed += size
		if c.headerUsed != yamuxHeaderBytes {
			continue
		}
		c.headerUsed = 0
		if c.header[0] != 0 || c.header[1] > 3 {
			return n, errors.Join(errors.New("muxsession: invalid yamux receipt framing"), err)
		}
		switch c.header[1] {
		case yamuxReceiptData:
			c.payloadLeft = binary.BigEndian.Uint32(c.header[8:12])
		case yamuxReceiptPing:
			if binary.BigEndian.Uint16(c.header[2:4]) == yamuxReceiptACK &&
				binary.BigEndian.Uint32(c.header[4:8]) == 0 {
				c.mu.Lock()
				if c.pending != nil && c.pendingID == binary.BigEndian.Uint32(c.header[8:12]) {
					select {
					case <-c.pending:
					default:
						close(c.pending)
					}
				}
				c.mu.Unlock()
			}
		}
	}
	return n, err
}

func (c *yamuxReceiptConn) SetWriteDeadline(at time.Time) error {
	c.mu.Lock()
	c.deadline = at
	c.mu.Unlock()
	select {
	case c.wake <- struct{}{}:
	default:
	}
	return c.Conn.SetWriteDeadline(at)
}

func (c *yamuxReceiptConn) SetDeadline(at time.Time) error {
	return errors.Join(c.Conn.SetReadDeadline(at), c.SetWriteDeadline(at))
}

func (c *yamuxReceiptConn) Close() error {
	c.closeOnce.Do(func() {
		close(c.done)
		c.closeErr = c.Conn.Close()
	})
	return c.closeErr
}

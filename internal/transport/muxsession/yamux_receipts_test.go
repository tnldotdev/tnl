package muxsession

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"testing"
	"time"
)

// synchronous submission with no host buffering signal: the peer can stop
// reading indefinitely while this fake still accepts every submitted message.
type receiptTestHost struct {
	net.Conn
	sent   chan []byte
	closed chan struct{}
	once   sync.Once
}

func (c *receiptTestHost) Write(p []byte) (int, error) {
	select {
	case <-c.closed:
		return 0, net.ErrClosed
	default:
	}
	c.sent <- bytes.Clone(p)
	return len(p), nil
}

func (c *receiptTestHost) Close() error {
	c.once.Do(func() { close(c.closed) })
	return c.Conn.Close()
}

func receiptTestNetwork(t *testing.T) (*yamuxReceiptConn, *receiptTestHost, net.Conn) {
	t.Helper()
	local, peer := net.Pipe()
	host := &receiptTestHost{Conn: local, sent: make(chan []byte, 1024), closed: make(chan struct{})}
	network := newYamuxReceiptConn(host)
	t.Cleanup(func() { _ = network.Close(); _ = peer.Close() })
	return network, host, peer
}

func receiptTestFrame(kind byte, flags uint16, id uint32, payload []byte) []byte {
	frame := make([]byte, yamuxHeaderBytes+len(payload))
	frame[1] = kind
	binary.BigEndian.PutUint16(frame[2:4], flags)
	if kind == yamuxReceiptPing {
		binary.BigEndian.PutUint32(frame[8:12], id)
	} else {
		binary.BigEndian.PutUint32(frame[4:8], id)
		binary.BigEndian.PutUint32(frame[8:12], uint32(len(payload)))
	}
	copy(frame[yamuxHeaderBytes:], payload)
	return frame
}

func TestYamuxReceiptsBoundSlowHostBytesAndControlFrames(t *testing.T) {
	for _, kind := range []string{"data bytes", "control frames"} {
		t.Run(kind, func(t *testing.T) {
			network, host, _ := receiptTestNetwork(t)
			frame := receiptTestFrame(yamuxReceiptData, 0, 1, make([]byte, 4096))
			if kind == "control frames" {
				frame = receiptTestFrame(1, 0, 1, nil)
			}
			count := min((yamuxReceiptBytes-yamuxHeaderBytes)/len(frame), yamuxReceiptFrames)
			for range count {
				if _, err := network.Write(frame); err != nil {
					t.Fatal(err)
				}
			}
			type result struct {
				n   int
				err error
			}
			completed := make(chan result, 1)
			go func() { n, err := network.Write(frame); completed <- result{n, err} }()
			total := 0
			for i := 0; i <= count; i++ {
				p := muxAwait(t, host.sent)
				total += len(p)
				if i == count && (p[1] != yamuxReceiptPing || binary.BigEndian.Uint16(p[2:4]) != yamuxReceiptSYN) {
					t.Fatal("budget did not end with a standard yamux receipt request", p)
				}
			}
			if total > yamuxReceiptBytes || count+1 > yamuxReceiptFrames+1 {
				t.Fatal("unacknowledged host submissions exceeded budget", total, count+1)
			}
			select {
			case got := <-completed:
				t.Fatal("slow peer released the gate without a receipt", got)
			default:
			}
			// deadline updates must wake a writer even though the host send
			// itself always succeeds and the peer never reads or acknowledges.
			_ = network.SetWriteDeadline(time.Now().Add(-time.Second))
			got := muxAwait(t, completed)
			if got.n != 0 || !errors.Is(got.err, os.ErrDeadlineExceeded) {
				t.Fatal("receipt wait ignored deadline", got)
			}
			select {
			case <-host.closed:
			default:
				t.Fatal("unconfirmed send budget was reused after timeout")
			}
		})
	}
}

func receiptReadThrough(t *testing.T, network net.Conn, peer net.Conn, wire []byte, split int) {
	t.Helper()
	written := make(chan error, 1)
	go func() {
		var err error
		for remaining := wire; len(remaining) > 0 && err == nil; {
			n := min(len(remaining), split)
			_, err = peer.Write(remaining[:n])
			remaining = remaining[n:]
		}
		written <- err
	}()
	got := make([]byte, len(wire))
	if _, err := io.ReadFull(network, got); err != nil || !bytes.Equal(got, wire) {
		t.Fatal("receipt tap changed yamux bytes", err)
	}
	if err := muxAwait(t, written); err != nil {
		t.Fatal(err)
	}
}

func TestYamuxReceiptsRequireExactFramedACKAndIgnoreStaleReceipts(t *testing.T) {
	network, host, peer := receiptTestNetwork(t)
	network.frameLimit = 1
	data := receiptTestFrame(yamuxReceiptData, 0, 1, []byte("payload"))
	if _, err := network.Write(data); err != nil {
		t.Fatal(err)
	}
	<-host.sent
	result := make(chan error, 1)
	go func() { _, err := network.Write(data); result <- err }()
	ping := muxAwait(t, host.sent)
	id := binary.BigEndian.Uint32(ping[8:12])
	ack := receiptTestFrame(yamuxReceiptPing, yamuxReceiptACK, id, nil)
	for _, wire := range [][]byte{
		receiptTestFrame(yamuxReceiptPing, yamuxReceiptACK, id-1, nil),
		receiptTestFrame(yamuxReceiptPing, yamuxReceiptSYN, id, nil),
		receiptTestFrame(yamuxReceiptData, 0, 2, ack),
	} {
		receiptReadThrough(t, network, peer, wire, 3)
		select {
		case err := <-result:
			t.Fatal("non-receipt bytes released the gate", err)
		default:
		}
	}
	receiptReadThrough(t, network, peer, ack, 1)
	if err := muxAwait(t, result); err != nil {
		t.Fatal(err)
	}
	<-host.sent // the frame released by the first receipt
	go func() { _, err := network.Write(data); result <- err }()
	next := muxAwait(t, host.sent)
	nextID := binary.BigEndian.Uint32(next[8:12])
	if nextID == id {
		t.Fatal("receipt identifier was reused")
	}
	receiptReadThrough(t, network, peer, ack, len(ack))
	select {
	case err := <-result:
		t.Fatal("stale receipt released a later budget", err)
	default:
	}
	receiptReadThrough(t, network, peer, receiptTestFrame(yamuxReceiptPing, yamuxReceiptACK, nextID, nil), 2)
	if err := muxAwait(t, result); err != nil {
		t.Fatal(err)
	}
}

func TestYamuxReceiptCloseUnblocksUnacknowledgedWriter(t *testing.T) {
	network, host, _ := receiptTestNetwork(t)
	network.frameLimit = 1
	frame := receiptTestFrame(1, 0, 1, nil)
	_, _ = network.Write(frame)
	<-host.sent
	result := make(chan error, 1)
	go func() { _, err := network.Write(frame); result <- err }()
	<-host.sent // the PING is submitted before waiting for its ACK
	if err := network.Close(); err != nil {
		t.Fatal(err)
	}
	if err := muxAwait(t, result); !errors.Is(err, net.ErrClosed) {
		t.Fatal(err)
	}
}

func TestYamuxReceiptsRejectPartialCoalescedAndOversizedWrites(t *testing.T) {
	frame := receiptTestFrame(yamuxReceiptData, 0, 1, []byte("payload"))
	for _, p := range [][]byte{
		frame[:4],
		append(bytes.Clone(frame), frame...),
		receiptTestFrame(yamuxReceiptData, 0, 1, make([]byte, WebSocketMaxBytes+1)),
		receiptTestFrame(yamuxReceiptPing, yamuxReceiptSYN, yamuxReceiptFirstID, nil),
	} {
		network, host, _ := receiptTestNetwork(t)
		if _, err := network.Write(p); err == nil {
			t.Fatal("invalid sender framing accepted")
		}
		select {
		case sent := <-host.sent:
			t.Fatal("invalid frame reached the host", sent)
		default:
		}
	}
}

func TestYamuxReceiptsUseNativePingWithoutWriterGateDeadlock(t *testing.T) {
	local, remote := net.Pipe()
	network := newYamuxReceiptConn(local)
	client, err := newYamuxSession(network, true, 8)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	server, err := newYamuxSession(remote, false, 8)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	a, b := streamPair(t, client, server)
	payload := bytes.Repeat([]byte("receipts"), 262144)
	result := make(chan error, 4)
	for _, stream := range []Stream{a, b} {
		go func() {
			_, err := stream.Write(payload)
			result <- errors.Join(err, stream.CloseWrite())
		}()
		go func() {
			got, err := io.ReadAll(stream)
			if err == nil && !bytes.Equal(got, payload) {
				err = errors.New("lost full-duplex yamux bytes")
			}
			result <- err
		}()
	}
	for range 4 {
		if err := muxAwait(t, result); err != nil {
			t.Fatal(err)
		}
	}
	network.writeMu.Lock()
	id := network.nextID
	network.writeMu.Unlock()
	if id <= yamuxReceiptFirstID {
		t.Fatal("large transfer never used a peer receipt")
	}
}

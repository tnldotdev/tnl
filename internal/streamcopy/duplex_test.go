package streamcopy

import (
	"bytes"
	"errors"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

// Real TCP is necessary here because net.Pipe cannot half-close a connection.
func tcpPair(t *testing.T) (*net.TCPConn, *net.TCPConn) {
	t.Helper()
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	_ = listener.SetDeadline(time.Now().Add(5 * time.Second))
	client, err := net.DialTimeout("tcp4", listener.Addr().String(), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	server, err := listener.AcceptTCP()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Close() })
	for _, c := range []net.Conn{client, server} {
		if err := c.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
			t.Fatal(err)
		}
	}
	return client.(*net.TCPConn), server
}

type copyOutcome struct {
	result Result
	err    error
}

func startCopy(t *testing.T, left, right net.Conn, lr, rl func(int64)) <-chan copyOutcome {
	t.Helper()
	result := make(chan copyOutcome, 1)
	done := make(chan struct{})
	t.Cleanup(func() {
		_ = left.Close()
		_ = right.Close()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("copy workers did not finish")
		}
	})
	go func() {
		defer close(done)
		r, err := CopyObserved(left, right, lr, rl)
		result <- copyOutcome{r, err}
	}()
	return result
}

func copyResult(t *testing.T, result <-chan copyOutcome) copyOutcome {
	t.Helper()
	select {
	case r := <-result:
		return r
	case <-time.After(5 * time.Second):
		t.Fatal("copy did not finish both directions")
		return copyOutcome{}
	}
}

func TestCopyHalfCloseAndExactAccounting(t *testing.T) {
	visitor, left := tcpPair(t)
	right, publisher := tcpPair(t)
	var lr, rl atomic.Int64
	result := startCopy(t, left, right, func(n int64) { lr.Add(n) }, func(n int64) { rl.Add(n) })
	request := bytes.Repeat([]byte("request"), 12000)
	response := bytes.Repeat([]byte("reply"), 17000)
	if _, err := visitor.Write(request); err != nil {
		t.Fatal(err)
	}
	if err := visitor.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(publisher)
	if err != nil || !bytes.Equal(got, request) {
		t.Fatalf("request: %d bytes, %v", len(got), err)
	}
	// The EOF in this direction must leave the reverse direction usable.
	select {
	case r := <-result:
		t.Fatalf("copy finished before response: %+v", r)
	default:
	}
	if _, err := publisher.Write(response); err != nil {
		t.Fatal(err)
	}
	if err := publisher.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	got, err = io.ReadAll(visitor)
	if err != nil || !bytes.Equal(got, response) {
		t.Fatalf("response: %d bytes, %v", len(got), err)
	}
	r := copyResult(t, result)
	if r.err != nil || r.result != (Result{LeftToRight: 84000, RightToLeft: 85000}) || lr.Load() != 84000 || rl.Load() != 85000 {
		t.Fatalf("copy = %+v, %v; observers = %d, %d", r.result, r.err, lr.Load(), rl.Load())
	}
}

type failingConn struct {
	net.Conn          // Hide TCP ReaderFrom/WriterTo so the injected error is actually exercised.
	readErr, writeErr error
	closed            atomic.Bool
}

func (c *failingConn) Read(p []byte) (int, error) {
	if c.readErr != nil {
		return 0, c.readErr
	}
	return c.Conn.Read(p)
}
func (c *failingConn) Write(p []byte) (int, error) {
	if c.writeErr != nil {
		n, _ := c.Conn.Write(p[:min(3, len(p))])
		return n, c.writeErr
	}
	return c.Conn.Write(p)
}
func (c *failingConn) Close() error { c.closed.Store(true); return c.Conn.Close() }

func TestCopyErrorsCloseBothDirectionsAndJoinWorkers(t *testing.T) {
	for _, direction := range []string{"read", "partial write"} {
		t.Run(direction, func(t *testing.T) {
			visitor, l := tcpPair(t)
			r, publisher := tcpPair(t)
			failure := errors.New("injected copy failure")
			left, right := &failingConn{Conn: l}, &failingConn{Conn: r}
			var observed atomic.Int64
			want := int64(0)
			if direction == "read" {
				left.readErr = failure
			} else {
				right.writeErr = failure
				want = 3
			}
			result := startCopy(t, left, right, func(n int64) { observed.Add(n) }, nil)
			if direction == "partial write" {
				if _, err := visitor.Write([]byte("request")); err != nil {
					t.Fatal(err)
				}
			}
			got := copyResult(t, result)
			if !errors.Is(got.err, failure) || got.result.LeftToRight != want || got.result.RightToLeft != 0 || observed.Load() != want {
				t.Fatalf("copy = %+v, %v; observed %d", got.result, got.err, observed.Load())
			}
			if !left.closed.Load() || !right.closed.Load() {
				t.Fatal("error did not close both connections")
			}
			payload, err := io.ReadAll(publisher)
			if err != nil || int64(len(payload)) != want {
				t.Fatalf("peer received %q, %v", payload, err)
			}
		})
	}
}

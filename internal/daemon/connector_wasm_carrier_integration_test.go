package daemon

import (
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

// a transparent connector-only proxy cuts existing outer WSS carriers and
// rejects their reconnects. publisher connections never pass through it.
type wasmCarrierProxy struct {
	listener    net.Listener
	target      string
	mu          sync.Mutex
	blocked     bool
	connections map[net.Conn]net.Conn
	workers     sync.WaitGroup
}

func newWASMCarrierProxy(t *testing.T, owner *runtimeTopology, target string) *wasmCarrierProxy {
	t.Helper()
	listener := serviceRuntimeListener(t, owner)
	proxy := &wasmCarrierProxy{listener: listener, target: target, connections: make(map[net.Conn]net.Conn)}
	t.Cleanup(func() {
		_ = listener.Close()
		proxy.setBlocked(true)
		done := make(chan struct{})
		go func() { proxy.workers.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("connector carrier proxy did not join")
		}
	})
	proxy.workers.Go(func() {
		for {
			connection, err := listener.Accept()
			if err != nil {
				return
			}
			proxy.workers.Go(func() { proxy.forward(connection) })
		}
	})
	return proxy
}

func (p *wasmCarrierProxy) setBlocked(blocked bool) int {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.blocked = blocked
	if !blocked {
		return 0
	}
	closed := 0
	for incoming, outgoing := range p.connections {
		_ = incoming.Close()
		_ = outgoing.Close()
		closed++
	}
	return closed
}

func (p *wasmCarrierProxy) forward(incoming net.Conn) {
	defer incoming.Close()
	p.mu.Lock()
	blocked := p.blocked
	p.mu.Unlock()
	if blocked {
		return
	}
	outgoing, err := net.DialTimeout("tcp", p.target, time.Second)
	if err != nil {
		return
	}
	defer outgoing.Close()
	p.mu.Lock()
	if p.blocked {
		p.mu.Unlock()
		return
	}
	p.connections[incoming] = outgoing
	p.mu.Unlock()
	defer func() { p.mu.Lock(); delete(p.connections, incoming); p.mu.Unlock() }()
	done := make(chan struct{})
	go func() {
		_, _ = io.Copy(incoming, outgoing)
		_ = incoming.Close()
		_ = outgoing.Close()
		close(done)
	}()
	_, _ = io.Copy(outgoing, incoming)
	_ = incoming.Close()
	_ = outgoing.Close()
	<-done
}

func TestWASMCarrierProxyBlocksAndRestores(t *testing.T) {
	owner := newRuntimeTopology(t)
	target := startPrivateEchoTarget(t, owner)
	proxy := newWASMCarrierProxy(t, owner, target.address)
	dial := func() net.Conn {
		t.Helper()
		connection, err := net.DialTimeout("tcp", proxy.listener.Addr().String(), time.Second)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = connection.Close() })
		if err := connection.SetDeadline(time.Now().Add(time.Second)); err != nil {
			t.Fatal(err)
		}
		return connection
	}
	exchange := func(connection net.Conn, message string) {
		t.Helper()
		if _, err := io.WriteString(connection, message); err != nil {
			t.Fatal(err)
		}
		got := make([]byte, len(message))
		if _, err := io.ReadFull(connection, got); err != nil || string(got) != message {
			t.Fatal("proxy exchange", err)
		}
	}
	connection := dial()
	exchange(connection, "before-cut\n")
	if proxy.setBlocked(true) != 1 {
		t.Fatal("proxy did not close the established carrier")
	}
	requireClosed := func(connection net.Conn) {
		t.Helper()
		var one [1]byte
		if _, err := connection.Read(one[:]); err == nil {
			t.Fatal("blocked carrier remained open")
		} else if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
			t.Fatal("blocked carrier did not close promptly")
		}
	}
	requireClosed(connection)
	requireClosed(dial())
	proxy.setBlocked(false)
	exchange(dial(), "after-restore\n")
}

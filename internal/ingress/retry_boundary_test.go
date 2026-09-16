package ingress

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

func TestIngressRetryBoundary(t *testing.T) {
	for _, committed := range []int{0, 1} {
		t.Run(fmt.Sprintf("visitor_bytes=%d", committed), func(t *testing.T) {
			first := newFailAfterProxyBackend(t, committed)
			fallback := newTLSBackend(t)
			_, address := startIngress(t, routeConfig(first, fallback))
			client := ingressClient(t, address, "route.example", "")
			err := client.Handshake()
			if committed != 0 {
				if err == nil {
					t.Fatal("partial ClientHello backend completed TLS")
				}
				if fallback.opens.Load() != 0 {
					t.Fatal("retried after visitor byte commit")
				}
			} else {
				if err != nil {
					t.Fatal(err)
				}
				exchangePing(t, client)
				result := ingressAwait(t, fallback.result)
				if result.err != nil || result.request != "ping" || result.visitorConnectionID != first.visitorConnectionID() {
					t.Fatalf("fallback = %+v", result)
				}
				if fallback.opens.Load() != 1 {
					t.Fatal("fallback not opened exactly once")
				}
			}
			if first.opens.Load() != 1 || !strings.HasPrefix(first.visitorConnectionID(), visitorConnectionIDPrefix) {
				t.Fatalf("first opens=%d, ID=%q", first.opens.Load(), first.visitorConnectionID())
			}
		})
	}
}

type failAfterProxyBackend struct {
	connection net.Conn
	opens      atomic.Int32
	mu         sync.Mutex
	visitorID  string
}

func newFailAfterProxyBackend(t *testing.T, visitorBytes int) *failAfterProxyBackend {
	t.Helper()
	a, b := net.Pipe()
	ownIngressConn(t, a)
	ownIngressConn(t, b)
	ingressWorker(t, func() { _ = a.Close(); _ = b.Close() }, func() error { defer b.Close(); _, _ = io.Copy(io.Discard, b); return nil })
	return &failAfterProxyBackend{connection: &failAfterProxyConn{Conn: a, visitorBytes: visitorBytes}}
}
func (b *failAfterProxyBackend) Open(_ context.Context, id string) (net.Conn, error) {
	b.opens.Add(1)
	b.mu.Lock()
	b.visitorID = id
	b.mu.Unlock()
	return b.connection, nil
}
func (b *failAfterProxyBackend) visitorConnectionID() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.visitorID
}

type failAfterProxyConn struct {
	net.Conn
	visitorBytes, writes int
}

func (c *failAfterProxyConn) Write(p []byte) (int, error) {
	c.writes++
	if c.writes == 1 {
		return c.Conn.Write(p)
	}
	return min(c.visitorBytes, len(p)), errors.New("ClientHello write failed")
}

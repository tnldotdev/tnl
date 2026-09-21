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
	"time"

	"github.com/tnldotdev/tnl/internal/routebackend"
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

type waitingBackend struct{ entered chan struct{} }

type contextBackend struct{ routebackend.Backend }

func (b contextBackend) Open(ctx context.Context, id string) (net.Conn, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return b.Backend.Open(ctx, id)
}

func (b waitingBackend) Open(ctx context.Context, _ string) (net.Conn, error) {
	if b.entered != nil {
		close(b.entered)
	}
	<-ctx.Done()
	return nil, ctx.Err()
}

func TestIngressStalledAttemptLeavesFallbackBudget(t *testing.T) {
	for _, stage := range []string{"open", "proxy_write"} {
		t.Run(stage, func(t *testing.T) {
			var first routebackend.Backend = waitingBackend{}
			if stage == "proxy_write" {
				a, b := net.Pipe()
				ownIngressConn(t, a)
				ownIngressConn(t, b)
				first = singleBackend{a} // Peer never reads the PROXY header.
			}
			fallback := newTLSBackend(t)
			config := routeConfig(first, contextBackend{fallback})
			config.OpenTimeout = 200 * time.Millisecond
			_, address := startIngress(t, config)
			client := ingressClient(t, address, "route.example", "")
			if err := client.SetDeadline(time.Now().Add(time.Second)); err != nil {
				t.Fatal(err)
			}
			if err := client.Handshake(); err != nil {
				t.Fatal(err)
			}
			exchangePing(t, client)
			if result := ingressAwait(t, fallback.result); result.err != nil {
				t.Fatal(result.err)
			}
		})
	}
}

func TestForcedDrainCancelsPendingOpen(t *testing.T) {
	entered := make(chan struct{})
	config := routeConfig(waitingBackend{entered: entered})
	config.OpenTimeout = time.Minute
	server, address := startIngress(t, config)
	client := ingressClient(t, address, "route.example", "")
	handshake := ingressWorker(t, func() { _ = client.Close() }, client.Handshake)
	ingressAwait(t, entered)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := server.Drain(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	ingressAwait(t, handshake)
	joined := make(chan struct{})
	go func() { server.active.Wait(); close(joined) }()
	select {
	case <-joined:
	case <-time.After(time.Second):
		t.Fatal("forced drain retained a pending backend open")
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

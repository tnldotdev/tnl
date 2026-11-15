package ingress

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"testing/synctest"

	"github.com/tnldotdev/tnl/internal/transport/proxyproto"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

type drainReadConn struct {
	net.Conn
	reading func()
}

func (c drainReadConn) Read(p []byte) (int, error) { c.reading(); return c.Conn.Read(p) }

type drainListener struct {
	net.Listener
	closed chan struct{}
	once   sync.Once
}

func (l *drainListener) Close() error {
	err := l.Listener.Close()
	l.once.Do(func() { close(l.closed) })
	return err
}

func TestDrainDeadlineForcesBackendClosed(t *testing.T) {
	a, b := net.Pipe()
	ownIngressConn(t, a)
	ownIngressConn(t, b)
	opened := make(chan struct{})
	capacity := make(chan func(context.Context) error, 1)
	authorized := make(chan struct{})
	backendDone := ingressWorker(t, func() { _ = a.Close(); _ = b.Close() }, func() error {
		defer b.Close()
		_, replay, err := proxyproto.Decode(b)
		if err != nil {
			return err
		}
		if err := (<-capacity)(ingressContext(t)); err != nil {
			return err
		}
		close(authorized)
		_, err = io.Copy(io.Discard, replay)
		return err
	})
	config := serviceIngressConfig(t, func(_ context.Context, _ tunnelv1.ServiceForwardingHeader, reserve func(context.Context) error) (net.Conn, error) {
		capacity <- reserve
		return &drainReadConn{Conn: a, reading: sync.OnceFunc(func() { close(opened) })}, nil
	})
	draining := make(chan struct{})
	server, address := startIngress(t, config, func(s *Server) {
		s.listener = &drainListener{Listener: s.listener, closed: draining}
	})
	client := ingressClient(t, address, "route.example", "192.0.2.4:42000")
	handshake := ingressWorker(t, func() { _ = client.Close() }, client.Handshake)
	ingressAwait(t, opened)
	// a running copy is not proof that the authorization guard reserved quota.
	// drain must begin after that reservation, or its rejection ends the stream
	// naturally and never exercises forced close.
	ingressAwait(t, authorized)
	ctx, cancel := context.WithCancelCause(t.Context())
	defer cancel(context.Canceled)
	result := ingressWorker(t, func() { cancel(context.Canceled) }, func() error { return server.Drain(ctx) })
	ingressAwait(t, draining)
	select {
	case err := <-result:
		t.Fatalf("live visitor ended before forced drain: %v", err)
	default:
	}
	cancel(context.DeadlineExceeded)
	if err := ingressAwait(t, result); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Drain: %v", err)
	}
	if err := ingressAwait(t, backendDone); err != nil {
		t.Fatal(err)
	}
	if err := ingressAwait(t, handshake); err == nil {
		t.Fatal("holding backend completed TLS")
	}
	if server.Load() != 0 || !publicServiceCapacityReleased(server) || len(server.backends) != 0 || len(server.connections) != 0 {
		t.Fatal("forced drain retained service forwarding ownership")
	}
}

func TestAdmissionRegistersBeforeDrainWait(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		// admission is entirely in memory; a real listener adds no behavior here.
		server := &Server{config: Config{MaxClientHelloConnections: 1}, connections: make(map[net.Conn]bool)}
		a, b := net.Pipe()
		ownIngressConn(t, a)
		ownIngressConn(t, b)
		if !server.admit(a) {
			t.Fatal("connection not admitted")
		}
		release := sync.OnceFunc(func() { server.finishInspection(); server.release(a); server.active.Done() })
		waited := make(chan struct{})
		t.Cleanup(func() { release(); ingressAwait(t, waited) })
		go func() { server.active.Wait(); close(waited) }()
		synctest.Wait()
		select {
		case <-waited:
			t.Fatal("wait completed before admitted handler")
		default:
		}
		release()
		ingressAwait(t, waited)
	})
}

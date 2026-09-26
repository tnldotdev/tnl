package ingress

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/tnldotdev/tnl/internal/proxyproto"
)

type singleBackend struct{ connection net.Conn }

func (b singleBackend) Open(context.Context, string) (net.Conn, error) { return b.connection, nil }

func TestDrainDeadlineForcesBackendClosed(t *testing.T) {
	a, b := net.Pipe()
	ownIngressConn(t, a)
	ownIngressConn(t, b)
	opened := make(chan struct{})
	backendDone := ingressWorker(t, func() { _ = a.Close(); _ = b.Close() }, func() error {
		defer b.Close()
		_, replay, err := proxyproto.Decode(b)
		if err != nil {
			return err
		}
		close(opened)
		_, err = io.Copy(io.Discard, replay)
		return err
	})
	server, address := startIngress(t, publicURLConfig(singleBackend{a}))
	client := ingressClient(t, address, "route.example", "")
	handshake := ingressWorker(t, func() { _ = client.Close() }, client.Handshake)
	ingressAwait(t, opened)
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
	defer cancel()
	if err := server.Drain(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Drain: %v", err)
	}
	if err := ingressAwait(t, backendDone); err != nil {
		t.Fatal(err)
	}
	if err := ingressAwait(t, handshake); err == nil {
		t.Fatal("holding backend completed TLS")
	}
}

func TestAdmissionRegistersBeforeDrainWait(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		// Admission is entirely in memory; a real listener adds no behavior here.
		server := &Server{config: Config{MaxClientHelloConnections: 1}, connections: make(map[net.Conn]struct{})}
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

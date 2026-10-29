package stream

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

func TestNativePreparationKeepsOriginalStartupDeadline(t *testing.T) {
	f := newConnectorFixture(t, "quic")
	gate := &fixtureTLSGate{entered: make(chan struct{}), release: make(chan struct{})}
	f.mu.Lock()
	f.tlsGate = gate
	f.mu.Unlock()
	defer close(gate.release)
	setup, stop := context.WithTimeout(t.Context(), 300*time.Millisecond)
	defer stop()
	done := make(chan error, 1)
	go func() {
		p, err := prepareNativeConnection(t.Context(), setup, f.config, f.device)
		if p != nil {
			p.Close()
		}
		done <- err
	}()
	select {
	case <-gate.entered:
	case err := <-done:
		t.Fatal("did not reach retained TCP preparation", err)
	case <-time.After(time.Second):
		t.Fatal("did not reach retained TCP preparation")
	}
	select {
	case err := <-done:
		if err == nil || setup.Err() == nil {
			t.Fatal("retained preparation escaped the startup deadline", err)
		}
	case <-time.After(time.Second):
		t.Fatal("retained TCP preparation reset the original startup budget")
	}
}

func TestNativePreparationPromotesStreamToOwnerLifetime(t *testing.T) {
	f := newConnectorFixture(t, "quic")
	setup, stop := context.WithTimeout(t.Context(), 3*time.Second)
	p, err := prepareNativeConnection(t.Context(), setup, f.config, f.device)
	stop()
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	local, app := net.Pipe()
	defer app.Close()
	done := make(chan error, 1)
	go func() { done <- p.Forward(t.Context(), local) }()
	_ = app.SetDeadline(time.Now().Add(time.Second))
	if _, err := io.WriteString(app, "promoted"); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len("promoted"))
	if _, err := io.ReadFull(app, got); err != nil || string(got) != "promoted" {
		t.Fatal("startup cancellation closed the promoted stream", err)
	}
	_ = app.Close()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("promoted stream did not join")
	}
}

func TestNativeRevokedOwnerDoesNotCloseSiblingOwner(t *testing.T) {
	f := newConnectorFixture(t, "quic")
	healthy := f.local(t)
	check := func(c net.Conn, message string) {
		t.Helper()
		_ = c.SetDeadline(time.Now().Add(time.Second))
		if _, err := io.WriteString(c, message); err != nil {
			t.Fatal(err)
		}
		got := make([]byte, len(message))
		if _, err := io.ReadFull(c, got); err != nil || string(got) != message {
			t.Fatal("owner lost its stream", err)
		}
	}
	check(healthy, "before")
	setup, stop := context.WithTimeout(t.Context(), 3*time.Second)
	defer stop()
	p, err := prepareNativeConnection(t.Context(), setup, f.config, f.device)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	local, revoked := net.Pipe()
	defer revoked.Close()
	done := make(chan error, 1)
	go func() { done <- p.Forward(t.Context(), local) }()
	check(revoked, "revoked")
	f.mu.Lock()
	session := f.peers[p.pair.PairId].session
	f.mu.Unlock()
	_ = session.Close()
	if _, err := revoked.Read(make([]byte, 1)); err == nil {
		t.Fatal("revoked owner retained its active stream")
	} else {
		var timeout net.Error
		if errors.As(err, &timeout) && timeout.Timeout() {
			t.Fatal("revocation only timed out the stream")
		}
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("revoked owner did not join its stream")
	}
	check(healthy, "after")
	if f.opened.Load() != 2 {
		t.Fatal("owner replacement replayed a stream", f.opened.Load())
	}
}

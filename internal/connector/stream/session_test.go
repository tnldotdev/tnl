package stream

import (
	"context"
	"io"
	"net"
	"testing"
	"time"
)

func TestPreparedSessionForwardCloseAndSiblingIsolation(t *testing.T) {
	f := newConnectorFixture(t, "tls-tcp")
	s, err := Prepare(f.ctx, f.config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	if got := s.SelectedRelayAddress(); got != f.run.PairReady.Relays[0].RelayAddress {
		t.Fatalf("initial signed slot-zero relay = %q", got)
	}
	if got := s.InnerCipherSuite(); got == 0 || got != s.connection.connection.ConnectionState().TLS.CipherSuite {
		t.Fatal("inner cipher metadata did not match the retained QUIC connection", got)
	}
	app, local := net.Pipe()
	t.Cleanup(func() { _ = app.Close() })
	done := make(chan error, 1)
	go func() { done <- s.Forward(s.Context(), local) }()
	_ = app.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := app.Write([]byte("portable")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, len("portable"))
	if _, err := io.ReadFull(app, buf); err != nil || string(buf) != "portable" {
		t.Fatalf("forwarded bytes = %q, %v", buf, err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("session close did not join forwarding")
	}
	if err := s.Close(); err != nil {
		t.Fatal("repeated close", err)
	}
	if err := s.Forward(context.Background(), local); err == nil {
		t.Fatal("closed session admitted another stream")
	}
	// the separately prepared Serve owner still carries traffic through its own
	// two paths; closing this session cannot revoke or close that sibling.
	sibling := f.local(t)
	defer sibling.Close()
	if _, err := sibling.Write([]byte("sibling")); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(sibling, make([]byte, len("sibling"))); err != nil {
		t.Fatal("closing one session stopped its sibling", err)
	}
}

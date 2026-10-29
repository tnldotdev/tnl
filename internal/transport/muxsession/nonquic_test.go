package muxsession

import (
	"context"
	"errors"
	"net"
	"os"
	"testing"
	"time"
)

func TestPeerNonQUICDeadlinesDoNotCloseQUICSocket(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	serverTLS, _ := testTLSConfigs(t)
	listener, err := ListenQUIC("127.0.0.1:0", serverTLS, QUICConfig{})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	packets := listener.NonQUICPackets(ctx)
	if err := packets.SetWriteDeadline(time.Now()); !errors.Is(err, errors.ErrUnsupported) {
		t.Fatal("child could change a shared write deadline", err)
	}
	_ = packets.SetReadDeadline(time.Now())
	var buffer [64]byte
	if _, _, err := packets.ReadFrom(buffer[:]); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatal("missing read deadline", err)
	}
	_ = packets.SetReadDeadline(time.Time{})
	_ = packets.Close()
	if _, _, err := packets.ReadFrom(buffer[:]); !errors.Is(err, net.ErrClosed) {
		t.Fatal("closed child still reading", err)
	}
	// closing a child view leaves the physical UDP port held by its owner.
	if other, err := net.ListenPacket("udp", listener.Addr().String()); err == nil {
		_ = other.Close()
		t.Fatal("child closed the physical QUIC socket")
	}
}

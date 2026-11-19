package service

import (
	"context"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

func TestConnectorTerminalAbortActiveTLSWithoutPriorStreamClose(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	target, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var workers sync.WaitGroup
	t.Cleanup(func() { _ = target.Close(); workers.Wait() })
	workers.Go(func() {
		conn, err := target.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_, _ = io.Copy(conn, conn)
	})
	_, p, verification, opening, _ := connectorPeerFixture(t, target.Addr().String())
	control := newModeledConnectorTerminal(t, p)
	client, server := connectorInnerPair(t, ctx, verification)
	raw, err := client.OpenStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	entry := opening("A")
	written := make(chan error, 1)
	go func() {
		_, err := tunnelv1.WriteConnectorPeerVisitorOpening(raw, entry, nil)
		written <- err
	}()
	remote, err := server.AcceptStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	a, err := p.reserve(ctx, remote)
	if err != nil {
		t.Fatal(err)
	}
	forwarded := make(chan error, 1)
	go func() { defer p.workers.Done(); forwarded <- a.forwardPeer() }()
	if err := <-written; err != nil {
		t.Fatal(err)
	}
	secured := connectorVisitorTLS(raw, verification, entry.VisitorConnectionID)
	if _, err := io.WriteString(secured, "active"); err != nil {
		t.Fatal(err)
	}
	echo := make([]byte, len("active"))
	if _, err := io.ReadFull(secured, echo); err != nil || string(echo) != "active" {
		t.Fatal("real publisher visitor TLS and target were not active", err)
	}
	// no connector reset, close-notify, or physical close precedes Abort.
	exchange, err := control.writer.Abort(ctx, a.terminalKey)
	joined := <-forwarded
	if failure := serviceWorkerError(joined, errConnectorAdmissionAbort); failure != nil {
		t.Fatalf("actual publisher Abort retained an independent joined cause: %v (full result: %v)", failure, joined)
	}
	if err != nil || !exchange.Matched || !exchange.ObservedWritten || exchange.Result.Outcome != tunnelv1.ConnectorTerminalAccepted {
		t.Fatal("active publisher Abort did not match its actual joined result", exchange, err)
	}
}

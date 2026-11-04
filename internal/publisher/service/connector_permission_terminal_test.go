package service

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/binary"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/transport/muxsession"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

func rawConnectorControl(t *testing.T, ctx context.Context, client muxsession.Session) muxsession.Stream {
	t.Helper()
	stream, err := client.OpenStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	until, _ := ctx.Deadline()
	_ = stream.SetDeadline(until)
	if err := tunnelv1.WriteConnectorPermissionHello(stream, false); err != nil {
		t.Fatal(err)
	}
	if err := tunnelv1.ReadConnectorPermissionHello(stream, true); err != nil {
		t.Fatal(err)
	}
	_ = stream.SetDeadline(time.Time{})
	t.Cleanup(func() { _ = stream.Reset(0) })
	return stream
}

func TestConnectorTerminalPermissionControlFencesAndJoinsHeldApplication(t *testing.T) {
	for _, mode := range []string{"eof", "reset", "truncated", "oversize"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			b, p, trust, opening, _ := connectorPeerFixture(t, permissionEchoTarget(t))
			client, server := connectorInnerPair(t, ctx, trust)
			held := &permissionHeldClose{entered: make(chan struct{}), release: make(chan struct{})}
			release := sync.OnceFunc(func() { close(held.release) })
			defer release()
			served := make(chan error, 1)
			serveReturned := make(chan struct{})
			go func() {
				served <- serveConnectorInner(ctx, p, &permissionHeldSession{Session: server, held: held})
				close(serveReturned)
			}()
			defer func() { release(); p.Close(); <-served }()
			control := rawConnectorControl(t, ctx, client)
			entry := opening("T")
			_ = openPermissionVisitor(t, ctx, client, trust, entry)
			a := permissionAdmission(t, b, p, entry.VisitorConnectionID)
			switch mode {
			case "reset":
				_ = control.Reset(0)
			case "truncated":
				_, _ = control.Write([]byte{0, 0, 0, 16, '{'})
				_ = control.CloseWrite()
			case "oversize":
				_, _ = control.Write(binary.BigEndian.AppendUint32(nil, tunnelv1.MaxConnectorPermissionBytes+1))
			default:
				_ = control.CloseWrite()
			}
			select {
			case <-held.entered:
			case <-ctx.Done():
				t.Fatal("terminal control channel did not retire its physical application")
			}
			b.mu.Lock()
			current, reserved, active := p.currentLocked(), b.reservedStreams, len(p.streams)
			b.mu.Unlock()
			if current || reserved != 1 || active != 1 {
				t.Fatal("terminal control did not fence before joined capacity release", current, reserved, active)
			}
			if _, err := p.reserve(ctx, nil); err == nil {
				t.Fatal("new admission entered a peer with a terminal control channel")
			}
			select {
			case <-serveReturned:
				t.Fatal("serve returned before physical application cleanup joined")
			default:
			}
			closed := make(chan struct{})
			go func() { p.Close(); close(closed) }()
			select {
			case <-closed:
				t.Fatal("peer close returned before its physical application joined")
			default:
			}
			release()
			select {
			case <-closed:
			case <-ctx.Done():
				t.Fatal("peer did not join after releasing physical cleanup")
			}
			select {
			case <-a.renewDone:
			default:
				t.Fatal("peer retained a permission worker after physical cleanup")
			}
			b.mu.Lock()
			defer b.mu.Unlock()
			if b.reservedStreams != 0 || b.connectorPending != 0 || len(p.streams) != 0 {
				t.Fatal("terminal control retained joined admission charges")
			}
		})
	}
}

func TestConnectorPermissionControlBoundsOverloadedVisitorWithoutBlockingSibling(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	b, p, trust, opening, _ := connectorPeerFixture(t, permissionEchoTarget(t))
	client, server := connectorInnerPair(t, ctx, trust)
	served := make(chan error, 1)
	go func() { served <- serveConnectorInner(ctx, p, server) }()
	defer func() { p.Close(); <-served }()
	control := rawConnectorControl(t, ctx, client)
	first, second := opening("P"), opening("Q")
	_ = openPermissionVisitor(t, ctx, client, trust, first)
	healthy := openPermissionVisitor(t, ctx, client, trust, second)
	a := permissionAdmission(t, b, p, first.VisitorConnectionID)
	update := signedPermissionUpdate(t, b, p, first, 2, time.Now().Add(time.Minute))
	for number := uint64(1); number <= 4; number++ {
		update.UpdateNumber = number
		if err := tunnelv1.WriteConnectorPermissionUpdate(control, update); err != nil {
			t.Fatal(err)
		}
	}
	update = signedPermissionUpdate(t, b, p, second, 1, time.Now().Add(3*time.Second))
	update.UpdateNumber = 5
	if err := tunnelv1.WriteConnectorPermissionUpdate(control, update); err != nil {
		t.Fatal(err)
	}
	_ = control.SetReadDeadline(time.Now().Add(time.Second))
	for {
		result, err := tunnelv1.ReadConnectorPermissionResult(control)
		if err != nil {
			t.Fatal("one visitor's full queue blocked sibling ACK", err)
		}
		if result.UpdateNumber == 5 {
			if result.Kind != tunnelv1.ConnectorPermissionAccepted || result.VisitorConnectionID != second.VisitorConnectionID {
				t.Fatal("sibling proof lost its own acknowledgement")
			}
			break
		}
		if result.Kind != tunnelv1.ConnectorPermissionRejected {
			t.Fatal("overloaded future revision acquired authority")
		}
	}
	if _, err := a.CheckUse(ctx); err == nil {
		t.Fatal("queue overload did not retire its exact admission")
	}
	_ = healthy.SetDeadline(time.Now().Add(time.Second))
	if _, err := healthy.Write([]byte("after")); err != nil {
		t.Fatal(err)
	}
	var data [5]byte
	if _, err := io.ReadFull(healthy, data[:]); err != nil || string(data[:]) != "after" {
		t.Fatal("queue overload stopped a sibling's raw bytes", err)
	}
}

// this test-only writer supplies a genuinely signed nonempty TLS prefix in the
// opening; all remaining handshake and application bytes use the raw stream.
type signedInitialConnectorConn struct {
	net.Conn
	entry   tunnelv1.ConnectorPeerVisitorEntry
	initial []byte
	opened  bool
}

func (c *signedInitialConnectorConn) Write(p []byte) (int, error) {
	if c.opened {
		return c.Conn.Write(p)
	}
	c.opened = true
	n := min(17, len(p))
	c.initial = append([]byte(nil), p[:n]...)
	message, err := tunnelv1.ConnectorPeerProofMessage(c.entry, c.initial)
	if err != nil {
		return 0, err
	}
	c.entry.Permission.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(ed25519.NewKeyFromSeed(bytes.Repeat([]byte{2}, 32)), message))
	if _, err := tunnelv1.WriteConnectorPeerVisitorOpening(c.Conn, c.entry, c.initial); err != nil {
		return 0, err
	}
	more, err := c.Conn.Write(p[n:])
	return n + more, err
}

func TestConnectorSignedNonemptyInitialPrefixThenRawTranscript(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	_, p, trust, opening, _ := connectorPeerFixture(t, permissionEchoTarget(t))
	client, server := connectorInnerPair(t, ctx, trust)
	served := make(chan error, 1)
	go func() { served <- serveConnectorInner(ctx, p, server) }()
	defer func() { p.Close(); <-served }()
	connectorControl(t, ctx, client)
	raw, err := client.OpenStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	prefix := &signedInitialConnectorConn{Conn: raw, entry: opening("U")}
	secured := connectorVisitorTLS(prefix, trust, prefix.entry.VisitorConnectionID)
	defer secured.Close()
	_ = secured.SetDeadline(time.Now().Add(3 * time.Second))
	want := bytes.Repeat([]byte{0x00, 0x16, 0x03, 0xff, 0x01}, (tunnelv1.MaxInitialBytes/5)+17)
	if _, err := secured.Write(want); err != nil {
		t.Fatal("signed initial TLS prefix did not reach the ordinary stream", err)
	}
	got := make([]byte, len(want))
	if _, err := io.ReadFull(secured, got); err != nil || !bytes.Equal(got, want) || len(prefix.initial) != 17 {
		t.Fatal("opening prefix or following raw transcript was lost, duplicated, or framed", err, len(prefix.initial))
	}
}

func TestConnectorInitialPrefixAndRawReadsRemainConcurrentSafe(t *testing.T) {
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	conn := &connectorOwnedConn{Conn: left, prefix: bytes.NewReader(bytes.Repeat([]byte{'A'}, 512))}
	written := make(chan error, 1)
	go func() { _, err := right.Write(bytes.Repeat([]byte{'B'}, 512)); _ = right.Close(); written <- err }()
	type result struct {
		a, b int
		err  error
	}
	results := make(chan result, 8)
	for range 8 {
		go func() {
			var got result
			var data [7]byte
			for {
				n, err := conn.Read(data[:])
				for _, b := range data[:n] {
					switch b {
					case 'A':
						got.a++
					case 'B':
						got.b++
					default:
						got.err = io.ErrUnexpectedEOF
					}
				}
				if err != nil {
					if err != io.EOF {
						got.err = err
					}
					results <- got
					return
				}
			}
		}()
	}
	var a, b int
	for range 8 {
		result := <-results
		if result.err != nil {
			t.Fatal(result.err)
		}
		a += result.a
		b += result.b
	}
	if a != 512 || b != 512 {
		t.Fatal("concurrent reads lost or duplicated initial/raw bytes", a, b)
	}
	if err := <-written; err != nil {
		t.Fatal(err)
	}
}

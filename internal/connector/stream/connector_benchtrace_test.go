//go:build tnl_benchtrace

package stream

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime/trace"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/transport/tunnel"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

func TestConnectorBenchTraceForwardPortAndCopyGoroutines(t *testing.T) {
	local, client := benchTraceTCPPair(t)
	inner, target := net.Pipe()
	t.Cleanup(func() { _ = target.Close() })
	p := &PreparedConnector{ctx: t.Context(), callbackDone: make(chan struct{})}
	connection := &benchTraceInnerConn{Conn: inner, owner: p}
	p.conn = connection
	p.stop = context.AfterFunc(p.ctx, func() { defer close(p.callbackDone); _ = p.closePhysical() })
	connectorBenchTracePrepared(p, connectorID(t, opaqueid.VisitorConnectionPrefix))
	t.Cleanup(func() { _ = p.Close() })
	echoDone := make(chan struct{})
	go func() { defer close(echoDone); _, _ = io.Copy(target, target) }()
	t.Cleanup(func() { _ = target.Close(); <-echoDone })
	done := make(chan error, 1)
	go func() { done <- p.Forward(t.Context(), local) }()
	exchange := func() {
		t.Helper()
		const payload = "private-application-payload"
		if _, err := io.WriteString(client, payload); err != nil {
			t.Fatal(err)
		}
		response := make([]byte, len(payload))
		if _, err := io.ReadFull(client, response); err != nil || string(response) != payload {
			t.Fatalf("forwarded bytes changed: %v", err)
		}
	}
	// the live session is registered while tracing is still off, just as in a
	// warmed native connector. later arming must not require another arrival.
	exchange()
	identity, ok := benchTraceIdentity(p)
	port := client.LocalAddr().(*net.TCPAddr).Port
	if !ok || identity.port != port || identity.id == 0 || trace.IsEnabled() {
		t.Fatalf("session was not registered before arming: %+v %t", identity, ok)
	}
	if allocations := testing.AllocsPerRun(100, func() {
		if connectorBenchTraceLog(p, "connector.test.off", 1, false) {
			t.Error("unarmed hook logged")
		}
	}); allocations != 0 {
		t.Fatalf("unarmed tagged event hook allocated: %g", allocations)
	}
	events := captureConnectorBenchTrace(t, func() {
		exchange()
		exchange()
		if err := p.Close(); err != nil {
			t.Fatal(err)
		}
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Fatal("Forward did not join after close")
		}
	})
	if _, ok := benchTraceIdentity(p); ok {
		t.Fatal("Forward retained its closed owner in the trace registry")
	}
	if !connection.closedAfterFence.Load() || !connection.registeredAtClose.Load() {
		t.Fatal("physical close preceded the owner close fence")
	}
	var writer, reader string
	var writes, reads int
	for _, event := range events {
		assertBenchTraceIdentity(t, event, identity)
		switch event.category {
		case "connector.stream.write.begin":
			writes++
			writer = event.goid
			if event.count != len("private-application-payload") || event.failed || !strings.Contains(event.stack, "streamcopy.CopyObserved.func1") {
				t.Fatalf("write hook was not on the actual copy worker: %+v", event)
			}
		case "connector.test.inner.write", "connector.stream.write.after-wait", "connector.stream.write.end":
			if event.goid != writer {
				t.Fatalf("write markers or the underlying write changed goroutine: %+v", event)
			}
		case "connector.stream.read.begin":
			reader = event.goid
			if !strings.Contains(event.stack, "streamcopy.CopyObserved.func1") {
				t.Fatalf("read hook was not on the actual copy worker: %+v", event)
			}
		case "connector.test.inner.read":
			reads++
			// the first armed completion can belong to a read begun before arming.
			if reader != "" && event.goid != reader {
				t.Fatalf("underlying response changed goroutine: %+v", event)
			}
		case "connector.stream.read.end":
			if reader != "" && event.goid != reader {
				t.Fatalf("response return changed goroutine: %+v", event)
			}
		case "connector.stream.permission-wait.begin", "connector.stream.permission-wait.end":
			t.Fatal("nil permission fence emitted a wait event")
		}
	}
	if writes != 2 || reads < 2 || writer == "" || reader == "" || writer == reader {
		t.Fatalf("missing distinct copy workers: writes=%d reads=%d writer=%s reader=%s", writes, reads, writer, reader)
	}
}

func TestConnectorBenchTraceUnusedPreparationRetiresIdentity(t *testing.T) {
	for _, aborted := range []bool{false, true} {
		t.Run(strconv.FormatBool(aborted), func(t *testing.T) {
			f := newConnectorFixture(t, "quic")
			connectorBenchTraces.Lock()
			before := len(connectorBenchTraces.active)
			connectorBenchTraces.Unlock()
			setup, cancel := context.WithTimeout(t.Context(), 3*time.Second)
			owner, err := prepareConnectorConnection(t.Context(), setup, f.config, f.device)
			cancel()
			if err != nil {
				t.Fatal(err)
			}
			defer owner.Close()
			p := owner.warm.prepared
			identity, ok := benchTraceIdentity(p)
			if !ok || identity.visitor != owner.warm.entry.VisitorConnectionID || identity.port != 0 || identity.id != 0 {
				t.Fatalf("preparation did not retain only its validated visitor identity: %+v", identity)
			}
			owner.mu.Lock()
			standby := make([]string, 0, len(owner.openings))
			for _, opening := range owner.openings {
				standby = append(standby, opening.entry.VisitorConnectionID)
			}
			owner.mu.Unlock()
			connectorBenchTraces.Lock()
			after := len(connectorBenchTraces.active)
			var retainedStandby bool
			for _, metadata := range connectorBenchTraces.active {
				for _, visitor := range standby {
					retainedStandby = retainedStandby || metadata.visitor == visitor
				}
			}
			connectorBenchTraces.Unlock()
			if after != before+1 || len(standby) == 0 || retainedStandby {
				t.Fatalf("raw standby openings grew the metadata registry: before=%d after=%d standby=%d retained=%t", before, after, len(standby), retainedStandby)
			}
			if aborted {
				ctx, cancel := context.WithCancel(t.Context())
				cancel()
				local, remote := net.Pipe()
				defer local.Close()
				defer remote.Close()
				if err := p.Forward(ctx, local); err == nil {
					t.Fatal("canceled arrival consumed the prepared stream")
				}
			}
			events := captureConnectorBenchTrace(t, func() {
				if connectorBenchTraceLog(p, "connector.test.unconsumed", 0, false) {
					t.Error("unconsumed preparation logged a portless identity")
				}
				owner.Close()
			})
			if _, retained := benchTraceIdentity(p); retained || len(events) != 0 {
				t.Fatalf("unused or aborted preparation retained or logged its closed owner: retained=%t events=%+v", retained, events)
			}
		})
	}
}

func TestConnectorBenchTracePermissionACKBoundaries(t *testing.T) {
	for _, mode := range []string{"continuous", "denied", "canceled"} {
		t.Run(mode, func(t *testing.T) {
			f := newConnectorFixture(t, "quic")
			setup, cancel := context.WithTimeout(t.Context(), 3*time.Second)
			owner, err := prepareConnectorConnection(t.Context(), setup, f.config, f.device)
			cancel()
			if err != nil {
				t.Fatal(err)
			}
			defer owner.Close()
			use := owner.warm
			p := use.prepared
			// this white-box writer consumes the prepared owner without Forward;
			// retain the same consumed lifetime until its explicit unregister.
			p.mu.Lock()
			p.taken = true
			p.mu.Unlock()
			connection := &benchTraceInnerConn{Conn: p.conn, owner: p}
			p.conn = connection
			local, client := benchTraceTCPPair(t)
			connectorBenchTraceRegister(p, local)
			defer connectorBenchTraceUnregister(p)
			identity, ok := benchTraceIdentity(p)
			if !ok || identity.port != client.LocalAddr().(*net.TCPAddr).Port || identity.visitor != use.entry.VisitorConnectionID {
				t.Fatal("fixture port registration failed")
			}
			type ack struct {
				update    tunnelv1.ConnectorPermissionUpdate
				responder *tunnel.ConnectorPermissionResponder
			}
			acks := make(chan ack, 2)
			f.mu.Lock()
			f.peers[owner.pair.PairId].permissionReply = func(update tunnelv1.ConnectorPermissionUpdate, responder *tunnel.ConnectorPermissionResponder) {
				acks <- ack{update, responder}
			}
			f.mu.Unlock()
			writeCtx, stopWrite := context.WithCancel(owner.ctx)
			defer stopWrite()
			selected := &benchTraceSelectContext{Context: writeCtx, entered: make(chan struct{})}
			application := &preparedConnectorUse{owner: p, ctx: selected}
			type result struct {
				n   int
				err error
			}
			written := make(chan result, 1)
			count := f.application.Load()
			nextACK := func() ack {
				t.Helper()
				select {
				case ack := <-acks:
					return ack
				case <-time.After(3 * time.Second):
					t.Fatal("renewal did not reach the real permission control stream")
					return ack{}
				}
			}
			assertBlocked := func() {
				t.Helper()
				select {
				case result := <-written:
					t.Fatalf("unacknowledged renewal released the write: %+v", result)
				default:
				}
				if f.application.Load() != count {
					t.Fatal("unacknowledged renewal forwarded application bytes")
				}
			}
			events := captureConnectorBenchTrace(t, func() {
				owner.renewActive([]*connectorUse{use}, owner.permission, time.Now().Add(time.Minute))
				first := nextACK()
				go func() {
					n, err := application.Write([]byte("private-application-payload"))
					written <- result{n, err}
				}()
				select {
				case <-selected.entered:
				case <-time.After(3 * time.Second):
					t.Fatal("writer did not enter the pending permission select")
				}
				assertBlocked()
				if mode == "canceled" {
					connectorBenchTraceLog(p, "connector.test.cancel", 0, false)
					stopWrite()
				} else {
					if mode == "continuous" {
						// queue a second update behind the first blocked ACK. the same
						// pending fence must cover both, with one begin/end pair.
						owner.renewActive([]*connectorUse{use}, owner.permission, time.Now().Add(time.Minute))
					}
					connectorBenchTraceLog(p, "connector.test.ack", 1, false)
					if err := first.responder.Respond(first.update, mode != "denied"); err != nil {
						t.Fatal(err)
					}
					if mode == "continuous" {
						second := nextACK()
						assertBlocked()
						connectorBenchTraceLog(p, "connector.test.ack", 2, false)
						if err := second.responder.Respond(second.update, true); err != nil {
							t.Fatal(err)
						}
					}
				}
				select {
				case result := <-written:
					if mode == "continuous" {
						if result.n != len("private-application-payload") || result.err != nil {
							t.Fatalf("ACK did not release its exact write: %+v", result)
						}
						response := make([]byte, result.n)
						if _, err := io.ReadFull(application, response); err != nil || string(response) != "private-application-payload" {
							t.Fatalf("acknowledged bytes changed: %v", err)
						}
					} else if result.n != 0 || result.err == nil || f.application.Load() != count {
						t.Fatalf("denial/cancellation admitted bytes: %+v count=%d", result, f.application.Load())
					}
				case <-time.After(3 * time.Second):
					t.Fatal("permission waiter did not return")
				}
				if err := p.Close(); err != nil {
					t.Fatal(err)
				}
				if n, err := application.Write([]byte("after-close")); n != 0 || err == nil {
					t.Fatal("closed owner admitted a later write")
				}
			})
			if !connection.closedAfterFence.Load() {
				t.Fatal("owner's physical close preceded its close fence")
			}
			var begin, end, lastDecision int = -1, -1, -1
			var writeGID string
			var begins, ends, innerWrites int
			for index, event := range events {
				assertBenchTraceIdentity(t, event, identity)
				switch event.category {
				case "connector.stream.permission-wait.begin":
					begins++
					begin, writeGID = index, event.goid
				case "connector.test.ack", "connector.test.cancel":
					lastDecision = index
				case "connector.stream.permission-wait.end":
					ends++
					end = index
					if event.goid != writeGID || event.failed != (mode != "continuous") {
						t.Fatalf("wait ended on the wrong worker or with the wrong result: %+v", event)
					}
				case "connector.test.inner.write", "connector.stream.write.end":
					if event.category == "connector.test.inner.write" {
						innerWrites++
					}
					if event.goid != writeGID || end < 0 || index <= end {
						t.Fatalf("inner write escaped its worker or permission fence: %+v", event)
					}
				}
			}
			if begins != 1 || ends != 1 || begin >= lastDecision || lastDecision >= end || mode != "continuous" && innerWrites != 0 || mode == "continuous" && innerWrites != 1 {
				t.Fatalf("permission boundaries do not bracket the controlled ACK wait: begin=%d end=%d decision=%d pairs=%d/%d inner=%d", begin, end, lastDecision, begins, ends, innerWrites)
			}
		})
	}
}

// Done is evaluated inside the actual pending select, after its begin marker.
// this lets the fixture release ACKs without sleeps or guessing worker timing.
type benchTraceSelectContext struct {
	context.Context
	entered chan struct{}
	once    sync.Once
}

func (c *benchTraceSelectContext) Done() <-chan struct{} {
	c.once.Do(func() { close(c.entered) })
	return c.Context.Done()
}

type benchTraceInnerConn struct {
	net.Conn
	owner             *PreparedConnector
	closedAfterFence  atomic.Bool
	registeredAtClose atomic.Bool
}

func (c *benchTraceInnerConn) Write(p []byte) (int, error) {
	connectorBenchTraceLog(c.owner, "connector.test.inner.write", len(p), false)
	return c.Conn.Write(p)
}

func (c *benchTraceInnerConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		connectorBenchTraceLog(c.owner, "connector.test.inner.read", n, err != nil)
	}
	return n, err
}

func (c *benchTraceInnerConn) Close() error {
	c.owner.mu.Lock()
	closed := c.owner.closed
	c.owner.mu.Unlock()
	c.closedAfterFence.Store(closed)
	_, registered := benchTraceIdentity(c.owner)
	c.registeredAtClose.Store(registered)
	connectorBenchTraceLog(c.owner, "connector.test.close", 0, !closed)
	return c.Conn.Close()
}

func benchTraceTCPPair(t *testing.T) (net.Conn, net.Conn) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	client, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	local, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = local.Close() })
	if err := client.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatal(err)
	}
	return local, client
}

func benchTraceIdentity(p *PreparedConnector) (connectorBenchTraceIdentity, bool) {
	connectorBenchTraces.Lock()
	defer connectorBenchTraces.Unlock()
	identity, ok := connectorBenchTraces.active[p]
	return identity, ok
}

type connectorBenchTraceEvent struct {
	goid, category, stack string
	port, count           int
	id                    uint64
	visitor               string
	failed                bool
}

func captureConnectorBenchTrace(t *testing.T, run func()) []connectorBenchTraceEvent {
	t.Helper()
	path := filepath.Join(t.TempDir(), "connector.trace")
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = file.Close() })
	if err := trace.Start(file); err != nil {
		t.Fatal(err)
	}
	func() { defer trace.Stop(); run() }()
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	output, err := exec.CommandContext(t.Context(), "go", "tool", "trace", "-d=parsed", path).CombinedOutput()
	if err != nil {
		t.Fatalf("parse real connector trace: %v\n%s", err, output)
	}
	for _, private := range []string{"private-application-payload", "signed-fixture-visitor-permission", "db.example", "127.0.0.1", "SELECT 1"} {
		if strings.Contains(string(output), private) {
			t.Fatalf("connector trace leaked private connection data: %q", private)
		}
	}
	header := regexp.MustCompile(`^M=\S+ P=\S+ G=(\d+) Log Time=\d+ Task=\d+ Category=("(?:[^"\\]|\\.)*") Message=("(?:[^"\\]|\\.)*")$`)
	lines := strings.Split(string(output), "\n")
	var events []connectorBenchTraceEvent
	for index, line := range lines {
		match := header.FindStringSubmatch(line)
		if match == nil {
			continue
		}
		category, err := strconv.Unquote(match[2])
		if err != nil {
			t.Fatal(err)
		}
		if !strings.HasPrefix(category, "connector.stream.") && !strings.HasPrefix(category, "connector.test.") {
			continue
		}
		message, err := strconv.Unquote(match[3])
		if err != nil {
			t.Fatal(err)
		}
		event := connectorBenchTraceEvent{goid: match[1], category: category}
		if n, err := fmt.Sscanf(message, "port=%d connection=%d visitor_connection_id=%s bytes=%d error=%t", &event.port, &event.id, &event.visitor, &event.count, &event.failed); err != nil || n != 5 {
			t.Fatalf("unsafe or incomplete event metadata: %q, %v", message, err)
		}
		for _, frame := range lines[index+1:] {
			if strings.HasPrefix(frame, "M=") {
				break
			}
			event.stack += frame + "\n"
		}
		events = append(events, event)
	}
	return events
}

func assertBenchTraceIdentity(t *testing.T, event connectorBenchTraceEvent, identity connectorBenchTraceIdentity) {
	t.Helper()
	if event.port != identity.port || event.id != identity.id || event.id == 0 || event.visitor != identity.visitor || !opaqueid.Valid(event.visitor, opaqueid.VisitorConnectionPrefix) {
		t.Fatalf("event lost its exact local port or opaque connection identity: %+v; want %+v", event, identity)
	}
}

type benchTraceAddressConn struct {
	net.Conn
	remote net.Addr
}

func (c benchTraceAddressConn) RemoteAddr() net.Addr { return c.remote }

func TestConnectorBenchTraceRegistryIsBoundedAndSafeIdentityOnly(t *testing.T) {
	owners := make([]*PreparedConnector, connectorBenchTraceLimit+1)
	t.Cleanup(func() {
		for _, p := range owners {
			connectorBenchTraceUnregister(p)
		}
	})
	local := benchTraceAddressConn{remote: &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 23456}}
	ids := make(map[uint64]bool)
	for index := range owners {
		owners[index] = &PreparedConnector{}
		visitor := connectorID(t, opaqueid.VisitorConnectionPrefix)
		connectorBenchTracePrepared(owners[index], visitor)
		connectorBenchTracePrepared(owners[index], "must-not-replace-the-validated-identity")
		connectorBenchTraceRegister(owners[index], local)
		identity, ok := benchTraceIdentity(owners[index])
		if index == connectorBenchTraceLimit {
			if ok {
				t.Fatal("trace metadata exceeded its active owner limit")
			}
			continue
		}
		if !ok || identity.port != 23456 || identity.id == 0 || ids[identity.id] || identity.visitor != visitor {
			t.Fatalf("invalid or reused diagnostic identity: %+v", identity)
		}
		ids[identity.id] = true
	}
	for _, p := range owners {
		connectorBenchTraceUnregister(p)
	}
	for _, remote := range []net.Addr{&net.TCPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 23456}, &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)}, &net.UnixAddr{Name: "private-path", Net: "unix"}} {
		connectorBenchTracePrepared(owners[0], connectorID(t, opaqueid.VisitorConnectionPrefix))
		connectorBenchTraceRegister(owners[0], benchTraceAddressConn{remote: remote})
		if identity, ok := benchTraceIdentity(owners[0]); !ok || identity.port != 0 || identity.id != 0 {
			t.Fatal("registry filled a port from a non-loopback, invalid, or non-TCP address")
		}
		connectorBenchTraceUnregister(owners[0])
	}
	connectorBenchTraces.Lock()
	retained := len(connectorBenchTraces.active)
	connectorBenchTraces.Unlock()
	if retained != 0 {
		t.Fatalf("registry retained %d closed owners", retained)
	}
}

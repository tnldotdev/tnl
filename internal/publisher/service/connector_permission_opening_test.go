package service

import (
	"bufio"
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/config"
	connectorstream "github.com/tnldotdev/tnl/internal/connector/stream"
	"github.com/tnldotdev/tnl/internal/publisher"
	"github.com/tnldotdev/tnl/internal/transport/muxsession"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

type permissionOpeningGate struct {
	entered, release chan struct{}
	once             sync.Once
}

func (g *permissionOpeningGate) open() { g.once.Do(func() { close(g.release) }) }

type permissionOpeningSession struct {
	muxsession.Session
	ctx            context.Context
	gate           *permissionOpeningGate
	accepted, hold int
}

func (s *permissionOpeningSession) AcceptStream(ctx context.Context) (muxsession.Stream, error) {
	stream, err := s.Session.AcceptStream(ctx)
	if err != nil {
		return nil, err
	}
	s.accepted++
	if s.accepted == s.hold {
		return &permissionOpeningStream{Stream: stream, ctx: s.ctx, gate: s.gate, closed: make(chan struct{})}, nil
	}
	return stream, nil
}

type permissionOpeningStream struct {
	muxsession.Stream
	ctx         context.Context
	gate        *permissionOpeningGate
	closed      chan struct{}
	read, close sync.Once
	err         error
}

func (s *permissionOpeningStream) Read(p []byte) (int, error) {
	s.read.Do(func() {
		close(s.gate.entered)
		select {
		case <-s.gate.release:
		case <-s.closed:
			s.err = net.ErrClosed
		case <-s.ctx.Done():
			s.err = context.Cause(s.ctx)
		}
	})
	if s.err != nil {
		return 0, s.err
	}
	return s.Stream.Read(p)
}

func (s *permissionOpeningStream) Close() error {
	s.close.Do(func() { close(s.closed) })
	return s.Stream.Close()
}

func permissionHTTPRoundTrip(t *testing.T, conn net.Conn) {
	t.Helper()
	_ = conn.SetDeadline(time.Now().Add(time.Second))
	request, _ := http.NewRequest(http.MethodGet, "https://127.0.0.1:15432/", nil)
	if err := request.Write(conn); err != nil {
		t.Fatal(err)
	}
	response, err := http.ReadResponse(bufio.NewReader(conn), request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil || string(body) != "ok" {
		t.Fatal("HTTP transcript changed across admission acknowledgement", string(body), err)
	}
	_ = conn.SetDeadline(time.Time{})
}

func permissionPreparedRun(b *Bound, trust *tls.Config, entry tunnelv1.ConnectorPeerVisitorEntry) connectorstream.Run {
	return connectorstream.Run{ServiceID: entry.ServiceID, ServiceRunID: entry.ServiceRunID, RunNumber: entry.RunNumber, Protocol: "http", TrustRevision: int64(entry.MetadataRevision), ValidUntil: time.Now().Add(time.Minute), Endpoint: &controlv1.ServiceEndpoint{Hostname: trust.ServerName, Port: int(b.prepared.servicePort)}, ServiceTLS: trust}
}

func TestConnectorNonTCPPreparationOrdersAdmissionBeforePermissionRenewal(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "ok") }))
	defer target.Close()
	b, p, trust, opening, _ := connectorPeerFixture(t, target.Listener.Addr().String())
	b.prepared.managedProtocol = config.ProtocolHTTP
	var err error
	b.prepared.serviceHTTPRequests, err = publisher.NewServiceHTTPRequestLimits(nil)
	if err != nil {
		t.Fatal(err)
	}
	client, server := connectorInnerPair(t, ctx, trust)
	gate := &permissionOpeningGate{entered: make(chan struct{}), release: make(chan struct{})}
	served := make(chan error, 1)
	go func() {
		served <- serveConnectorInner(ctx, p, &permissionOpeningSession{Session: server, ctx: ctx, gate: gate, hold: 3})
	}()
	defer func() { gate.open(); p.Close(); <-served }()
	control := rawConnectorControl(t, ctx, client)
	healthyEntry, entry := opening("M"), opening("N")
	healthyRaw, err := client.OpenStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tunnelv1.WriteConnectorPeerVisitorOpening(healthyRaw, healthyEntry, nil); err != nil {
		t.Fatal(err)
	}
	healthy := connectorVisitorTLS(healthyRaw, trust, healthyEntry.VisitorConnectionID)
	defer healthy.Close()
	permissionHTTPRoundTrip(t, healthy)
	type result struct {
		prepared *connectorstream.PreparedConnector
		err      error
	}
	prepared := make(chan result, 1)
	go func() {
		value, err := connectorstream.PrepareConnector(ctx, ctx, client, permissionPreparedRun(b, trust, entry), entry)
		prepared <- result{value, err}
	}()
	joined := false
	defer func() {
		gate.open()
		if !joined {
			value := <-prepared
			if value.prepared != nil {
				_ = value.prepared.Close()
			}
		}
	}()
	select {
	case <-gate.entered:
	case <-ctx.Done():
		t.Fatal("application opening was not held before admission")
	}
	// the first control update really precedes opening verification. a valid
	// sibling update on that same ordered control stream proves it was decoded.
	early := signedPermissionUpdate(t, b, p, entry, 2, time.Now().Add(30*time.Second))
	early.UpdateNumber = 1
	if err := tunnelv1.WriteConnectorPermissionUpdate(control, early); err != nil {
		t.Fatal(err)
	}
	sibling := signedPermissionUpdate(t, b, p, healthyEntry, 1, time.Now().Add(30*time.Second))
	sibling.UpdateNumber = 2
	if err := tunnelv1.WriteConnectorPermissionUpdate(control, sibling); err != nil {
		t.Fatal(err)
	}
	_ = control.SetReadDeadline(time.Now().Add(time.Second))
	ack, err := tunnelv1.ReadConnectorPermissionResult(control)
	if err != nil || ack.UpdateNumber != 2 || ack.VisitorConnectionID != healthyEntry.VisitorConnectionID || ack.Kind != tunnelv1.ConnectorPermissionAccepted {
		t.Fatal("unknown visitor gained authority or blocked its admitted sibling", ack, err)
	}
	permissionHTTPRoundTrip(t, healthy)
	select {
	case value := <-prepared:
		joined = true
		if value.prepared != nil {
			_ = value.prepared.Close()
		}
		t.Fatal("non-tcp preparation became renewal-eligible before publisher admission", value.err)
	default:
	}
	b.mu.Lock()
	active, pending := b.reservedStreams, b.connectorPending
	b.mu.Unlock()
	if active != 1 || pending != 1 {
		t.Fatal("held opening acquired admission through its early control proof", active, pending)
	}
	gate.open()
	var value result
	select {
	case value = <-prepared:
		joined = true
	case <-ctx.Done():
		t.Fatal("admission did not release non-tcp preparation")
	}
	if value.err != nil || value.prepared == nil {
		t.Fatal("admitted non-tcp stream failed preparation", value.err)
	}
	defer value.prepared.Close()
	a := permissionAdmission(t, b, p, entry.VisitorConnectionID)
	b.mu.Lock()
	last := a.lastUpdate
	b.mu.Unlock()
	if last != 0 {
		t.Fatal("pre-admission proof was cached and replayed into later authority", last)
	}
	current := signedPermissionUpdate(t, b, p, entry, 1, time.Now().Add(30*time.Second))
	current.UpdateNumber = 3
	if err := tunnelv1.WriteConnectorPermissionUpdate(control, current); err != nil {
		t.Fatal(err)
	}
	_ = control.SetReadDeadline(time.Now().Add(time.Second))
	ack, err = tunnelv1.ReadConnectorPermissionResult(control)
	if err != nil || ack.UpdateNumber != 3 || ack.VisitorConnectionID != entry.VisitorConnectionID || ack.Kind != tunnelv1.ConnectorPermissionAccepted {
		t.Fatal("admission lost a legitimate subsequent renewal or retained an unknown proof", ack, err)
	}
	local, app := net.Pipe()
	defer app.Close()
	forwarded := make(chan error, 1)
	go func() { forwarded <- value.prepared.Forward(ctx, local) }()
	visitor := tls.Client(app, trust)
	permissionHTTPRoundTrip(t, visitor)
	_ = visitor.Close()
	select {
	case <-forwarded:
	case <-ctx.Done():
		t.Fatal("prepared raw HTTP forwarding did not join")
	}
}

func TestConnectorNonTCPAdmissionAcceptanceKeepsOriginalSetupDeadline(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	b, p, trust, opening, _ := connectorPeerFixture(t, "127.0.0.1:1")
	client, server := connectorInnerPair(t, ctx, trust)
	gate := &permissionOpeningGate{entered: make(chan struct{}), release: make(chan struct{})}
	served := make(chan error, 1)
	go func() {
		served <- serveConnectorInner(ctx, p, &permissionOpeningSession{Session: server, ctx: ctx, gate: gate, hold: 2})
	}()
	defer func() { gate.open(); p.Close(); <-served }()
	rawConnectorControl(t, ctx, client)
	entry := opening("O")
	setup, stop := context.WithTimeout(ctx, 100*time.Millisecond)
	defer stop()
	deadline, _ := setup.Deadline()
	type result struct {
		prepared *connectorstream.PreparedConnector
		err      error
	}
	done := make(chan result, 1)
	go func() {
		value, err := connectorstream.PrepareConnector(ctx, setup, client, permissionPreparedRun(b, trust, entry), entry)
		done <- result{value, err}
	}()
	select {
	case <-gate.entered:
	case <-ctx.Done():
		t.Fatal("opening did not reach the held admission")
	}
	select {
	case value := <-done:
		if value.prepared != nil {
			_ = value.prepared.Close()
		}
		if value.prepared != nil || value.err == nil || time.Now().Before(deadline) {
			t.Fatal("opening acceptance escaped or reset the original setup budget", value.err)
		}
	case <-ctx.Done():
		t.Fatal("admission acceptance did not respect the original setup deadline")
	}
}

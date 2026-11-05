package service

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/security/visitortoken"
	"github.com/tnldotdev/tnl/internal/transport/muxsession"
	"github.com/tnldotdev/tnl/internal/transport/tunnel"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

func connectorControl(t *testing.T, ctx context.Context, client muxsession.Session) *tunnel.ConnectorPermissionWriter {
	t.Helper()
	writer, err := tunnel.OpenConnectorPermissionControl(ctx, ctx, client)
	if err != nil {
		t.Fatal("connector control handshake", err)
	}
	t.Cleanup(writer.Close)
	return writer
}

type connectorAcceptedTestConn struct {
	net.Conn
	visitor string
	once    sync.Once
	err     error
}

func (c *connectorAcceptedTestConn) Read(p []byte) (int, error) {
	c.once.Do(func() { c.err = tunnelv1.ReadConnectorPeerVisitorAccepted(c.Conn, c.visitor) })
	if c.err != nil {
		return 0, c.err
	}
	return c.Conn.Read(p)
}

func connectorVisitorTLS(conn net.Conn, trust *tls.Config, visitor string) *tls.Conn {
	return tls.Client(&connectorAcceptedTestConn{Conn: conn, visitor: visitor}, trust)
}

func permissionEchoTarget(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var workers sync.WaitGroup
	workers.Go(func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			workers.Go(func() { defer conn.Close(); _, _ = io.Copy(conn, conn) })
		}
	})
	t.Cleanup(func() { _ = listener.Close(); workers.Wait() })
	return listener.Addr().String()
}

func signedPermissionUpdate(t *testing.T, b *Bound, p *PeerSession, entry tunnelv1.ConnectorPeerVisitorEntry, revision int64, expiry time.Time) tunnelv1.ConnectorPermissionUpdate {
	t.Helper()
	view, _, _ := b.prepared.policy.Current()
	original, err := visitortoken.VerifyConnectorPeerSession(entry, nil, p.bindingSnapshot().expected(), view, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	facts := original.Facts()
	facts.VisitorPolicyRevision, facts.ExpiresAt = revision, expiry
	token, err := visitortoken.Sign(view.Issuer, "fixture", ed25519.NewKeyFromSeed(bytes.Repeat([]byte{1}, 32)), facts, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	entry.Permission.Token = token.Reveal()
	message, err := tunnelv1.ConnectorPeerProofMessage(entry, nil)
	if err != nil {
		t.Fatal(err)
	}
	entry.Permission.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(ed25519.NewKeyFromSeed(bytes.Repeat([]byte{2}, 32)), message))
	return tunnelv1.ConnectorPermissionUpdate{VisitorConnectionID: entry.VisitorConnectionID, DeliveryGeneration: entry.DeliveryGeneration, Permission: entry.Permission}
}

func permissionAdmission(t *testing.T, b *Bound, p *PeerSession, id string) *connectorAdmission {
	t.Helper()
	b.mu.Lock()
	defer b.mu.Unlock()
	for a := range p.streams {
		if a.entry.VisitorConnectionID == id && a.admitted {
			return a
		}
	}
	t.Fatal("missing live application admission")
	return nil
}

func TestConnectorPermissionStaleBindingDoesNotRenewOrCloseCurrentAdmission(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	b, p, trust, opening, _ := connectorPeerFixture(t, permissionEchoTarget(t))
	client, server := connectorInnerPair(t, ctx, trust)
	served := make(chan error, 1)
	go func() { served <- serveConnectorInner(ctx, p, server) }()
	defer func() { p.Close(); <-served }()
	control := connectorControl(t, ctx, client)
	entry := opening("S")
	traffic := openPermissionVisitor(t, ctx, client, trust, entry)
	a := permissionAdmission(t, b, p, entry.VisitorConnectionID)
	old := signedPermissionUpdate(t, b, p, entry, 1, time.Now().Add(2*time.Minute))
	before, err := a.CheckUse(ctx)
	if err != nil {
		t.Fatal(err)
	}
	// activation is covered by packet tests. isolate the permission boundary:
	// a delayed old proof arrives after the retained admission changes binding.
	b.mu.Lock()
	newSource := netip.MustParseAddr("192.0.2.2")
	err = a.guard.RebindSource(newSource, p.identity.trustRevision)
	if err == nil {
		p.network.generation++
		p.network.source = newSource
		a.entry.DeliveryGeneration, a.entry.SourceIP = p.network.generation, newSource.String()
	}
	current := a.entry
	b.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	if err := control.Renew(ctx, old); !errors.Is(err, tunnel.ErrConnectorPermissionStale) {
		t.Fatal("old binding proof was accepted or became a terminal rejection", err)
	}
	after, err := a.CheckUse(ctx)
	if err != nil || !after.Equal(before) {
		t.Fatal("stale binding proof renewed or retired the current admission", err)
	}
	message, err := tunnelv1.ConnectorPeerProofMessage(current, nil)
	if err != nil {
		t.Fatal(err)
	}
	current.Permission.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(ed25519.NewKeyFromSeed(bytes.Repeat([]byte{2}, 32)), message))
	fresh := signedPermissionUpdate(t, b, p, current, 1, time.Now().Add(2*time.Minute))
	if err := control.Renew(ctx, fresh); err != nil {
		t.Fatal("current binding could not follow a stale proof", err)
	}
	_ = traffic.SetDeadline(time.Now().Add(time.Second))
	if _, err := traffic.Write([]byte("same")); err != nil {
		t.Fatal(err)
	}
	var echoed [4]byte
	if _, err := io.ReadFull(traffic, echoed[:]); err != nil || string(echoed[:]) != "same" {
		t.Fatal("permission rebinding lost the retained application stream", err)
	}
}

func TestConnectorPermissionPendingBindingWaitsForLocalActivation(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 4*time.Second)
	defer cancel()
	b, p, trust, opening, _ := connectorPeerFixture(t, permissionEchoTarget(t))
	client, server := connectorInnerPair(t, ctx, trust)
	served := make(chan error, 1)
	go func() { served <- serveConnectorInner(ctx, p, server) }()
	defer func() { p.Close(); <-served }()
	connectorControl(t, ctx, client)
	entry := opening("W")
	_ = openPermissionVisitor(t, ctx, client, trust, entry)
	a := permissionAdmission(t, b, p, entry.VisitorConnectionID)
	pending := nextPublisherBinding(p.bindingSnapshot())
	pending.source = netip.MustParseAddr("192.0.2.2")
	entry.DeliveryGeneration, entry.SourceIP = pending.generation, pending.source.String()
	message, err := tunnelv1.ConnectorPeerProofMessage(entry, nil)
	if err != nil {
		t.Fatal(err)
	}
	entry.Permission.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(ed25519.NewKeyFromSeed(bytes.Repeat([]byte{2}, 32)), message))
	before, err := a.CheckUse(ctx)
	if err != nil {
		t.Fatal(err)
	}
	b.mu.Lock()
	p.pending, p.pendingInstalled, p.highwater, p.deliveryActive = &pending, true, pending.generation, false
	b.mu.Unlock()
	old := a.entry
	if err := a.renewPermission(old, a.permission); !errors.Is(err, tunnel.ErrConnectorPermissionStale) {
		t.Fatal("old permission renewed while its successor was pending", err)
	}
	done := make(chan error, 1)
	joined := make(chan struct{})
	go func() { defer close(joined); done <- a.renewPermission(entry, a.permission) }()
	defer func() { a.cancel(); <-joined }()
	// the authenticated new proof may arrive before this publisher sees the
	// active control observation. it must grant nothing, not retire the stream.
	timer := time.NewTimer(20 * time.Millisecond)
	defer timer.Stop()
	select {
	case err := <-done:
		t.Fatal("pending permission did not wait for local activation", err)
	case <-timer.C:
	}
	if current, err := a.CheckUse(ctx); err != nil || !current.Equal(before) {
		t.Fatal("pending permission changed its original guard deadline", err)
	}
	b.mu.Lock()
	err = a.guard.RebindSource(pending.source, p.identity.trustRevision)
	if err == nil {
		p.network, p.pending, p.deliveryActive = pending.peerNetworkBinding, nil, true
		p.network.state = controlv1.ConnectorPeerPairBindingActive
		p.lease = pending.peerLease
		a.entry = entry
	}
	b.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal("activated permission stayed fenced", err)
		}
	case <-ctx.Done():
		t.Fatal("activated proof did not finish", ctx.Err())
	}
}

func openPermissionVisitor(t *testing.T, ctx context.Context, client muxsession.Session, trust *tls.Config, entry tunnelv1.ConnectorPeerVisitorEntry) *tls.Conn {
	t.Helper()
	raw, err := client.OpenStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tunnelv1.WriteConnectorPeerVisitorOpening(raw, entry, nil); err != nil {
		t.Fatal(err)
	}
	secured := connectorVisitorTLS(raw, trust, entry.VisitorConnectionID)
	t.Cleanup(func() { _ = secured.Close() })
	_ = secured.SetDeadline(time.Now().Add(time.Second))
	if _, err := secured.Write([]byte("ready")); err != nil {
		t.Fatal(err)
	}
	var data [5]byte
	if _, err := io.ReadFull(secured, data[:]); err != nil || string(data[:]) != "ready" {
		t.Fatal("raw visitor TLS transcript changed", err)
	}
	_ = secured.SetDeadline(time.Time{})
	return secured
}

func TestConnectorPermissionControlIsolatesPolicyWaitAndInvalidProof(t *testing.T) {
	for _, boundary := range []string{"policy ahead", "visitor", "pair", "run"} {
		t.Run(boundary, func(t *testing.T) {
			invalid := boundary != "policy ahead"
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			b, p, trust, opening, _ := connectorPeerFixture(t, permissionEchoTarget(t))
			client, server := connectorInnerPair(t, ctx, trust)
			served := make(chan error, 1)
			go func() { served <- serveConnectorInner(ctx, p, server) }()
			defer func() { p.Close(); <-served }()
			control := connectorControl(t, ctx, client)
			first, second := opening("X"), opening("Y")
			_ = openPermissionVisitor(t, ctx, client, trust, first)
			healthy := openPermissionVisitor(t, ctx, client, trust, second)
			a, sibling := permissionAdmission(t, b, p, first.VisitorConnectionID), permissionAdmission(t, b, p, second.VisitorConnectionID)
			update := signedPermissionUpdate(t, b, p, first, 2, time.Now().Add(time.Minute))
			if invalid {
				// a valid proof for another visitor cannot transfer its authority.
				update = signedPermissionUpdate(t, b, p, second, 1, time.Now().Add(time.Minute))
				update.VisitorConnectionID = first.VisitorConnectionID
				if boundary != "visitor" {
					foreign := first
					if boundary == "pair" {
						foreign.PairID = "cpp_zzzzzzzzzzzzzzzzzzzzzz"
					} else {
						foreign.ServiceRunID = "srun_zzzzzzzzzzzzzzzzzzzzzz"
						foreign.RunNumber++
					}
					message, err := tunnelv1.ConnectorPeerProofMessage(foreign, nil)
					if err != nil {
						t.Fatal(err)
					}
					foreign.Permission.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(ed25519.NewKeyFromSeed(bytes.Repeat([]byte{2}, 32)), message))
					update = tunnelv1.ConnectorPermissionUpdate{VisitorConnectionID: first.VisitorConnectionID, DeliveryGeneration: first.DeliveryGeneration, Permission: foreign.Permission}
				}
			}
			pending, cancelPending := context.WithCancel(ctx)
			defer cancelPending()
			firstDone := make(chan error, 1)
			go func() { firstDone <- control.Renew(pending, update) }()
			for {
				b.mu.Lock()
				dispatched := a.lastUpdate != 0
				b.mu.Unlock()
				if dispatched {
					break
				}
				select {
				case <-ctx.Done():
					t.Fatal("first update did not reach the shared control decoder")
				case <-time.After(time.Millisecond):
				}
			}
			// unknown visitors are not retained for later admission or replay.
			unknown := update
			unknown.VisitorConnectionID = "vc_zzzzzzzzzzzzzzzzzzzzzz"
			unknownCtx, cancelUnknown := context.WithCancel(ctx)
			defer cancelUnknown()
			unknownDone := make(chan error, 1)
			go func() { unknownDone <- control.Renew(unknownCtx, unknown) }()
			until := time.Now().Add(3 * time.Second)
			renew := signedPermissionUpdate(t, b, p, second, 1, until)
			if err := control.Renew(ctx, renew); err != nil {
				t.Fatal(err)
			}
			for {
				current, err := sibling.CheckUse(ctx)
				if err != nil {
					t.Fatal("unrelated renewal lost admission", err)
				}
				if !current.After(until.Add(10 * time.Millisecond)) {
					break // the independently verified shorter token was installed.
				}
				select {
				case <-ctx.Done():
					t.Fatal("one visitor blocked another visitor's renewal")
				case <-time.After(time.Millisecond):
				}
			}
			cancelUnknown()
			if err := <-unknownDone; err == nil {
				t.Fatal("unknown visitor acquired a permission acknowledgement")
			}
			if invalid {
				if err := <-firstDone; !errors.Is(err, tunnel.ErrConnectorPermissionRejected) {
					t.Fatal("foreign proof was not rejected for its exact visitor", err)
				}
				select {
				case <-a.renewDone:
				case <-ctx.Done():
					t.Fatal("invalid renewal did not retire only its visitor")
				}
				if _, err := a.CheckUse(ctx); err == nil {
					t.Fatal("another visitor's signed proof transferred admission")
				}
			} else {
				select {
				case err := <-firstDone:
					t.Fatal("future revision did not retain its independent ACK wait", err)
				default:
				}
			}
			// duplicate updates cannot revive a stopped admission, and a delayed
			// unknown update cannot grant new admission. the sibling stays live.
			late := signedPermissionUpdate(t, b, p, first, 1, time.Now().Add(time.Minute))
			a.Stop()
			if !invalid {
				cancelPending()
				<-firstDone
			}
			for range 2 {
				call, cancel := context.WithTimeout(ctx, 30*time.Millisecond)
				err := control.Renew(call, late)
				cancel()
				if err == nil {
					t.Fatal("retired visitor acquired a late acknowledgement")
				}
			}
			if _, err := a.CheckUse(ctx); err == nil {
				t.Fatal("late update revived a stopped admission")
			}
			_ = healthy.SetDeadline(time.Now().Add(time.Second))
			if _, err := healthy.Write([]byte("after")); err != nil {
				t.Fatal(err)
			}
			var got [5]byte
			if _, err := io.ReadFull(healthy, got[:]); err != nil || string(got[:]) != "after" {
				t.Fatal("failed renewal stopped sibling application bytes", err)
			}
		})
	}
}

func TestConnectorPermissionControlKeepsAll64ApplicationAdmissions(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	b, p, trust, opening, _ := connectorPeerFixture(t, permissionEchoTarget(t))
	client, server := connectorInnerPair(t, ctx, trust)
	served := make(chan error, 1)
	go func() { served <- serveConnectorInner(ctx, p, server) }()
	defer func() { p.Close(); <-served }()
	connectorControl(t, ctx, client)
	for i := range 64 {
		entry := opening("A")
		entry.VisitorConnectionID = fmt.Sprintf("vc_%022d", i)
		message, err := tunnelv1.ConnectorPeerProofMessage(entry, nil)
		if err != nil {
			t.Fatal(err)
		}
		entry.Permission.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(ed25519.NewKeyFromSeed(bytes.Repeat([]byte{2}, 32)), message))
		_ = openPermissionVisitor(t, ctx, client, trust, entry)
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.reservedStreams != 64 || b.connectorPending != 0 || len(p.streams) != 64 {
		t.Fatal("permission control consumed application admission", b.reservedStreams, b.connectorPending, len(p.streams))
	}
}

type permissionHeldClose struct {
	muxsession.Stream
	entered, release chan struct{}
	once             sync.Once
}

func (s *permissionHeldClose) Close() error {
	err := s.Stream.Close()
	s.once.Do(func() { close(s.entered) })
	<-s.release
	return err
}

type permissionHeldSession struct {
	muxsession.Session
	accepted int
	held     *permissionHeldClose
}

func (s *permissionHeldSession) AcceptStream(ctx context.Context) (muxsession.Stream, error) {
	stream, err := s.Session.AcceptStream(ctx)
	if err != nil {
		return nil, err
	}
	s.accepted++
	if s.accepted == 2 { // the first stream is permission control.
		s.held.Stream = stream
		return s.held, nil
	}
	return stream, nil
}

func TestConnectorPermissionControlRetainsCapacityUntilRenewalAndPhysicalCloseJoin(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	b, p, trust, opening, _ := connectorPeerFixture(t, permissionEchoTarget(t))
	client, server := connectorInnerPair(t, ctx, trust)
	held := &permissionHeldClose{entered: make(chan struct{}), release: make(chan struct{})}
	release := sync.OnceFunc(func() { close(held.release) })
	defer release()
	served := make(chan error, 1)
	go func() { served <- serveConnectorInner(ctx, p, &permissionHeldSession{Session: server, held: held}) }()
	defer func() { release(); p.Close(); <-served }()
	control := connectorControl(t, ctx, client)
	entry := opening("V")
	_ = openPermissionVisitor(t, ctx, client, trust, entry)
	a := permissionAdmission(t, b, p, entry.VisitorConnectionID)
	update := signedPermissionUpdate(t, b, p, entry, 1, time.Now().Add(time.Minute))
	update.Permission.Signature = base64.RawURLEncoding.EncodeToString(make([]byte, ed25519.SignatureSize))
	if err := control.Renew(ctx, update); !errors.Is(err, tunnel.ErrConnectorPermissionRejected) {
		t.Fatal("invalid renewal was not rejected before physical cleanup", err)
	}
	select {
	case <-held.entered:
	case <-ctx.Done():
		t.Fatal("rejected renewal did not close its physical stream")
	}
	b.mu.Lock()
	reserved, active := b.reservedStreams, len(p.streams)
	b.mu.Unlock()
	if reserved != 1 || active != 1 {
		t.Fatal("renewal released admission before its physical close joined", reserved, active)
	}
	select {
	case <-a.renewDone:
		t.Fatal("renewal worker returned before its physical close")
	default:
	}
	closed := make(chan struct{})
	go func() { p.Close(); close(closed) }()
	select {
	case <-closed:
		t.Fatal("peer close did not join its permission worker and physical IO")
	default:
	}
	release()
	select {
	case <-closed:
	case <-ctx.Done():
		t.Fatal("peer close did not join after physical IO was released")
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.reservedStreams != 0 || b.connectorPending != 0 || len(p.streams) != 0 {
		t.Fatal("joined renewal retained application capacity")
	}
}

func TestConnectorPermissionControlRenewsResponseAfterTLSCloseNotify(t *testing.T) {
	for _, rejected := range []bool{false, true} {
		t.Run(map[bool]string{false: "renewed", true: "rejected"}[rejected], func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			target, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer target.Close()
			halfClosed, release, targetDone := make(chan struct{}), make(chan struct{}), make(chan struct{})
			resume := sync.OnceFunc(func() { close(release) })
			defer resume()
			go func() {
				defer close(targetDone)
				conn, err := target.Accept()
				if err != nil {
					return
				}
				defer conn.Close()
				_, _ = io.Copy(conn, conn)
				close(halfClosed)
				<-release
				_, _ = io.WriteString(conn, "response")
			}()
			b, p, trust, opening, _ := connectorPeerFixture(t, target.Addr().String())
			client, server := connectorInnerPair(t, ctx, trust)
			served := make(chan error, 1)
			go func() { served <- serveConnectorInner(ctx, p, server) }()
			defer func() { resume(); p.Close(); <-served; _ = target.Close(); <-targetDone }()
			control := connectorControl(t, ctx, client)
			entry := opening("Z")
			secured := openPermissionVisitor(t, ctx, client, trust, entry)
			a := permissionAdmission(t, b, p, entry.VisitorConnectionID)
			if err := secured.CloseWrite(); err != nil {
				t.Fatal(err)
			}
			select {
			case <-halfClosed:
			case <-ctx.Done():
				t.Fatal("TLS close_notify did not preserve target half-close")
			}
			// neither an application read nor its expired deadline carries renewal.
			_ = a.stream.SetReadDeadline(time.Now().Add(-time.Second))
			until := time.Now().Add(3 * time.Second)
			update := signedPermissionUpdate(t, b, p, entry, 1, until)
			if rejected {
				update.Permission.Signature = base64.RawURLEncoding.EncodeToString(make([]byte, ed25519.SignatureSize))
			}
			if err := control.Renew(ctx, update); rejected && !errors.Is(err, tunnel.ErrConnectorPermissionRejected) || !rejected && err != nil {
				t.Fatal("TLS close_notify stopped permission writes", err)
			}
			if rejected {
				select {
				case <-a.renewDone:
				case <-ctx.Done():
					t.Fatal("response-only renewal was not checked")
				}
				_ = secured.SetReadDeadline(time.Now().Add(time.Second))
				_, err := secured.Read(make([]byte, 1))
				var timeout net.Error
				if err == nil || errors.As(err, &timeout) && timeout.Timeout() {
					t.Fatal("rejected renewal left the response direction open", err)
				}
			} else {
				for {
					current, err := a.CheckUse(ctx)
					if err != nil {
						t.Fatal("response-only permission expired", err)
					}
					if !current.After(until.Add(10 * time.Millisecond)) {
						break
					}
					select {
					case <-ctx.Done():
						t.Fatal("response-only stream stopped reading control")
					case <-time.After(time.Millisecond):
					}
				}
				resume()
				_ = secured.SetReadDeadline(time.Now().Add(time.Second))
				var response [8]byte
				if _, err := io.ReadFull(secured, response[:]); err != nil || string(response[:]) != "response" {
					t.Fatal("TLS half-close truncated the renewed response", err)
				}
			}
		})
	}
}

func TestConnectorPermissionNegotiationRejectsOldOpeningBeforeTargetResolution(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	b, p, trust, opening, _ := connectorPeerFixture(t, "127.0.0.1:1")
	resolver := &connectorDeniedResolver{target: "127.0.0.1:1"}
	b.prepared.targetResolver = resolver
	client, server := connectorInnerPair(t, ctx, trust)
	served := make(chan error, 1)
	go func() { served <- serveConnectorInner(ctx, p, server) }()
	raw, err := client.OpenStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = tunnelv1.WriteConnectorPeerVisitorOpening(raw, opening("W"), []byte("old request-framed visitor bytes"))
	select {
	case err := <-served:
		if err == nil {
			t.Fatal("old connector negotiated the current wire")
		}
	case <-ctx.Done():
		t.Fatal("mixed versions did not fail during initial negotiation")
	}
	if resolver.calls.Load() != 0 {
		t.Fatal("mixed versions reached target resolution")
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.reservedStreams != 0 || b.connectorPending != 0 || len(p.seen) != 0 {
		t.Fatal("mixed-version negotiation spent application admission")
	}
}

func TestConnectorPermissionControlReservesCreditAgainstAllApplicationBackpressure(t *testing.T) {
	for _, grown := range []bool{false, true} {
		t.Run(map[bool]string{false: "initial windows", true: "maximum windows and batched credit"}[grown], func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
			defer cancel()
			_, _, trust, _, _ := connectorPeerFixture(t, "127.0.0.1:1")
			config := tunnel.ConnectorQUICConfig()
			if grown {
				// model every permitted application window already autotuned to
				// its maximum, without a timing-dependent warm-up for 64 streams.
				// the wire, aggregate budget and stream maximum stay production-real.
				config.InitialStreamReceiveWindow = config.MaxStreamReceiveWindow
			}
			blocked := newPermissionBackpressureTrace(config.InitialStreamReceiveWindow, grown)
			config.Tracer = blocked.tracer
			client, server := connectorInnerPairWithConfig(t, ctx, trust, config)
			accepted := make(chan muxsession.Stream, 1)
			go func() {
				stream, err := tunnel.AcceptConnectorPermissionControl(ctx, server)
				if err == nil {
					accepted <- stream
				}
			}()
			control := connectorControl(t, ctx, client)
			var stream muxsession.Stream
			select {
			case stream = <-accepted:
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
			var writers sync.WaitGroup
			defer writers.Wait()
			defer client.Close()
			payload := make([]byte, config.InitialStreamReceiveWindow)
			filled := make(chan error, tunnel.MaxConnectorApplicationStreams)
			excess := make(chan error, tunnel.MaxConnectorApplicationStreams)
			if grown {
				// consume credit just below quic-go's 25% aggregate update
				// threshold before parking fresh streams. closing this warm-up
				// stream avoids its separate batched stream-credit remainder.
				warm := config.InitialConnectionReceiveWindow/4 - config.MaxStreamReceiveWindow
				raw, err := client.OpenStream(ctx)
				if err != nil {
					t.Fatal(err)
				}
				warmed := make(chan error, 1)
				writers.Go(func() {
					for left := warm; left > 0; {
						n := min(uint64(len(payload)), left)
						if _, err := raw.Write(payload[:n]); err != nil {
							warmed <- err
							return
						}
						left -= n
					}
					warmed <- raw.CloseWrite()
				})
				application, err := server.AcceptStream(ctx)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := io.CopyN(io.Discard, application, int64(warm)); err != nil {
					t.Fatal("could not establish batched aggregate-credit state", err)
				}
				if err := <-warmed; err != nil {
					t.Fatal(err)
				}
				if _, err := application.Read(payload[:1]); !errors.Is(err, io.EOF) {
					t.Fatal("warm-up stream did not finish", err)
				}
				if err := application.CloseWrite(); err != nil {
					t.Fatal(err)
				}
				if _, err := raw.Read(payload[:1]); !errors.Is(err, io.EOF) {
					t.Fatal("warm-up response direction did not finish", err)
				}
				_ = raw.Close()
				_ = application.Close()
			}
			for range tunnel.MaxConnectorApplicationStreams {
				raw, err := client.OpenStream(ctx)
				if err != nil {
					t.Fatal("control stream spent application capacity", err)
				}
				// only this first byte is needed to make the stream visible.
				if _, err := raw.Write(payload[:1]); err != nil {
					t.Fatal(err)
				}
				_, err = server.AcceptStream(ctx)
				if err != nil {
					t.Fatal(err)
				}
				writers.Go(func() {
					_, err := raw.Write(payload[1:])
					filled <- err
					_, err = raw.Write(payload[:64<<10])
					excess <- err
				})
			}
			for range tunnel.MaxConnectorApplicationStreams {
				select {
				case err := <-filled:
					if err != nil {
						t.Fatal("application could not fill its unchanged receive window", err)
					}
				case <-ctx.Done():
					t.Fatal("aggregate credit did not cover all 64 application windows")
				}
			}
			select {
			case <-blocked.allBlocked:
			case <-ctx.Done():
				blocked.mu.Lock()
				count := len(blocked.seen)
				blocked.mu.Unlock()
				t.Fatal("real QUIC did not exhaust all 64 application receive windows before renewal", count)
			}
			select {
			case err := <-excess:
				t.Fatal("unread application stream escaped its bounded receive window", err)
			default:
			}
			got := make(chan tunnelv1.ConnectorPermissionUpdate, 1)
			done := make(chan error, 1)
			go func() {
				u, err := tunnelv1.ReadConnectorPermissionUpdate(stream)
				if err == nil {
					err = tunnelv1.WriteConnectorPermissionResult(stream, tunnelv1.ConnectorPermissionResult{VisitorConnectionID: u.VisitorConnectionID, UpdateNumber: u.UpdateNumber, DeliveryGeneration: u.DeliveryGeneration, Kind: tunnelv1.ConnectorPermissionAccepted})
				}
				got <- u
				done <- err
			}()
			update := tunnelv1.ConnectorPermissionUpdate{VisitorConnectionID: "vc_aaaaaaaaaaaaaaaaaaaaaa", UpdateNumber: 1, DeliveryGeneration: 7, Permission: tunnelv1.ConnectorVisitorPermission{Token: "signed-visitor-token", PublicKey: base64.RawURLEncoding.EncodeToString(make([]byte, 32)), Signature: base64.RawURLEncoding.EncodeToString(make([]byte, 64))}}
			call, stop := context.WithTimeout(ctx, 2*time.Second)
			defer stop()
			if err := control.Renew(call, update); err != nil {
				t.Fatal("application receive windows starved control credit", err)
			}
			select {
			case u := <-got:
				if u != update || <-done != nil {
					t.Fatal("backpressure changed the independent renewal proof")
				}
			case <-call.Done():
				t.Fatal("application backpressure blocked the dedicated control stream")
			}
		})
	}
}

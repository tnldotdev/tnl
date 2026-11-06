package stream

import (
	"bytes"
	"context"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/transport/muxsession"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

func TestConnectorInterruptedRenewalReconnectsWithoutReplacingApplication(t *testing.T) {
	for _, transport := range []string{"quic", "tls-tcp"} {
		t.Run(transport, func(t *testing.T) {
			f := newConnectorFixture(t, transport)
			setup, stop := context.WithTimeout(t.Context(), 3*time.Second)
			p, err := prepareConnectorConnection(t.Context(), setup, f.config, f.device)
			stop()
			if err != nil {
				t.Fatal(err)
			}
			defer p.Close()
			inner, permissions, owner := p.connection, p.permissions, p.owner
			local, app := net.Pipe()
			defer app.Close()
			forwarded := make(chan error, 1)
			go func() { forwarded <- p.Forward(t.Context(), local) }()
			exchange := func(message string) {
				t.Helper()
				_ = app.SetDeadline(time.Now().Add(3 * time.Second))
				if _, err := io.WriteString(app, message); err != nil {
					t.Fatal(err)
				}
				got := make([]byte, len(message))
				if _, err := io.ReadFull(app, got); err != nil || string(got) != message {
					t.Fatal("interrupted renewal replaced application delivery", err)
				}
			}
			exchange("before renewal")
			opened := f.opened.Load()
			p.mu.Lock()
			old, pair := p.paths[0].leg, p.pair
			p.mu.Unlock()
			gate := &fixtureTLSGate{entered: make(chan struct{}), release: make(chan struct{})}
			resume := sync.OnceFunc(func() { close(gate.release) })
			defer resume()
			f.mu.Lock()
			f.peers[pair.PairId].renewalGate[0] = gate
			f.mu.Unlock()
			select {
			case <-gate.entered:
			case <-time.After(3 * time.Second):
				t.Fatal("renewal did not reach the reply barrier")
			}
			select {
			case <-old.session.Done():
			case <-time.After(3 * time.Second):
				t.Fatal("timed-out renewal retained its uncertain control stream")
			}
			resume()
			deadline := time.Now().Add(4 * time.Second)
			for {
				p.mu.Lock()
				repaired := p.paths[0].leg != old
				p.mu.Unlock()
				if repaired && p.endpoint.PathHealthy(0) {
					break
				}
				if p.ctx.Err() != nil || time.Now().After(deadline) {
					t.Fatal("interrupted renewal did not reconnect", context.Cause(p.ctx))
				}
				time.Sleep(time.Millisecond)
			}
			exchange("after renewal")
			if p.connection != inner || p.permissions != permissions || p.owner != owner || f.opened.Load() != opened {
				t.Fatal("renewal recovery replaced retained ownership or replayed the application")
			}
			_ = app.Close()
			select {
			case <-forwarded:
			case <-time.After(time.Second):
				t.Fatal("application forwarding did not join")
			}
		})
	}
}

func TestConnectorReconnectRetainsInnerSessionAndApplication(t *testing.T) {
	for _, transport := range []string{"quic", "tls-tcp"} {
		t.Run(transport, func(t *testing.T) {
			f := newConnectorFixture(t, transport)
			setup, stop := context.WithTimeout(t.Context(), 3*time.Second)
			p, err := prepareConnectorConnection(t.Context(), setup, f.config, f.device)
			stop()
			if err != nil {
				t.Fatal(err)
			}
			defer p.Close()
			inner, endpoint, permissions, owner := p.connection, p.endpoint, p.permissions, p.owner
			local, app := net.Pipe()
			defer app.Close()
			done := make(chan error, 1)
			go func() { done <- p.Forward(t.Context(), local) }()
			exchange := func(message string) {
				t.Helper()
				_ = app.SetDeadline(time.Now().Add(3 * time.Second))
				if _, err := io.WriteString(app, message); err != nil {
					t.Fatal(err)
				}
				got := make([]byte, len(message))
				if _, err := io.ReadFull(app, got); err != nil || string(got) != message {
					t.Fatal("application changed", err)
				}
			}
			exchange("before")
			opened := f.opened.Load()
			for _, slots := range [][]int{{0}, {1}, {0, 1}} {
				p.mu.Lock()
				old := [2]*connectorRelayLeg{p.paths[0].leg, p.paths[1].leg}
				p.mu.Unlock()
				for _, slot := range slots {
					_ = old[slot].session.Close()
				}
				until := time.Now().Add(4 * time.Second)
				for {
					p.mu.Lock()
					repaired := true
					for _, slot := range slots {
						repaired = repaired && p.paths[slot].leg != old[slot]
					}
					p.mu.Unlock()
					if repaired && p.endpoint.PathHealthy(0) && p.endpoint.PathHealthy(1) {
						break
					}
					if time.Now().After(until) {
						t.Fatal("leg not repaired", context.Cause(p.ctx))
					}
					time.Sleep(time.Millisecond)
				}
				exchange("after-repair")
				if p.connection != inner || p.endpoint != endpoint || p.permissions != permissions || p.owner != owner || f.opened.Load() != opened {
					t.Fatal("repair replaced inner ownership or target stream")
				}
			}
			_ = app.Close()
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Fatal("forwarding did not join")
			}
		})
	}
}

func TestConnectorReconnectRetainsOperationAcrossLostHelloAndActivationReplies(t *testing.T) {
	for _, transport := range []string{"quic", "tls-tcp"} {
		t.Run(transport, func(t *testing.T) {
			f := newConnectorFixture(t, transport)
			setup, stop := context.WithTimeout(t.Context(), 3*time.Second)
			p, err := prepareConnectorConnection(t.Context(), setup, f.config, f.device)
			stop()
			if err != nil {
				t.Fatal(err)
			}
			defer p.Close()
			inner, permissions, owner, opened := p.connection, p.permissions, p.owner, f.opened.Load()
			waitForRepair := func(old *connectorRelayLeg) *connectorRelayLeg {
				t.Helper()
				deadline := time.Now().Add(6 * time.Second)
				for {
					p.mu.Lock()
					current := p.paths[0].leg
					p.mu.Unlock()
					if current != old && p.endpoint.PathHealthy(0) {
						return current
					}
					if p.ctx.Err() != nil || time.Now().After(deadline) {
						t.Fatal("uncertain replies stranded retained connection", context.Cause(p.ctx))
					}
					time.Sleep(time.Millisecond)
				}
			}
			p.mu.Lock()
			old := p.paths[0].leg
			p.mu.Unlock()
			f.dropHelloReply[0].Store(true)
			f.dropActivationReply[0].Store(true)
			_ = old.session.Close()
			repaired := waitForRepair(old)
			if repaired.handoffRevision != 1 {
				t.Fatal("uncertain retry advanced revision")
			}
			f.mu.Lock()
			attempts := append([]tunnelv1.ConnectorHandoff(nil), f.handoffAttempts[0]...)
			nonces := append([][]byte(nil), f.helloNonces[0]...)
			f.mu.Unlock()
			if len(attempts) < 2 || f.dropHelloReply[0].Load() || f.dropActivationReply[0].Load() {
				t.Fatal("fixture did not lose both replies and retry activation")
			}
			for _, attempt := range attempts {
				if attempt != attempts[0] || attempt.Next() != repaired.selectedHandoff {
					t.Fatal("uncertain reply changed the planned operation")
				}
			}
			for i, nonce := range nonces {
				for _, previous := range nonces[:i] {
					if bytes.Equal(nonce, previous) {
						t.Fatal("retry reused a signed hello")
					}
				}
			}
			_ = repaired.session.Close()
			next := waitForRepair(repaired)
			if next.handoffRevision != 2 || next.selectedHandoff == repaired.selectedHandoff || p.connection != inner || p.permissions != permissions || p.owner != owner || f.opened.Load() != opened {
				t.Fatal("next failure reset the chain or replaced inner ownership")
			}
		})
	}
}

func TestConnectorReconnectCancellationAndAuthorityDeadline(t *testing.T) {
	for _, boundary := range []string{"backoff", "connect", "expiry"} {
		t.Run(boundary, func(t *testing.T) {
			f := newConnectorFixture(t, "quic")
			var armed atomic.Bool
			entered := make(chan struct{}, 2)
			connector := muxsession.QUICConnector{TLSConfig: f.config.TransportTLS, Config: muxsession.QUICConfig{Config: fixtureDatagramConfig()}}
			config := f.config
			gate := muxsession.ConnectorFunc(func(ctx context.Context, endpoint muxsession.Endpoint) (muxsession.Session, error) {
				if !armed.Load() {
					return connector.Connect(ctx, endpoint)
				}
				entered <- struct{}{}
				<-ctx.Done()
				return nil, context.Cause(ctx)
			})
			config.RelayQUIC, config.RelayTCP = gate, gate
			setup, stop := context.WithTimeout(t.Context(), 3*time.Second)
			p, err := prepareConnectorConnection(t.Context(), setup, config, f.device)
			stop()
			if err != nil {
				t.Fatal(err)
			}
			defer p.Close()
			armed.Store(true)
			p.mu.Lock()
			old := p.paths[0].leg
			if boundary == "expiry" {
				p.preparedUntil = time.Now().Add(400 * time.Millisecond)
				p.notifyLocked()
			}
			deadline := p.preparedUntil
			p.mu.Unlock()
			_ = old.session.Close()
			if boundary != "backoff" {
				select {
				case <-entered:
				case <-time.After(time.Second):
					t.Fatal("connect not reached")
				}
			}
			if boundary == "expiry" {
				select {
				case <-p.ctx.Done():
				case <-time.After(time.Second):
					t.Fatal("reconnect extended authority")
				}
				if time.Now().Before(deadline) {
					t.Fatal("fixture did not reach expiry")
				}
			}
			closed := make(chan struct{})
			go func() { p.Close(); close(closed) }()
			select {
			case <-closed:
			case <-time.After(time.Second):
				t.Fatal("reconnect did not cancel and join")
			}
			p.mu.Lock()
			replaced := p.paths[0].leg != old
			p.mu.Unlock()
			if replaced {
				t.Fatal("canceled reconnect installed carrier")
			}
		})
	}
}

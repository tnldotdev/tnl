package stream

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	quic "github.com/quic-go/quic-go"
	"github.com/tnldotdev/tnl/internal/transport/muxsession"
	"github.com/tnldotdev/tnl/internal/transport/peer"
	"github.com/tnldotdev/tnl/internal/transport/tunnel"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

type ownerStopFixture struct {
	p           *connectorConnection
	cause       error
	retirements int
	retireErr   error
}

func newOwnerStopFixture(t *testing.T) *ownerStopFixture {
	t.Helper()
	budget, finish := context.WithTimeout(t.Context(), 10*time.Second)
	life, cancel := context.WithCancelCause(budget)
	packets, cancelPackets := context.WithCancelCause(context.WithoutCancel(budget))
	cleanup := newConnectorCleanup(budget, nil)
	until := time.Now().Add(time.Minute)
	p := &connectorConnection{
		ctx: life, packetCtx: packets, packetCancel: cancelPackets, cleanup: cleanup,
		owner: "ik_aaaaaaaaaaaaaaaaaaaaaa", session: &actionExpirySession{},
		until: until, preparedUntil: until, run: Run{ValidUntil: until},
		permission: controlv1.VisitorTokenResponse{ExpiresAt: until},
	}
	p.cancel = func(cause error) { cleanup.begin(); cancel(cause) }
	f := &ownerStopFixture{p: p, cause: fmt.Errorf("maintain connector leg 1: %w", &tunnel.ProtocolError{Code: tunnelv1.Unauthenticated})}
	authority := actionExpiryRetirement(t, p)
	p.config.Control = actionExpiryControl{
		retire: func(ctx context.Context, service, pair string, body controlv1.ConnectorPeerPairRetireRequest) (controlv1.ConnectorPeerPairRetirement, error) {
			f.retirements++
			deadline, _ := ctx.Deadline()
			if ctx.Err() != nil || deadline.After(time.Now().Add(5*time.Second)) {
				t.Error("owner stop lost or extended its original retirement budget", ctx.Err(), deadline)
			}
			receipt, err := authority.Retire(ctx, service, pair, body)
			return receipt, errors.Join(err, f.retireErr)
		},
	}
	t.Cleanup(func() {
		p.cancel(context.Canceled)
		_ = p.Close(cleanup.context())
		cancelPackets(context.Canceled)
		cleanup.close()
		finish()
	})
	return f
}

func ownerStopPrepared(t *testing.T, p *connectorConnection, conn *actionExpiryConn) *PreparedConnector {
	t.Helper()
	prepared := &PreparedConnector{
		ctx: p.ctx, conn: conn, stream: streamPrepared{}, permission: permissionUsable{},
		permissionUntil: p.until, stop: func() bool { return true },
	}
	prepared.mu.Lock()
	prepared.startPermissionWorkerLocked()
	prepared.mu.Unlock()
	return prepared
}

func TestConnectorOwnerStopIdleLegDoesNotBecomeCleanup(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := newOwnerStopFixture(t)
		p := f.p
		signer, _, pair, _, _ := rebindFixture(t)
		raw := newLegRetrySession(t, p.packetCtx, pair, 0, legRetryScript{response: tunnelv1.HelloAccepted})
		leg, err := dialConnectorLeg(t.Context(), p.packetCtx, Config{
			RelayQUIC: muxsession.ConnectorFunc(func(context.Context, muxsession.Endpoint) (muxsession.Session, error) { return raw, nil }),
			RelayTCP:  muxsession.DisabledConnector{},
		}, signer, pair, [32]byte{1}, 0, nil, tunnelv1.ConnectorHandoffID{1})
		if err != nil {
			t.Fatal(err)
		}
		p.paths[0].leg = leg
		// a deferred probe keeps the real maintenance operation in its idle wait;
		// no packet path or renewal result is manufactured by this fixture.
		p.endpoint = &peer.Endpoint{}
		p.paths[0].probeAfter = time.Now().Add(time.Minute)
		changed := make(chan struct{})
		done := make(chan error, 1)
		go func() {
			disposition, err := p.maintainConnectorLeg(p.packetCtx, 0, leg, changed)
			if disposition != retirePath {
				t.Error("stopped idle leg entered another maintenance operation", disposition)
			}
			done <- err
		}()
		synctest.Wait()
		if raw.opens.Load() != 1 || context.Cause(p.ctx) != nil {
			t.Fatal("leg did not enter the live idle maintenance boundary")
		}
		p.cancel(f.cause)
		stopped := <-done
		if !errors.Is(stopped, f.cause) {
			t.Fatal("idle leg replaced its owner's exact serving result", stopped)
		}
		p.recordLegRecoveryFailure(stopped, context.Cause(p.ctx))
		p.endpoint = nil // the zero-value observation above owns no endpoint.
		if err := p.Close(p.cleanup.context()); err != nil {
			t.Error("an inherited idle leg stop became failed cleanup", err)
		}
		if context.Cause(p.ctx) != f.cause || f.retirements != 1 {
			t.Error("cleanup hid the serving failure or skipped exact retirement", context.Cause(p.ctx), f.retirements)
		}
	})
}

func TestConnectorOwnerStopIdlePreparedDoesNotBecomeCleanup(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := newOwnerStopFixture(t)
		p := f.p
		conn := &actionExpiryConn{}
		prepared := ownerStopPrepared(t, p, conn)
		p.warm = &connectorUse{prepared: prepared}
		synctest.Wait()
		p.cancel(f.cause)
		synctest.Wait()
		if err := prepared.Close(); !errors.Is(err, f.cause) {
			t.Fatal("direct prepared caller lost its owner's exact serving result", err)
		}
		if err := p.Close(p.cleanup.context()); err != nil {
			t.Error("an inherited idle permission stop became failed cleanup", err)
		}
		if conn.closes != 1 || f.retirements != 1 || context.Cause(p.ctx) != f.cause {
			t.Error("idle cleanup changed its closes, retirement, or serving result", conn.closes, f.retirements, context.Cause(p.ctx))
		}
	})
}

type ownerStopRenewal struct {
	entered chan struct{}
	release chan struct{}
	err     error
}

func (r ownerStopRenewal) Renew(context.Context, tunnelv1.ConnectorPermissionUpdate) error {
	close(r.entered)
	<-r.release
	return r.err
}

func TestConnectorOwnerStopKeepsIndependentFailures(t *testing.T) {
	for _, kind := range []string{
		"same received denial", "different received denial", "joined failure",
		"physical close", "reset", "retirement", "required worker", "entered renewal",
	} {
		t.Run(kind, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				f := newOwnerStopFixture(t)
				p := f.p
				independent := errors.New("independent owner cleanup failure")
				var required error = independent
				conn := &actionExpiryConn{}
				switch kind {
				case "physical close":
					conn.closeErr = &muxsession.QUICTransportCloseError{Err: errors.Join(f.cause, independent)}
				case "reset":
					required = &quic.StreamError{ErrorCode: 7}
					conn.closeErr = required
				}
				prepared := ownerStopPrepared(t, p, conn)
				p.warm = &connectorUse{prepared: prepared}
				synctest.Wait()
				var renewal ownerStopRenewal
				if kind == "entered renewal" {
					renewal = ownerStopRenewal{entered: make(chan struct{}), release: make(chan struct{}), err: f.cause}
					release := sync.OnceFunc(func() { close(renewal.release) })
					defer release()
					if err := prepared.queuePermission(preparedPermissionRenewal{writer: renewal, until: p.until}); err != nil {
						t.Fatal(err)
					}
					<-renewal.entered
					f.cause = renewal.err
					required = renewal.err
					p.cancel(f.cause)
					release()
				} else {
					p.cancel(f.cause)
				}
				synctest.Wait()
				switch kind {
				case "same received denial":
					required = f.cause
					p.recordLegRecoveryFailure(required, context.Cause(p.ctx))
				case "different received denial":
					required = &tunnel.ProtocolError{Code: tunnelv1.Unauthenticated}
					p.recordLegRecoveryFailure(required, context.Cause(p.ctx))
				case "joined failure":
					p.recordLegRecoveryFailure(errors.Join(f.cause, independent), context.Cause(p.ctx))
				case "retirement":
					f.retireErr = independent
				}
				releaseWorker := make(chan struct{})
				if kind == "required worker" {
					p.workers.Go(func() { <-releaseWorker; p.recordUseCleanup(independent) })
				}
				done := make(chan error, 1)
				go func() { done <- p.Close(p.cleanup.context()) }()
				synctest.Wait()
				if kind == "required worker" {
					select {
					case err := <-done:
						t.Fatal("owner cleanup returned before a required worker joined", err)
					default:
					}
					close(releaseWorker)
				}
				err := <-done
				if !errors.Is(err, required) || context.Cause(p.ctx) != f.cause || f.retirements != 1 {
					t.Fatal("owner stop hid independent work or changed retirement", required, err, f.retirements)
				}
			})
		})
	}
}

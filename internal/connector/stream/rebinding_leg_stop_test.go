package stream

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/tnldotdev/tnl/internal/transport/muxsession"
	"github.com/tnldotdev/tnl/internal/transport/peer"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

// the old leg has entered physical cleanup when its coordinator starts rebinding.
// no replacement dial or renewal has entered; that local stop must not become a
// synthetic authority failure in the retained owner's eventual cleanup result.
func TestConnectorRebindingStopsOldReconnectBeforeReplacement(t *testing.T) {
	for _, kind := range []string{"binding stop", "binding publication", "independent close failure", "live authority expiry"} {
		t.Run(kind, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				budget, finish := context.WithTimeout(t.Context(), 5*time.Second)
				defer finish()
				p, _ := pendingRetryOwner(t, budget)
				p.rebind, p.recoveryState = nil, connectorBindingReady
				p.bindingCtx, p.bindingCancel = context.WithCancel(p.packetCtx)
				defer p.bindingCancel()
				entered, release := make(chan struct{}), make(chan struct{})
				releaseClose := sync.OnceFunc(func() { close(release) })
				defer releaseClose()
				independent := errors.New("old carrier close failed independently")
				script := legRetryScript{response: tunnelv1.HelloAccepted, closeEntered: entered, closeRelease: release}
				if kind == "independent close failure" {
					script.closeErr = independent
				}
				raw := newLegRetrySession(t, budget, p.pair, 0, script)
				var calls [2]atomic.Int32
				leg, err := dialConnectorLeg(budget, p.packetCtx,
					legRetryConfig("quic", raw, muxsession.ErrConnectorDisabled, &calls),
					p.signer, p.pair, [32]byte{1}, 0, nil, tunnelv1.ConnectorHandoffID{1})
				if err != nil {
					t.Fatal(err)
				}
				assertLegRetryHello(t, budget, raw)
				defer func() { releaseClose(); _ = leg.Close() }()
				p.paths[0] = connectorPath{leg: leg, carrier: peer.NewCarrierSlot()}
				defer p.paths[0].carrier.Close()
				var replacements atomic.Int32
				p.config.RelayQUIC = muxsession.ConnectorFunc(func(context.Context, muxsession.Endpoint) (muxsession.Session, error) {
					replacements.Add(1)
					return nil, errors.New("stopped binding started a replacement")
				})
				p.config.RelayTCP = p.config.RelayQUIC
				type result struct {
					disposition reconnectDisposition
					err         error
				}
				done := make(chan result, 1)
				go func() {
					disposition, err := p.reconnectLeg(p.bindingCtx, 0, leg)
					done <- result{disposition, err}
				}()
				<-entered
				if kind == "live authority expiry" {
					p.run.ValidUntil = time.Now().Add(-time.Second)
				} else if kind == "binding publication" {
					cancelEntered, cancelRelease, recoveryDone := make(chan struct{}), make(chan struct{}), make(chan struct{})
					releaseCancel := sync.OnceFunc(func() { close(cancelRelease) })
					stopBinding := p.bindingCancel
					p.bindingCancel = func() {
						close(cancelEntered)
						<-cancelRelease
						stopBinding()
					}
					defer func() { releaseCancel(); <-recoveryDone }()
					go func() { p.requestRecovery(connectorRebinding); close(recoveryDone) }()
					<-cancelEntered
					if p.mu.TryLock() {
						state, cause := p.recoveryState, context.Cause(p.bindingCtx)
						p.mu.Unlock()
						t.Fatal("reconnect could observe an unfinished binding transition", state, cause)
					}
					releaseCancel()
					<-recoveryDone
				} else {
					p.requestRecovery(connectorRebinding)
					if context.Cause(p.ctx) != nil || context.Cause(p.bindingCtx) != context.Canceled {
						t.Fatal("rebinding did not stop only the previous binding")
					}
				}
				until, runUntil, permissionUntil := p.until, p.run.ValidUntil, p.permission.ExpiresAt
				synctest.Wait()
				select {
				case <-done:
					t.Fatal("old reconnect returned before joining its physical close")
				default:
				}
				releaseClose()
				got := <-done
				if kind == "live authority expiry" {
					// later binding cancellation cannot erase a live guard's
					// already-returned independent authority failure.
					p.bindingCancel()
				}
				p.recordLegRecoveryFailure(got.err, context.Cause(p.bindingCtx))
				if replacements.Load() != 0 || raw.closes.Load() != 1 ||
					!p.until.Equal(until) || !p.run.ValidUntil.Equal(runUntil) || !p.permission.ExpiresAt.Equal(permissionUntil) {
					t.Fatal("binding stop changed replacement work, physical cleanup, or authority")
				}
				if kind == "live authority expiry" {
					if got.disposition != retirePath || !errors.Is(p.useErr, ErrServiceConnection) {
						t.Fatal("later cancellation hid an earlier live authority failure", got.err, p.useErr)
					}
				} else if kind == "independent close failure" {
					if got.disposition != terminateConnection || !errors.Is(p.useErr, independent) {
						t.Fatal("rebinding hid an independent physical failure", got.err, p.useErr)
					}
				} else if got.disposition != retirePath || p.useErr != nil {
					t.Fatal("coordinator's binding stop became failed owner cleanup", got.err, p.useErr)
				}
			})
		})
	}
}

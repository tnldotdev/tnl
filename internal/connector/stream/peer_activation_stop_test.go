package stream

import (
	"context"
	"errors"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

func TestConnectorActivationStopRetainsOnlyIndependentOwnerFailures(t *testing.T) {
	for _, kind := range []string{"owned stop", "independent read failure", "independent close failure", "typed canceled close"} {
		t.Run(kind, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				budget, finish := context.WithTimeout(t.Context(), 5*time.Second)
				defer finish()
				p, op := pendingRetryOwner(t, budget)
				call, stop := context.WithTimeout(p.ctx, 2*time.Second)
				defer stop()
				gate := &fixtureTLSGate{entered: make(chan struct{}), release: make(chan struct{})}
				releaseReply := sync.OnceFunc(func() { close(gate.release) })
				defer releaseReply()
				closeEntered, closeRelease := make(chan struct{}), make(chan struct{})
				releaseClose := sync.OnceFunc(func() { close(closeRelease) })
				defer releaseClose()
				independent := errors.New("activation failed independently of the owner stop")
				script := legRetryScript{response: tunnelv1.HelloAccepted, activation: true, activationGate: gate,
					closeEntered: closeEntered, closeRelease: closeRelease}
				switch kind {
				case "independent read failure":
					script.readErr = independent
				case "independent close failure":
					script.closeErr = independent
				case "typed canceled close":
					script.closeErr = &CleanupError{Err: context.Canceled}
				}
				session := newLegRetrySession(t, budget, op.pair, 0, script)
				var calls [2]atomic.Int32
				result := make(chan error, 1)
				go func() {
					leg, err := prepareConnectorLeg(call, budget, legRetryConfig("quic", session, errors.New("unused alternate"), &calls),
						p.signer, op.pair, [32]byte{1}, 0, nil, op.initial[0])
					if leg != nil {
						err = errors.Join(err, errors.New("stopped activation exposed a relay leg"), leg.Close())
					}
					result <- err
				}()
				<-gate.entered
				synctest.Wait()
				if context.Cause(call) != nil {
					t.Fatal("activation did not enter with a live call")
				}
				p.cancel(context.Canceled)
				<-closeEntered
				synctest.Wait()
				select {
				case <-result:
					t.Fatal("activation stop returned before physical cleanup joined")
				default:
				}
				releaseClose()
				err := <-result
				if !errors.Is(err, context.Canceled) || !errors.Is(err, os.ErrDeadlineExceeded) ||
					session.closes.Load() != 1 || calls[0].Load() != 1 || calls[1].Load() != 0 || len(session.activation) != 1 {
					t.Fatal("activation stop lost its physical result or changed the attempt", err)
				}
				p.recordLegRecoveryFailure(err, context.Cause(p.ctx))
				p.mu.Lock()
				retained := p.useErr
				p.mu.Unlock()
				switch kind {
				case "owned stop":
					if retained != nil {
						t.Error("an owned activation interruption became a failed owner cleanup", retained)
					}
				case "typed canceled close":
					if !errors.Is(retained, script.closeErr) {
						t.Error("activation cancellation hid typed physical cleanup", retained)
					}
				default:
					if !errors.Is(retained, independent) {
						t.Error("activation cancellation hid an independent operation or cleanup", retained)
					}
				}
			})
		})
	}
}

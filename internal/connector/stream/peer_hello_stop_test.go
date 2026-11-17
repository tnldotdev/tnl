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

	"github.com/tnldotdev/tnl/internal/transport/muxsession"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

func TestConnectorHelloStopRetainsIndependentCandidateAndCleanup(t *testing.T) {
	for _, kind := range []string{"owned hello stop", "disabled alternate", "untyped disabled alternate", "disabled with independent failure", "independent connect failure", "independent read failure", "independent close failure", "typed canceled close"} {
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
				independent := errors.New("candidate failed independently before the owner stop")
				if kind == "untyped disabled alternate" {
					independent = errors.New("transport disabled by private runtime workload")
				}
				script := legRetryScript{response: tunnelv1.HelloAccepted, helloGate: gate,
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
				config := Config{
					RelayQUIC: muxsession.ConnectorFunc(func(ctx context.Context, _ muxsession.Endpoint) (muxsession.Session, error) {
						calls[0].Add(1)
						if kind == "independent connect failure" || kind == "untyped disabled alternate" {
							return nil, independent
						}
						if kind == "disabled alternate" {
							return muxsession.DisabledConnector{}.Connect(ctx, muxsession.Endpoint{})
						}
						if kind == "disabled with independent failure" {
							return nil, errors.Join(muxsession.ErrConnectorDisabled, independent)
						}
						<-ctx.Done()
						return nil, context.Cause(ctx)
					}),
					RelayTCP: muxsession.ConnectorFunc(func(context.Context, muxsession.Endpoint) (muxsession.Session, error) {
						calls[1].Add(1)
						return session, nil
					}),
				}
				result := make(chan error, 1)
				go func() {
					leg, err := prepareConnectorLeg(call, budget, config, p.signer, op.pair, [32]byte{1}, 0, nil, op.initial[0])
					if leg != nil {
						err = errors.Join(err, errors.New("canceled hello exposed a leg"), leg.Close())
					}
					result <- err
				}()
				<-gate.entered
				synctest.Wait()
				if context.Cause(call) != nil {
					t.Fatal("hello did not enter with its original call budget")
				}
				p.cancel(context.Canceled)
				<-closeEntered
				synctest.Wait()
				select {
				case <-result:
					t.Fatal("hello returned before joining its physical close")
				default:
				}
				releaseClose()
				err := <-result
				if !errors.Is(err, context.Canceled) || !errors.Is(err, os.ErrDeadlineExceeded) ||
					session.closes.Load() != 1 || calls[0].Load() != 1 || calls[1].Load() != 1 || len(session.activation) != 0 {
					t.Fatal("hello stop lost its raw result or changed the candidate budget", err)
				}
				p.recordLegRecoveryFailure(err, context.Cause(p.ctx))
				p.mu.Lock()
				retained := p.useErr
				p.mu.Unlock()
				switch kind {
				case "owned hello stop", "disabled alternate":
					if retained != nil {
						t.Error("owned hello interruption became an independent cleanup failure", retained)
					}
				case "typed canceled close":
					if !errors.Is(retained, script.closeErr) {
						t.Error("hello stop hid typed physical cleanup", retained)
					}
				default:
					if !errors.Is(retained, independent) {
						t.Error("hello stop hid an independent candidate, read, or cleanup failure", retained)
					}
				}
			})
		})
	}
}

func TestConnectorDisabledCandidatesCannotBorrowALaterOwnerStop(t *testing.T) {
	p, _ := pendingRetryOwner(t, t.Context())
	err := &connectorLegAttemptError{context: context.Canceled, count: 2,
		candidates: [2]connectorCandidateFailure{
			{stage: connectorAttemptConnect, cause: muxsession.ErrConnectorDisabled},
			{stage: connectorAttemptConnect, cause: muxsession.ErrConnectorDisabled},
		}}
	p.cancel(context.Canceled)
	p.recordLegRecoveryFailure(err, context.Cause(p.ctx))
	if p.useErr == nil {
		t.Fatal("an all-disabled configuration borrowed a later owner's stop as operation provenance")
	}
}

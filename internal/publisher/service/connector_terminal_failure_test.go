package service

import (
	"context"
	"errors"
	"testing"
	"testing/synctest"
	"time"

	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/transport/muxsession"
	"github.com/tnldotdev/tnl/internal/transport/tunnel"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

func TestConnectorTerminalAbortAfterAdmissionStopKeepsIndependentFailure(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		b, _, a, _, control := newConnectorDeliveryAdmission(t, config.ProtocolTCP, time.Second)
		started := time.Now()
		physical := &muxsession.QUICTransportCloseError{Err: errors.New("independent physical close failure")}
		joined := errors.Join(context.Canceled, physical)
		b.mu.Lock()
		originalUntil := a.terminalBudgetLocked()
		b.mu.Unlock()
		// this fixture owns the admission join, not the terminal decision. the
		// real framed Abort must still match that stopped admission's exact key.
		joinModeledConnectorAdmission(a, joined)
		done := make(chan struct {
			exchange tunnel.ConnectorTerminalExchange
			err      error
		}, 1)
		control.calls.Go(func() {
			exchange, err := control.writer.Abort(control.ctx, a.terminalKey)
			done <- struct {
				exchange tunnel.ConnectorTerminalExchange
				err      error
			}{exchange, err}
		})
		dispatch := <-control.dispatched
		if dispatch.err != nil || dispatch.request.Key != a.terminalKey || dispatch.request.Purpose != tunnelv1.ConnectorTerminalAbort {
			t.Fatal("stopped admission lost its exact Abort binding", dispatch.request, dispatch.err)
		}
		got := <-done
		if !errors.Is(got.err, tunnel.ErrConnectorTerminalFailed) || !got.exchange.Matched || !got.exchange.ObservedWritten ||
			got.exchange.Result.TerminalRequest() != dispatch.request || got.exchange.Result.Outcome != tunnelv1.ConnectorTerminalFailed {
			t.Fatal("physical failure became rejection, success, or a missing result", got)
		}
		b.mu.Lock()
		phase := a.terminal
		until := a.terminalUntil
		outcome := a.joinedOutcome
		b.mu.Unlock()
		<-phase.done
		if !errors.Is(outcome.err, physical) || !errors.Is(outcome.err, context.Canceled) ||
			connectorAdmissionRoutineError(outcome.err) || phase.end.Cause != tunnel.ConnectorTerminalResultObserved ||
			!until.Equal(originalUntil) || !until.Equal(started.Add(time.Second)) || !time.Now().Equal(started) {
			t.Fatal("observing the failed result erased cleanup, reset authority, or spent the deadline", outcome.err, phase.end, until, time.Since(started))
		}
	})
}

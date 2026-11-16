package tunnel

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"time"

	quic "github.com/quic-go/quic-go"
	"github.com/tnldotdev/tnl/internal/transport/muxsession"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

var ErrConnectorTerminalRejected = errors.New("connector terminal request rejected")
var ErrConnectorTerminalFailed = errors.New("connector terminal request failed")
var ErrConnectorTerminalMismatch = errors.New("connector terminal binding is invalid")

type ConnectorTerminalExchange struct {
	Matched         bool
	Result          tunnelv1.ConnectorVisitorTerminalResult
	ObservedWritten bool
}

type ConnectorControlFailureOrigin uint8

const (
	ConnectorControlReaderFailure ConnectorControlFailureOrigin = iota + 1
	ConnectorControlWriterFailure
	ConnectorControlHandlerFailure
	ConnectorControlOwnerStop
)

type ConnectorControlFailure struct {
	Origin ConnectorControlFailureOrigin
	Err    error
}

func (e *ConnectorControlFailure) Error() string {
	return fmt.Sprintf("connector control (%d): %v", e.Origin, e.Err)
}
func (e *ConnectorControlFailure) Unwrap() error { return e.Err }

type ConnectorTerminalEndCause string

const (
	ConnectorTerminalResultObserved ConnectorTerminalEndCause = "result_observed"
	ConnectorTerminalPeerTerminated ConnectorTerminalEndCause = "peer_terminated"
	ConnectorTerminalOwnerRetired   ConnectorTerminalEndCause = "owner_retired"
	ConnectorTerminalLocalFailure   ConnectorTerminalEndCause = "local_failure"
	ConnectorTerminalDeadline       ConnectorTerminalEndCause = "deadline"
)

type ConnectorTerminalEnd struct {
	Cause ConnectorTerminalEndCause
	Err   error
}

type pendingConnectorTerminal struct {
	request  tunnelv1.ConnectorVisitorTerminalRequest
	ctx      context.Context
	until    time.Time
	result   chan struct{}
	decided  bool
	decision tunnelv1.ConnectorVisitorTerminalResult
}

func (w *ConnectorPermissionWriter) Complete(ctx context.Context, key tunnelv1.ConnectorVisitorTerminalKey) (ConnectorTerminalExchange, error) {
	return w.terminal(ctx, key, tunnelv1.ConnectorTerminalCompletion)
}

func (w *ConnectorPermissionWriter) Abort(ctx context.Context, key tunnelv1.ConnectorVisitorTerminalKey) (ConnectorTerminalExchange, error) {
	return w.terminal(ctx, key, tunnelv1.ConnectorTerminalAbort)
}

func (w *ConnectorPermissionWriter) terminal(ctx context.Context, key tunnelv1.ConnectorVisitorTerminalKey, purpose tunnelv1.ConnectorTerminalPurpose) (exchange ConnectorTerminalExchange, result error) {
	if ctx == nil || key.Validate() != nil {
		return exchange, ErrConnectorTerminalMismatch
	}
	if cause := context.Cause(ctx); cause != nil {
		return exchange, cause
	}
	until, ok := ctx.Deadline()
	if !ok || !until.After(time.Now()) {
		return exchange, context.DeadlineExceeded
	}
	call, finish := connectorControlCall(ctx, w.ctx)
	registered := false
	defer func() {
		finish()
		result = errors.Join(result, w.Err())
		if registered {
			w.uses.Done()
		}
	}()
	w.mu.Lock()
	if w.closed || w.ctx.Err() != nil {
		w.mu.Unlock()
		return exchange, errors.Join(ErrConnectorTerminalMismatch, w.Err())
	}
	if len(w.terminals) >= MaxConnectorApplicationStreams || w.terminalNext == math.MaxUint64 {
		w.mu.Unlock()
		return exchange, errors.New("tunnel: connector terminal capacity exhausted")
	}
	for _, pending := range w.terminals {
		if pending.request.Key.VisitorConnectionID == key.VisitorConnectionID {
			w.mu.Unlock()
			return exchange, ErrConnectorTerminalMismatch
		}
	}
	w.terminalNext++
	number := w.terminalNext
	pending := &pendingConnectorTerminal{
		request: tunnelv1.ConnectorVisitorTerminalRequest{Key: key, Purpose: purpose, TerminalNumber: number},
		ctx:     call, until: until, result: make(chan struct{}),
	}
	w.terminals[number] = pending
	w.uses.Add(1)
	registered = true
	w.mu.Unlock()
	defer func() {
		w.mu.Lock()
		if pending.decided {
			exchange.Matched, exchange.Result = true, pending.decision
		}
		delete(w.terminals, number)
		w.mu.Unlock()
	}()
	write := func(out io.Writer) error {
		if purpose == tunnelv1.ConnectorTerminalCompletion {
			return tunnelv1.WriteConnectorVisitorCompletion(out, tunnelv1.ConnectorVisitorCompletion{
				Kind: tunnelv1.ConnectorVisitorCompleted, VisitorConnectionID: key.VisitorConnectionID,
				DeliveryGeneration: key.DeliveryGeneration, TerminalNumber: number,
			})
		}
		return tunnelv1.WriteConnectorVisitorAbort(out, tunnelv1.ConnectorVisitorAbort{
			Kind: tunnelv1.ConnectorVisitorAborted, VisitorConnectionID: key.VisitorConnectionID,
			DeliveryGeneration: key.DeliveryGeneration, TerminalNumber: number,
		})
	}
	delivery := ConnectorPermissionGate{failed: func(err error) { w.fail(ConnectorControlWriterFailure, err) }}
	shared, err := delivery.write(call, w.stream, w.gate, write)
	if shared {
		w.fail(ConnectorControlWriterFailure, err)
	}
	if err != nil {
		return exchange, err
	}
	select {
	case <-pending.result:
	case <-call.Done():
		return exchange, context.Cause(call)
	}
	w.mu.Lock()
	decision := pending.decision
	w.mu.Unlock()
	var outcomeErr error
	switch decision.Outcome {
	case tunnelv1.ConnectorTerminalRejected:
		outcomeErr = ErrConnectorTerminalRejected
	case tunnelv1.ConnectorTerminalFailed:
		outcomeErr = ErrConnectorTerminalFailed
	}
	if cause := context.Cause(call); cause != nil {
		return exchange, errors.Join(outcomeErr, cause)
	}
	if !time.Now().Before(until) {
		return exchange, errors.Join(outcomeErr, context.DeadlineExceeded)
	}
	if decision.Outcome == tunnelv1.ConnectorTerminalRejected {
		return exchange, outcomeErr
	}
	observation := ConnectorPermissionGate{failed: func(err error) { w.fail(ConnectorControlWriterFailure, err) }}
	shared, err = observation.write(call, w.stream, w.gate, func(out io.Writer) error {
		return tunnelv1.WriteConnectorVisitorTerminalObserved(out, tunnelv1.ConnectorVisitorTerminalObserved{
			Kind: tunnelv1.ConnectorVisitorTerminalObservedKind, VisitorConnectionID: key.VisitorConnectionID,
			DeliveryGeneration: key.DeliveryGeneration, TerminalNumber: number, Purpose: purpose, Outcome: decision.Outcome,
		})
	})
	exchange.ObservedWritten = err == nil
	if shared {
		w.fail(ConnectorControlWriterFailure, err)
	}
	return exchange, errors.Join(outcomeErr, err, context.Cause(call))
}

// callers join the registered owner-cancellation callback before returning.
func connectorControlCall(ctx, owner context.Context) (context.Context, func()) {
	call, cancel := context.WithCancelCause(ctx)
	done := make(chan struct{})
	stop := context.AfterFunc(owner, func() { defer close(done); cancel(context.Cause(owner)) })
	return call, func() {
		cancel(context.Canceled)
		if !stop() {
			<-done
		}
	}
}

// only an already-recorded local interruption permits this classification.
// independent leaves and abnormal transport/stream errors remain failures.
func connectorControlInterrupted(err error) bool {
	if muxsession.NormalSessionCloseOnly(err) || err == context.Canceled || err == io.EOF || err == io.ErrClosedPipe {
		return true
	}
	if stream, ok := err.(*quic.StreamError); ok {
		return stream != nil && !stream.Remote && stream.ErrorCode == 0
	}
	switch err.(type) {
	case *muxsession.QUICTransportCloseError, *quic.ApplicationError, *quic.TransportError,
		*quic.IdleTimeoutError, *quic.HandshakeTimeoutError, *quic.StatelessResetError,
		*quic.VersionNegotiationError:
		return false
	}
	if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
		return false
	}
	switch err := err.(type) {
	case interface{ Unwrap() []error }:
		causes := err.Unwrap()
		if len(causes) == 0 {
			return false
		}
		for _, cause := range causes {
			if !connectorControlInterrupted(cause) {
				return false
			}
		}
		return true
	case interface{ Unwrap() error }:
		return connectorControlInterrupted(err.Unwrap())
	}
	return false
}

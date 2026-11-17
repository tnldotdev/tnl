package tunnel

import (
	"context"
	"errors"
	"io"
	"sync"
	"time"

	"github.com/tnldotdev/tnl/internal/transport/muxsession"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

type ConnectorPermissionControlHandlers interface {
	Update(tunnelv1.ConnectorPermissionUpdate, *ConnectorPermissionResponder) error
	Terminal(tunnelv1.ConnectorVisitorTerminalRequest, *ConnectorPermissionResponder) error
	Observed(tunnelv1.ConnectorVisitorTerminalObserved) error
	Failed(*ConnectorControlFailure)
}

type ConnectorPermissionResponder struct {
	ctx        context.Context
	stream     muxsession.Stream
	gate       chan struct{}
	fail       func(*ConnectorControlFailure)
	suspension *ConnectorPermissionGate
	mu         sync.Mutex
	closed     bool
	uses       sync.WaitGroup
}

func (r *ConnectorPermissionResponder) Respond(ctx context.Context, update tunnelv1.ConnectorPermissionUpdate, accepted bool) error {
	kind := tunnelv1.ConnectorPermissionRejected
	if accepted {
		kind = tunnelv1.ConnectorPermissionAccepted
	}
	return r.respond(ctx, update, kind)
}

func (r *ConnectorPermissionResponder) RespondStale(ctx context.Context, update tunnelv1.ConnectorPermissionUpdate) error {
	return r.respond(ctx, update, tunnelv1.ConnectorPermissionStale)
}

func (r *ConnectorPermissionResponder) respond(ctx context.Context, update tunnelv1.ConnectorPermissionUpdate, kind tunnelv1.StreamKind) error {
	return r.write(ctx, r.suspension, func(out io.Writer) error {
		return tunnelv1.WriteConnectorPermissionResult(out, tunnelv1.ConnectorPermissionResult{
			VisitorConnectionID: update.VisitorConnectionID, UpdateNumber: update.UpdateNumber,
			DeliveryGeneration: update.DeliveryGeneration, Kind: kind,
		})
	})
}

// the admission owner registers its immutable result before entering this write.
// actual observed dispatch may run before the framed write returns.
func (r *ConnectorPermissionResponder) Result(ctx context.Context, result tunnelv1.ConnectorVisitorTerminalResult) error {
	delivery := ConnectorPermissionGate{failed: func(err error) { r.fail(&ConnectorControlFailure{Origin: ConnectorControlWriterFailure, Err: err}) }}
	return r.write(ctx, &delivery, func(out io.Writer) error {
		return tunnelv1.WriteConnectorVisitorTerminalResult(out, result)
	})
}

func (r *ConnectorPermissionResponder) write(ctx context.Context, delivery *ConnectorPermissionGate, write func(io.Writer) error) error {
	if ctx == nil {
		return context.DeadlineExceeded
	}
	if cause := context.Cause(ctx); cause != nil {
		return cause
	}
	if until, ok := ctx.Deadline(); !ok || !until.After(time.Now()) {
		return context.DeadlineExceeded
	}
	r.mu.Lock()
	if r.closed || r.ctx.Err() != nil {
		r.mu.Unlock()
		return errors.Join(context.Canceled, context.Cause(r.ctx))
	}
	r.uses.Add(1)
	r.mu.Unlock()
	defer r.uses.Done()
	call, finish := connectorControlCall(ctx, r.ctx)
	defer finish()
	shared, err := delivery.write(call, r.stream, r.gate, write)
	if shared {
		r.fail(&ConnectorControlFailure{Origin: ConnectorControlWriterFailure, Err: err})
	}
	return err
}

type connectorTerminalRejection struct {
	request tunnelv1.ConnectorVisitorTerminalRequest
	until   time.Time
}

func ServeConnectorPermissionControl(ctx context.Context, stream muxsession.Stream, scope tunnelv1.ConnectorControlScope, handlers ConnectorPermissionControlHandlers, suspension *ConnectorPermissionGate) (result error) {
	if ctx == nil || stream == nil || handlers == nil || suspension == nil || scope.Validate() != nil {
		return errors.New("tunnel: connector control requires scope, handlers, stream, context, and suspension gate")
	}
	life, cancel := context.WithCancelCause(ctx)
	var mu sync.Mutex
	var failures error
	var firstFailure *ConnectorControlFailure
	var failureCount int
	var once sync.Once
	fail := func(err *ConnectorControlFailure) {
		mu.Lock()
		if firstFailure == nil {
			firstFailure = err
		}
		failureCount++
		failures = errors.Join(failures, err)
		mu.Unlock()
		once.Do(func() {
			// the callback fences new work before cancellation interrupts the stream.
			handlers.Failed(err)
			cancel(err)
		})
	}
	responder := &ConnectorPermissionResponder{ctx: life, stream: stream, gate: make(chan struct{}, 1), fail: fail, suspension: suspension}
	suspension.mu.Lock()
	suspension.failed = func(err error) { fail(&ConnectorControlFailure{Origin: ConnectorControlWriterFailure, Err: err}) }
	suspension.mu.Unlock()
	resetDone := make(chan struct{})
	stop := context.AfterFunc(life, func() {
		defer close(resetDone)
		responder.mu.Lock()
		responder.closed = true
		responder.mu.Unlock()
		if err := stream.Reset(0); err != nil && !connectorControlInterrupted(err) {
			fail(&ConnectorControlFailure{Origin: ConnectorControlOwnerStop, Err: err})
		}
	})
	rejections := make(chan connectorTerminalRejection, MaxConnectorApplicationStreams)
	rejectionsDone := make(chan struct{})
	go func() {
		defer close(rejectionsDone)
		for {
			select {
			case <-life.Done():
				return
			case rejection := <-rejections:
				call, finish := context.WithDeadline(life, rejection.until)
				request := rejection.request
				err := responder.Result(call, tunnelv1.ConnectorVisitorTerminalResult{
					Kind: tunnelv1.ConnectorVisitorTerminalResultKind, VisitorConnectionID: request.Key.VisitorConnectionID,
					DeliveryGeneration: request.Key.DeliveryGeneration, TerminalNumber: request.TerminalNumber,
					Purpose: request.Purpose, Outcome: tunnelv1.ConnectorTerminalRejected,
				})
				finish()
				if err != nil {
					fail(&ConnectorControlFailure{Origin: ConnectorControlWriterFailure, Err: err})
					return
				}
			}
		}
	}()
	defer func() {
		responder.mu.Lock()
		responder.closed = true
		responder.mu.Unlock()
		cancel(context.Canceled)
		if !stop() {
			<-resetDone
		}
		<-rejectionsDone
		responder.uses.Wait()
		mu.Lock()
		if failureCount != 1 || firstFailure.Err != result {
			result = errors.Join(result, failures)
		}
		mu.Unlock()
	}()
	for {
		message, err := tunnelv1.ReadConnectorControlMessage(stream)
		if err == tunnelv1.ErrConnectorPermissionUpdate {
			continue
		}
		if err != nil {
			if life.Err() != nil && connectorControlInterrupted(err) {
				return context.Cause(life)
			}
			fail(&ConnectorControlFailure{Origin: ConnectorControlReaderFailure, Err: err})
			return err
		}
		if life.Err() != nil {
			return context.Cause(life)
		}
		var terminal *tunnelv1.ConnectorVisitorTerminalRequest
		switch message := message.(type) {
		case tunnelv1.ConnectorPermissionUpdate:
			err = handlers.Update(message, responder)
		case tunnelv1.ConnectorVisitorCompletion:
			request := message.TerminalRequest()
			terminal = &request
			err = handlers.Terminal(request, responder)
		case tunnelv1.ConnectorVisitorAbort:
			request := message.TerminalRequest()
			terminal = &request
			err = handlers.Terminal(request, responder)
		case tunnelv1.ConnectorVisitorTerminalObserved:
			err = handlers.Observed(message)
		}
		if err == ErrConnectorTerminalRejected && terminal != nil {
			request := *terminal
			until := time.Now().Add(2 * time.Second)
			if bound, ok := life.Deadline(); ok {
				until = minTime(until, bound)
			}
			select {
			case rejections <- connectorTerminalRejection{request: request, until: until}:
				continue
			default:
				err = errors.New("tunnel: connector terminal rejection queue exhausted")
			}
		}
		if err != nil {
			fail(&ConnectorControlFailure{Origin: ConnectorControlHandlerFailure, Err: err})
			return err
		}
	}
}

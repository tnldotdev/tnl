package tunnel

import (
	"context"
	"errors"
	"io"
	"math"
	"sync"
	"time"

	"github.com/tnldotdev/tnl/internal/transport/muxsession"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

var ErrConnectorPermissionRejected = errors.New("connector permission renewal rejected")
var ErrConnectorPermissionStale = errors.New("connector permission binding is stale")

type pendingConnectorPermission struct {
	visitor    string
	generation int64
	result     chan error
	decided    bool
}

// ConnectorPermissionWriter owns the first inner bidirectional stream and its
// sole ACK reader. pending requests are bounded by the application allowance;
// one visitor's policy wait never owns the shared write gate.
type ConnectorPermissionWriter struct {
	stream       muxsession.Stream
	gate         chan struct{}
	ctx          context.Context
	cancel       context.CancelCauseFunc
	done         chan struct{}
	mu           sync.Mutex
	next         uint64
	closed       bool
	pending      map[uint64]*pendingConnectorPermission
	scope        tunnelv1.ConnectorControlScope
	terminalNext uint64
	terminals    map[uint64]*pendingConnectorTerminal
	err          error
	uses         sync.WaitGroup
	suspension   ConnectorPermissionGate
}

func OpenConnectorPermissionControl(lifetime, setup context.Context, session muxsession.Session, scope tunnelv1.ConnectorControlScope) (*ConnectorPermissionWriter, error) {
	if lifetime == nil || setup == nil || session == nil || scope.Validate() != nil {
		return nil, tunnelv1.ErrConnectorPermissionUpdate
	}
	if cause := context.Cause(lifetime); cause != nil {
		return nil, cause
	}
	stream, err := session.OpenStream(setup)
	if err != nil {
		return nil, err
	}
	if err := connectorPermissionHandshake(setup, stream, false); err != nil {
		_ = stream.Reset(0)
		return nil, err
	}
	ctx, cancel := context.WithCancelCause(lifetime)
	w := &ConnectorPermissionWriter{stream: stream, gate: make(chan struct{}, 1), ctx: ctx, cancel: cancel, done: make(chan struct{}), pending: make(map[uint64]*pendingConnectorPermission), scope: scope, terminals: make(map[uint64]*pendingConnectorTerminal)}
	w.suspension.failed = func(err error) { w.fail(ConnectorControlWriterFailure, err) }
	go w.receive()
	if cause := context.Cause(lifetime); cause != nil {
		return nil, errors.Join(cause, w.Close())
	}
	return w, nil
}

func (w *ConnectorPermissionWriter) Done() <-chan struct{} { return w.ctx.Done() }
func (w *ConnectorPermissionWriter) Err() error            { return context.Cause(w.ctx) }

func (w *ConnectorPermissionWriter) Suspend(until time.Time) error {
	return w.suspension.Suspend(until)
}
func (w *ConnectorPermissionWriter) Resume() error { return w.suspension.Resume() }

func (w *ConnectorPermissionWriter) Close() error {
	w.mu.Lock()
	w.closed = true
	w.cancel(context.Canceled)
	w.mu.Unlock()
	<-w.done
	w.uses.Wait()
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.err
}

func (w *ConnectorPermissionWriter) fail(origin ConnectorControlFailureOrigin, err error) {
	if err == nil {
		return
	}
	failed := &ConnectorControlFailure{Origin: origin, Err: err}
	w.mu.Lock()
	w.err = errors.Join(w.err, failed)
	w.closed = true
	w.cancel(failed)
	w.mu.Unlock()
}

func (w *ConnectorPermissionWriter) receive() {
	joined := make(chan struct{})
	stop := context.AfterFunc(w.ctx, func() {
		defer close(joined)
		if err := w.stream.Reset(0); err != nil && !connectorControlInterrupted(err) {
			w.fail(ConnectorControlOwnerStop, err)
		}
	})
	defer func() {
		if !stop() {
			<-joined
		}
		close(w.done)
	}()
	for {
		reply, err := tunnelv1.ReadConnectorControlReply(w.stream)
		if err != nil {
			if w.ctx.Err() == nil || !connectorControlInterrupted(err) {
				w.fail(ConnectorControlReaderFailure, err)
			}
			return
		}
		w.mu.Lock()
		switch result := reply.(type) {
		case tunnelv1.ConnectorVisitorTerminalResult:
			pending := w.terminals[result.TerminalNumber]
			if result.TerminalNumber > w.terminalNext || pending != nil &&
				(pending.request != result.TerminalRequest() || pending.decided && pending.decision != result) {
				w.mu.Unlock()
				w.fail(ConnectorControlReaderFailure, ErrConnectorTerminalMismatch)
				return
			}
			if pending != nil && !pending.decided && pending.ctx.Err() == nil && time.Now().Before(pending.until) {
				pending.decided, pending.decision = true, result
				close(pending.result)
			}
		case tunnelv1.ConnectorPermissionResult:
			pending := w.pending[result.UpdateNumber]
			if result.UpdateNumber > w.next || pending != nil && (pending.visitor != result.VisitorConnectionID || pending.generation != result.DeliveryGeneration) {
				w.mu.Unlock()
				w.fail(ConnectorControlReaderFailure, tunnelv1.ErrConnectorPermissionUpdate)
				return
			}
			if pending != nil && !pending.decided {
				pending.decided = true
				var decision error
				if result.Kind == tunnelv1.ConnectorPermissionRejected {
					decision = ErrConnectorPermissionRejected
				} else if result.Kind == tunnelv1.ConnectorPermissionStale {
					decision = ErrConnectorPermissionStale
				}
				pending.result <- decision
			}
		default:
			w.mu.Unlock()
			w.fail(ConnectorControlReaderFailure, tunnelv1.ErrConnectorPermissionUpdate)
			return
		}
		w.mu.Unlock()
	}
}

func (w *ConnectorPermissionWriter) Renew(ctx context.Context, update tunnelv1.ConnectorPermissionUpdate) (result error) {
	// cancellation signals share a first cause; the result must also retain an
	// independent owner failure that arrives after this visitor has stopped.
	defer func() { result = errors.Join(result, context.Cause(w.ctx)) }()
	if cause := context.Cause(ctx); cause != nil {
		return cause
	}
	until, ok := ctx.Deadline()
	if !ok || !until.After(time.Now()) {
		return context.DeadlineExceeded
	}
	w.mu.Lock()
	if w.closed || w.ctx.Err() != nil || len(w.pending) >= MaxConnectorApplicationStreams || w.next == math.MaxUint64 {
		w.mu.Unlock()
		return errors.Join(tunnelv1.ErrConnectorPermissionUpdate, context.Cause(w.ctx))
	}
	for _, pending := range w.pending {
		if pending.visitor == update.VisitorConnectionID {
			w.mu.Unlock()
			return tunnelv1.ErrConnectorPermissionUpdate
		}
	}
	w.next++
	update.UpdateNumber = w.next
	pending := &pendingConnectorPermission{visitor: update.VisitorConnectionID, generation: update.DeliveryGeneration, result: make(chan error, 1)}
	w.pending[w.next] = pending
	w.uses.Add(1)
	w.mu.Unlock()
	defer w.uses.Done()
	defer func() { w.mu.Lock(); delete(w.pending, update.UpdateNumber); w.mu.Unlock() }()
	call, cancel := context.WithCancelCause(ctx)
	stopped := make(chan struct{})
	stop := context.AfterFunc(w.ctx, func() { defer close(stopped); cancel(context.Cause(w.ctx)) })
	defer func() {
		cancel(context.Canceled)
		if !stop() {
			<-stopped
		}
	}()
	sharedFailure, err := w.suspension.write(call, w.stream, w.gate, func(w io.Writer) error {
		return tunnelv1.WriteConnectorPermissionUpdate(w, update)
	})
	if err == nil {
		sharedFailure, err = w.suspension.acknowledged(call, pending.result)
	}
	if sharedFailure {
		w.fail(ConnectorControlWriterFailure, err)
	}
	return err
}

func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}

// AcceptConnectorPermissionControl gates application admission on the same
// handshake the connector waits for. no old/new data interpretation is attempted.
func AcceptConnectorPermissionControl(ctx context.Context, session muxsession.Session) (muxsession.Stream, error) {
	stream, err := session.AcceptStream(ctx)
	if err != nil {
		return nil, err
	}
	if err := connectorPermissionHandshake(ctx, stream, true); err != nil {
		_ = stream.Reset(0)
		return nil, err
	}
	return stream, nil
}

func connectorPermissionHandshake(ctx context.Context, stream muxsession.Stream, server bool) (result error) {
	if err := context.Cause(ctx); err != nil {
		return err
	}
	until, ok := ctx.Deadline()
	if !ok || !until.After(time.Now()) {
		return context.DeadlineExceeded
	}
	if err := stream.SetDeadline(until); err != nil {
		return err
	}
	joined := make(chan struct{})
	stop := context.AfterFunc(ctx, func() { defer close(joined); _ = stream.Reset(0) })
	defer func() {
		if !stop() {
			<-joined
			result = errors.Join(result, context.Cause(ctx))
		}
	}()
	if server {
		if err := tunnelv1.ReadConnectorPermissionHello(stream, false); err != nil {
			return err
		}
		result = tunnelv1.WriteConnectorPermissionHello(stream, true)
	} else {
		if err := tunnelv1.WriteConnectorPermissionHello(stream, false); err != nil {
			return err
		}
		result = tunnelv1.ReadConnectorPermissionHello(stream, true)
	}
	if result == nil && (ctx.Err() != nil || !time.Now().Before(until)) {
		return context.DeadlineExceeded
	}
	return errors.Join(result, stream.SetDeadline(time.Time{}))
}

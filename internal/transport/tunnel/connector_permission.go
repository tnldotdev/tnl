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
	stream     muxsession.Stream
	gate       chan struct{}
	ctx        context.Context
	cancel     context.CancelCauseFunc
	done       chan struct{}
	mu         sync.Mutex
	next       uint64
	closed     bool
	pending    map[uint64]*pendingConnectorPermission
	uses       sync.WaitGroup
	suspension ConnectorPermissionGate
}

func OpenConnectorPermissionControl(lifetime, setup context.Context, session muxsession.Session) (*ConnectorPermissionWriter, error) {
	stream, err := session.OpenStream(setup)
	if err != nil {
		return nil, err
	}
	if err := connectorPermissionHandshake(setup, stream, false); err != nil {
		_ = stream.Reset(0)
		return nil, err
	}
	ctx, cancel := context.WithCancelCause(lifetime)
	w := &ConnectorPermissionWriter{stream: stream, gate: make(chan struct{}, 1), ctx: ctx, cancel: cancel, done: make(chan struct{}), pending: make(map[uint64]*pendingConnectorPermission)}
	go w.receive()
	return w, nil
}

func (w *ConnectorPermissionWriter) Done() <-chan struct{} { return w.ctx.Done() }
func (w *ConnectorPermissionWriter) Err() error            { return context.Cause(w.ctx) }

func (w *ConnectorPermissionWriter) Suspend(until time.Time) error {
	return w.suspension.Suspend(until)
}
func (w *ConnectorPermissionWriter) Resume() error { return w.suspension.Resume() }

func (w *ConnectorPermissionWriter) Close() {
	w.cancel(context.Canceled)
	<-w.done
	w.uses.Wait()
}

func (w *ConnectorPermissionWriter) receive() {
	joined := make(chan struct{})
	stop := context.AfterFunc(w.ctx, func() { defer close(joined); _ = w.stream.Reset(0) })
	defer func() {
		if !stop() {
			<-joined
		}
		close(w.done)
	}()
	fail := func(err error) {
		w.mu.Lock()
		w.closed = true
		w.cancel(err) // fence the owner before physical interruption joins.
		w.mu.Unlock()
	}
	for {
		result, err := tunnelv1.ReadConnectorPermissionResult(w.stream)
		if err != nil {
			fail(err)
			return
		}
		w.mu.Lock()
		pending := w.pending[result.UpdateNumber]
		if result.UpdateNumber > w.next || pending != nil && (pending.visitor != result.VisitorConnectionID || pending.generation != result.DeliveryGeneration) {
			w.mu.Unlock()
			fail(tunnelv1.ErrConnectorPermissionUpdate)
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
		w.mu.Unlock()
	}
}

func (w *ConnectorPermissionWriter) Renew(ctx context.Context, update tunnelv1.ConnectorPermissionUpdate) error {
	until, ok := ctx.Deadline()
	if !ok || !until.After(time.Now()) || ctx.Err() != nil {
		return errors.Join(context.DeadlineExceeded, context.Cause(ctx))
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
	started, err := w.suspension.write(call, w.stream, w.gate, func(w io.Writer) error {
		return tunnelv1.WriteConnectorPermissionUpdate(w, update)
	})
	if err != nil {
		if started || !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
			w.cancel(err)
		}
		return err
	}
	return w.suspension.acknowledged(call, pending.result)
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

func writeConnectorPermission(ctx context.Context, stream muxsession.Stream, gate chan struct{}, write func(io.Writer) error) (result error) {
	if err := context.Cause(ctx); err != nil {
		return err
	}
	select {
	case gate <- struct{}{}:
	case <-ctx.Done():
		return context.Cause(ctx)
	}
	defer func() { <-gate }()
	until, ok := ctx.Deadline()
	if !ok || !until.After(time.Now()) {
		return context.DeadlineExceeded
	}
	if err := stream.SetWriteDeadline(until); err != nil {
		return err
	}
	joined := make(chan struct{})
	stop := context.AfterFunc(ctx, func() { defer close(joined); _ = stream.Reset(0) })
	defer func() {
		if !stop() {
			<-joined
		}
		result = errors.Join(result, context.Cause(ctx))
	}()
	result = write(stream)
	if result != nil {
		// partial control frames cannot be repaired or replayed. the ACK
		// reader observes the reset and fences the complete retained owner.
		_ = stream.Reset(0)
	}
	return result
}

// ConnectorPermissionResponder is shared only by the bounded per-admission
// renewal workers. ACK writes never wait for application IO or policy work.
type ConnectorPermissionResponder struct {
	ctx        context.Context
	stream     muxsession.Stream
	gate       chan struct{}
	fail       func(error)
	suspension *ConnectorPermissionGate
}

func (r *ConnectorPermissionResponder) Respond(update tunnelv1.ConnectorPermissionUpdate, accepted bool) error {
	kind := tunnelv1.ConnectorPermissionRejected
	if accepted {
		kind = tunnelv1.ConnectorPermissionAccepted
	}
	return r.respond(update, kind)
}

// RespondStale grants no authority. the caller keeps the admission's existing
// permission deadline and waits for a proof for the current binding revision.
func (r *ConnectorPermissionResponder) RespondStale(update tunnelv1.ConnectorPermissionUpdate) error {
	return r.respond(update, tunnelv1.ConnectorPermissionStale)
}

func (r *ConnectorPermissionResponder) respond(update tunnelv1.ConnectorPermissionUpdate, kind tunnelv1.StreamKind) error {
	ctx, cancel := context.WithTimeout(r.ctx, connectorPermissionSuspensionLimit)
	defer cancel()
	_, err := r.suspension.write(ctx, r.stream, r.gate, func(w io.Writer) error {
		return tunnelv1.WriteConnectorPermissionResult(w, tunnelv1.ConnectorPermissionResult{VisitorConnectionID: update.VisitorConnectionID, UpdateNumber: update.UpdateNumber, DeliveryGeneration: update.DeliveryGeneration, Kind: kind})
	})
	if err != nil {
		r.fail(err)
	}
	return err
}

// dispatch must enqueue without policy or application IO. terminal wire failure
// fences the owner through failed before physical interruption joins.
func ServeConnectorPermissionControl(ctx context.Context, stream muxsession.Stream, dispatch func(tunnelv1.ConnectorPermissionUpdate, *ConnectorPermissionResponder), failed func(), suspension ...*ConnectorPermissionGate) error {
	life, cancel := context.WithCancelCause(ctx)
	joined := make(chan struct{})
	stop := context.AfterFunc(life, func() { defer close(joined); _ = stream.Reset(0) })
	defer func() {
		cancel(context.Canceled)
		if !stop() {
			<-joined
		}
	}()
	var once sync.Once
	fail := func(err error) {
		cancel(err)
		once.Do(failed)
	}
	gate := &ConnectorPermissionGate{}
	if len(suspension) > 0 && suspension[0] != nil {
		gate = suspension[0]
	}
	responder := &ConnectorPermissionResponder{ctx: life, stream: stream, gate: make(chan struct{}, 1), fail: fail, suspension: gate}
	for {
		update, err := tunnelv1.ReadConnectorPermissionUpdate(stream)
		if errors.Is(err, tunnelv1.ErrConnectorPermissionUpdate) {
			continue
		}
		if err != nil {
			fail(err)
			return err
		}
		dispatch(update, responder)
	}
}

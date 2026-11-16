package tunnel

import (
	"context"
	"sync"

	"github.com/tnldotdev/tnl/internal/transport/muxsession"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

func permissionControlScope() tunnelv1.ConnectorControlScope {
	return tunnelv1.ConnectorControlScope{
		ServiceID: "svc_aaaaaaaaaaaaaaaaaaaaaa", ServiceRunID: "srun_aaaaaaaaaaaaaaaaaaaaaa", RunNumber: 1,
		PublisherIdentityID: "pub_aaaaaaaaaaaaaaaaaaaaaa", PairID: "cpp_aaaaaaaaaaaaaaaaaaaaaa",
	}
}

// these transport-only fixtures have no application work. their callback and
// actual result write are joined; real publisher admission proof lives elsewhere.
type permissionTestHandlers struct {
	ctx       context.Context
	update    func(tunnelv1.ConnectorPermissionUpdate, *ConnectorPermissionResponder)
	completed func(tunnelv1.ConnectorVisitorCompletion)
	failed    func()
	rawOnly   bool
	observe   func(tunnelv1.ConnectorVisitorTerminalObserved)
	mu        sync.Mutex
	closed    bool
	workers   sync.WaitGroup
	results   map[uint64]tunnelv1.ConnectorVisitorTerminalResult
}

func (h *permissionTestHandlers) Update(update tunnelv1.ConnectorPermissionUpdate, responder *ConnectorPermissionResponder) error {
	h.update(update, responder)
	return nil
}

func (h *permissionTestHandlers) Terminal(request tunnelv1.ConnectorVisitorTerminalRequest, responder *ConnectorPermissionResponder) error {
	if request.Purpose != tunnelv1.ConnectorTerminalCompletion {
		return ErrConnectorTerminalRejected
	}
	receipt := tunnelv1.ConnectorVisitorCompletion{
		Kind: tunnelv1.ConnectorVisitorCompleted, VisitorConnectionID: request.Key.VisitorConnectionID,
		DeliveryGeneration: request.Key.DeliveryGeneration, TerminalNumber: request.TerminalNumber,
	}
	if h.rawOnly {
		h.completed(receipt)
		return nil
	}
	h.mu.Lock()
	if h.closed {
		h.mu.Unlock()
		return ErrConnectorTerminalRejected
	}
	result := tunnelv1.ConnectorVisitorTerminalResult{
		Kind: tunnelv1.ConnectorVisitorTerminalResultKind, VisitorConnectionID: request.Key.VisitorConnectionID,
		DeliveryGeneration: request.Key.DeliveryGeneration, TerminalNumber: request.TerminalNumber,
		Purpose: request.Purpose, Outcome: tunnelv1.ConnectorTerminalAccepted,
	}
	h.results[request.TerminalNumber] = result
	h.workers.Add(1)
	h.mu.Unlock()
	go func() {
		defer h.workers.Done()
		h.completed(receipt)
		_ = responder.Result(h.ctx, result)
	}()
	return nil
}

func (h *permissionTestHandlers) Observed(observed tunnelv1.ConnectorVisitorTerminalObserved) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	result, ok := h.results[observed.TerminalNumber]
	if !ok || result.TerminalRequest() != observed.TerminalRequest() || result.Outcome != observed.Outcome {
		return ErrConnectorTerminalMismatch
	}
	delete(h.results, observed.TerminalNumber)
	if h.observe != nil {
		h.observe(observed)
	}
	return nil
}

func (h *permissionTestHandlers) Failed(*ConnectorControlFailure) { h.failed() }

func servePermissionTestControl(ctx context.Context, stream muxsession.Stream, update func(tunnelv1.ConnectorPermissionUpdate, *ConnectorPermissionResponder), completed func(tunnelv1.ConnectorVisitorCompletion), failed func(), gate *ConnectorPermissionGate) error {
	life, cancel := context.WithCancel(ctx)
	handlers := &permissionTestHandlers{ctx: life, update: update, completed: completed, failed: failed, results: make(map[uint64]tunnelv1.ConnectorVisitorTerminalResult)}
	defer func() {
		handlers.mu.Lock()
		handlers.closed = true
		handlers.mu.Unlock()
		cancel()
		handlers.workers.Wait()
	}()
	return ServeConnectorPermissionControl(life, stream, permissionControlScope(), handlers, gate)
}

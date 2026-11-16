package connectorfixture

import (
	"context"
	"errors"
	"io"
	"sync"
	"time"

	quic "github.com/quic-go/quic-go"
	"github.com/tnldotdev/tnl/internal/transport/muxsession"
	"github.com/tnldotdev/tnl/internal/transport/tunnel"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

// JoinedVisitor is a fixture barrier, not publisher authorization. the fixture
// closes it only after its real application work, callbacks, and sockets join.
type JoinedVisitor struct {
	Key      tunnelv1.ConnectorVisitorTerminalKey
	Until    time.Time
	Context  context.Context
	cancel   context.CancelFunc
	joined   chan struct{}
	err      error
	stop     func() error
	terminal *joinedTerminal
}

func NewJoinedVisitor(ctx context.Context, entry tunnelv1.ConnectorPeerVisitorEntry, until time.Time, stop func() error) *JoinedVisitor {
	life, cancel := context.WithCancel(ctx)
	return &JoinedVisitor{
		Key:   tunnelv1.ConnectorVisitorTerminalKey{VisitorConnectionID: entry.VisitorConnectionID, DeliveryGeneration: entry.DeliveryGeneration},
		Until: until, Context: life, cancel: cancel, joined: make(chan struct{}), stop: stop,
	}
}

func (v *JoinedVisitor) Join(err error) {
	v.err = err
	close(v.joined)
	v.cancel()
}

type joinedTerminal struct {
	request  tunnelv1.ConnectorVisitorTerminalRequest
	result   tunnelv1.ConnectorVisitorTerminalResult
	writing  bool
	observed chan struct{}
	seen     bool
}

// JoinedControl only joins fixture work supplied by the owning fixture. it
// contains no service policy, capacity accounting, or replacement publisher.
type JoinedControl struct {
	Context    context.Context
	cancel     context.CancelFunc
	Scope      tunnelv1.ConnectorControlScope
	Lookup     func(tunnelv1.ConnectorVisitorTerminalKey) *JoinedVisitor
	Permission func(tunnelv1.ConnectorPermissionUpdate, *tunnel.ConnectorPermissionResponder)
	Entered    func(tunnelv1.ConnectorVisitorTerminalRequest)
	mu         sync.Mutex
	closed     bool
	pending    map[uint64]*joinedTerminal
	workers    sync.WaitGroup
	err        error
}

func NewJoinedControl(ctx context.Context, scope tunnelv1.ConnectorControlScope, lookup func(tunnelv1.ConnectorVisitorTerminalKey) *JoinedVisitor) *JoinedControl {
	life, cancel := context.WithCancel(ctx)
	return &JoinedControl{Context: life, cancel: cancel, Scope: scope, Lookup: lookup, pending: make(map[uint64]*joinedTerminal)}
}

func (c *JoinedControl) Serve(stream muxsession.Stream, gate *tunnel.ConnectorPermissionGate) error {
	err := tunnel.ServeConnectorPermissionControl(c.Context, stream, c.Scope, c, gate)
	c.mu.Lock()
	c.closed = true
	c.mu.Unlock()
	c.cancel()
	c.workers.Wait()
	c.mu.Lock()
	defer c.mu.Unlock()
	return errors.Join(err, c.err)
}

func (c *JoinedControl) Update(update tunnelv1.ConnectorPermissionUpdate, responder *tunnel.ConnectorPermissionResponder) error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return context.Canceled
	}
	c.workers.Add(1)
	c.mu.Unlock()
	go func() {
		defer c.workers.Done()
		if c.Permission != nil {
			c.Permission(update, responder)
			return
		}
		ctx, stop := context.WithTimeout(c.Context, 2*time.Second)
		defer stop()
		if err := responder.Respond(ctx, update, true); err != nil {
			c.Failed(&tunnel.ConnectorControlFailure{Origin: tunnel.ConnectorControlWriterFailure, Err: err})
		}
	}()
	return nil
}

func (c *JoinedControl) Terminal(request tunnelv1.ConnectorVisitorTerminalRequest, responder *tunnel.ConnectorPermissionResponder) error {
	visitor := c.Lookup(request.Key)
	if visitor == nil || visitor.Key != request.Key {
		return tunnel.ErrConnectorTerminalRejected
	}
	c.mu.Lock()
	if visitor.terminal != nil {
		same := visitor.terminal.request == request && c.pending[request.TerminalNumber] == visitor.terminal
		c.mu.Unlock()
		if same {
			return nil
		}
		return tunnel.ErrConnectorTerminalRejected
	}
	if c.closed || len(c.pending) >= tunnel.MaxConnectorApplicationStreams {
		c.mu.Unlock()
		return tunnel.ErrConnectorTerminalRejected
	}
	if existing := c.pending[request.TerminalNumber]; existing != nil {
		c.mu.Unlock()
		if existing.request != request {
			return tunnel.ErrConnectorTerminalRejected
		}
		return nil
	}
	for _, pending := range c.pending {
		if pending.request.Key == request.Key {
			c.mu.Unlock()
			return tunnel.ErrConnectorTerminalRejected
		}
	}
	phase := &joinedTerminal{request: request, observed: make(chan struct{})}
	visitor.terminal = phase
	c.pending[request.TerminalNumber] = phase
	c.workers.Add(1)
	c.mu.Unlock()
	if c.Entered != nil {
		c.Entered(request)
	}
	go func() {
		defer c.workers.Done()
		defer func() { c.mu.Lock(); delete(c.pending, request.TerminalNumber); c.mu.Unlock() }()
		until := visitor.Until
		if cap := time.Now().Add(5 * time.Second); cap.Before(until) {
			until = cap
		}
		ctx, stop := context.WithDeadline(c.Context, until)
		defer stop()
		var closeErr error
		if request.Purpose == tunnelv1.ConnectorTerminalAbort {
			visitor.cancel()
			closeErr = visitor.stop()
		}
		select {
		case <-visitor.joined:
		case <-ctx.Done():
			return
		}
		err := errors.Join(visitor.err, closeErr)
		outcome := tunnelv1.ConnectorTerminalAccepted
		if err != nil && !muxsession.NormalSessionCloseOnly(err) && !(request.Purpose == tunnelv1.ConnectorTerminalAbort && fixtureAbortOnly(err)) {
			outcome = tunnelv1.ConnectorTerminalFailed
		}
		result := tunnelv1.ConnectorVisitorTerminalResult{
			Kind: tunnelv1.ConnectorVisitorTerminalResultKind, VisitorConnectionID: request.Key.VisitorConnectionID,
			DeliveryGeneration: request.Key.DeliveryGeneration, TerminalNumber: request.TerminalNumber, Purpose: request.Purpose, Outcome: outcome,
		}
		c.mu.Lock()
		phase.result, phase.writing = result, true
		c.mu.Unlock()
		if err := responder.Result(ctx, result); err != nil {
			c.Failed(&tunnel.ConnectorControlFailure{Origin: tunnel.ConnectorControlWriterFailure, Err: err})
			return
		}
		select {
		case <-phase.observed:
		case <-ctx.Done():
		}
	}()
	return nil
}

func (c *JoinedControl) Observed(observed tunnelv1.ConnectorVisitorTerminalObserved) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	phase := c.pending[observed.TerminalNumber]
	if phase == nil || !phase.writing || phase.request != observed.TerminalRequest() || phase.result.Outcome != observed.Outcome {
		return tunnel.ErrConnectorTerminalMismatch
	}
	if !phase.seen {
		phase.seen = true
		close(phase.observed)
	}
	return nil
}

func (c *JoinedControl) Failed(err *tunnel.ConnectorControlFailure) {
	c.mu.Lock()
	c.err = errors.Join(c.err, err)
	c.closed = true
	c.mu.Unlock()
	c.cancel()
}

func (c *JoinedControl) Retire() { c.cancel() }

func fixtureAbortOnly(err error) bool {
	if err == nil || err == context.Canceled || err == io.EOF || muxsession.NormalSessionCloseOnly(err) {
		return true
	}
	if stream, ok := err.(*quic.StreamError); ok {
		return stream.ErrorCode == 0
	}
	switch err.(type) {
	case *muxsession.QUICTransportCloseError, *quic.ApplicationError, *quic.TransportError,
		*quic.IdleTimeoutError, *quic.HandshakeTimeoutError, *quic.StatelessResetError,
		*quic.VersionNegotiationError:
		return false
	}
	switch err := err.(type) {
	case interface{ Unwrap() []error }:
		for _, child := range err.Unwrap() {
			if !fixtureAbortOnly(child) {
				return false
			}
		}
		return true
	case interface{ Unwrap() error }:
		return fixtureAbortOnly(err.Unwrap())
	}
	return false
}

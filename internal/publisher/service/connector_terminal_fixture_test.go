package service

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/transport/muxsession"
	"github.com/tnldotdev/tnl/internal/transport/tunnel"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

// these focused fixtures carry real framed control exchanges over one reserved
// pipe stream. multiplex/QUIC behavior belongs to the real native workload and
// transport suites; no helper fabricates a result, Observed, or production join.
type terminalFixtureStream struct{ net.Conn }

func (*terminalFixtureStream) CloseWrite() error    { return nil }
func (s *terminalFixtureStream) Reset(uint32) error { return s.Close() }

type terminalFixtureSession struct {
	stream *terminalFixtureStream
	done   chan struct{}
	once   sync.Once
}

func (s *terminalFixtureSession) OpenStream(context.Context) (muxsession.Stream, error) {
	return s.stream, nil
}
func (s *terminalFixtureSession) AcceptStream(context.Context) (muxsession.Stream, error) {
	return s.stream, nil
}
func (s *terminalFixtureSession) Done() <-chan struct{} { return s.done }
func (s *terminalFixtureSession) Err() error            { return muxsession.ErrClosed }
func (s *terminalFixtureSession) Close() error {
	var err error
	s.once.Do(func() { err = s.stream.Close(); close(s.done) })
	return err
}

type terminalFixtureDispatch struct {
	request   tunnelv1.ConnectorVisitorTerminalRequest
	responder *tunnel.ConnectorPermissionResponder
	err       error
}

type terminalFixtureHandlers struct {
	*PeerSession
	dispatched chan terminalFixtureDispatch
}

func (h *terminalFixtureHandlers) Terminal(request tunnelv1.ConnectorVisitorTerminalRequest, responder *tunnel.ConnectorPermissionResponder) error {
	err := h.PeerSession.Terminal(request, responder)
	h.dispatched <- terminalFixtureDispatch{request: request, responder: responder, err: err}
	return err
}

type modeledConnectorTerminal struct {
	t          *testing.T
	peer       *PeerSession
	writer     *tunnel.ConnectorPermissionWriter
	ctx        context.Context
	dispatched <-chan terminalFixtureDispatch
	last       *terminalFixtureDispatch
	calls      sync.WaitGroup
}

func newModeledConnectorTerminal(t *testing.T, p *PeerSession, wrap ...func(muxsession.Stream) muxsession.Stream) *modeledConnectorTerminal {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	left, right := net.Pipe()
	client := &terminalFixtureSession{stream: &terminalFixtureStream{left}, done: make(chan struct{})}
	server := &terminalFixtureSession{stream: &terminalFixtureStream{right}, done: make(chan struct{})}
	handlers := &terminalFixtureHandlers{PeerSession: p, dispatched: make(chan terminalFixtureDispatch, 64)}
	served := make(chan error, 1)
	go func() {
		stream, err := tunnel.AcceptConnectorPermissionControl(ctx, server)
		if err == nil {
			if len(wrap) != 0 {
				stream = wrap[0](stream)
			}
			err = tunnel.ServeConnectorPermissionControl(ctx, stream, p.controlScope(), handlers, &p.permissionGate)
		}
		served <- err
	}()
	writer, err := tunnel.OpenConnectorPermissionControl(ctx, ctx, client, p.controlScope())
	if err != nil {
		cancel()
		_ = client.Close()
		_ = server.Close()
		<-served
		t.Fatal(err)
	}
	fixture := &modeledConnectorTerminal{t: t, peer: p, writer: writer, ctx: ctx, dispatched: handlers.dispatched}
	t.Cleanup(func() {
		// every modeled admission is explicitly joined by its fixture before
		// this control owner is stopped, exactly as real visitor cleanup is.
		cancel()
		closeErr := writer.Close()
		_ = client.Close()
		_ = server.Close()
		fixture.calls.Wait()
		if !connectorAdmissionRoutineError(closeErr) {
			t.Error("modeled terminal control close", closeErr)
		}
		if err := <-served; !connectorAdmissionRoutineError(err) {
			t.Error("modeled terminal serve", err)
		}
	})
	return fixture
}

func (f *modeledConnectorTerminal) Complete(p *PeerSession, receipt tunnelv1.ConnectorVisitorCompletion) {
	f.t.Helper()
	key := tunnelv1.ConnectorVisitorTerminalKey{VisitorConnectionID: receipt.VisitorConnectionID, DeliveryGeneration: receipt.DeliveryGeneration}
	if f.last != nil && (p != f.peer || f.last.err == nil && f.last.request.Key == key) {
		request := f.last.request
		request.Key = key
		err := p.Terminal(request, f.last.responder)
		if err != nil && err != tunnel.ErrConnectorTerminalRejected {
			f.t.Error("duplicate or wrong-owner terminal dispatch", err)
		}
		return
	}
	returned := make(chan struct{})
	f.calls.Go(func() {
		defer close(returned)
		exchange, err := f.writer.Complete(f.ctx, key)
		if err == nil && (!exchange.Matched || !exchange.ObservedWritten || exchange.Result.Outcome != tunnelv1.ConnectorTerminalAccepted) {
			f.t.Error("modeled completion lacked its actual matched and observed result")
		}
		if err != nil && !httpAdmissionRoutineError(err) && !failure.Only(err, tunnel.ErrConnectorTerminalRejected) && !failure.Only(err, tunnel.ErrConnectorTerminalFailed) {
			f.t.Error("modeled terminal exchange", err)
		}
	})
	dispatch := <-f.dispatched
	f.last = &dispatch
	if dispatch.err != nil {
		<-returned
	}
}

// joinModeledConnectorAdmission is only for tests that own finishDelivery instead
// of forwardPeer. it joins that actual operation, physical close and guard before
// publishing its modeled outcome. production joins are never driven by this.
func joinModeledConnectorAdmission(a *connectorAdmission, operation error) {
	a.cancel()
	operation = errors.Join(operation, a.closeStream())
	if a.guard != nil {
		a.guard.Close()
	}
	b := a.peer.bound
	b.mu.Lock()
	defer b.mu.Unlock()
	if a.joined == nil {
		a.joined = make(chan struct{})
	}
	select {
	case <-a.joined:
		return
	default:
	}
	a.joinedOutcome = connectorAdmissionJoin{err: operation, completionConsumed: a.completionConsumed, abortRequested: a.abortRequested}
	close(a.joined)
}

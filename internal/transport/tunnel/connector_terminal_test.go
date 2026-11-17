package tunnel

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"sync"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/transport/muxsession"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

type terminalTestCall struct {
	exchange ConnectorTerminalExchange
	err      error
}

func terminalTestResult(request tunnelv1.ConnectorVisitorTerminalRequest, outcome tunnelv1.ConnectorTerminalOutcome) tunnelv1.ConnectorVisitorTerminalResult {
	return tunnelv1.ConnectorVisitorTerminalResult{
		Kind: tunnelv1.ConnectorVisitorTerminalResultKind, VisitorConnectionID: request.Key.VisitorConnectionID,
		DeliveryGeneration: request.Key.DeliveryGeneration, TerminalNumber: request.TerminalNumber,
		Purpose: request.Purpose, Outcome: outcome,
	}
}

func TestConnectorTerminalCanceledHistoryDoesNotConsumeCurrentAllowance(t *testing.T) {
	client, server := newMemoryPair(t)
	writer, control := permissionControlPair(t, client, server)
	readRequest := func() tunnelv1.ConnectorVisitorTerminalRequest {
		t.Helper()
		message, err := tunnelv1.ReadConnectorControlMessage(control)
		if err != nil {
			t.Fatal(err)
		}
		return message.(interface {
			TerminalRequest() tunnelv1.ConnectorVisitorTerminalRequest
		}).TerminalRequest()
	}
	var canceled []tunnelv1.ConnectorVisitorTerminalRequest
	for index := range MaxConnectorApplicationStreams + 1 {
		ctx, cancel := context.WithCancel(tunnelContext(t))
		key := tunnelv1.ConnectorVisitorTerminalKey{VisitorConnectionID: fmt.Sprintf("vc_%022d", index), DeliveryGeneration: 7}
		done := tunnelWorker(t, func() { _ = writer.Close() }, func() terminalTestCall {
			exchange, err := writer.Complete(ctx, key)
			return terminalTestCall{exchange, err}
		})
		canceled = append(canceled, readRequest())
		cancel()
		result := await(t, done)
		if !errors.Is(result.err, context.Canceled) || result.exchange.Matched || result.exchange.ObservedWritten {
			t.Fatal("canceled waiter acquired a terminal fact", result)
		}
	}
	pending := make([]<-chan terminalTestCall, 0, MaxConnectorApplicationStreams)
	requests := make([]tunnelv1.ConnectorVisitorTerminalRequest, 0, MaxConnectorApplicationStreams)
	for index := range MaxConnectorApplicationStreams {
		key := tunnelv1.ConnectorVisitorTerminalKey{VisitorConnectionID: fmt.Sprintf("vc_%022d", index+100), DeliveryGeneration: 7}
		done := tunnelWorker(t, func() { _ = writer.Close() }, func() terminalTestCall {
			exchange, err := writer.Abort(tunnelContext(t), key)
			return terminalTestCall{exchange, err}
		})
		pending = append(pending, done)
		requests = append(requests, readRequest())
	}
	writer.mu.Lock()
	count := len(writer.terminals)
	writer.mu.Unlock()
	if count != MaxConnectorApplicationStreams {
		t.Fatal("cancellation history reduced the concurrent allowance", count)
	}
	renewal := tunnelWorker(t, func() { _ = writer.Close() }, func() error {
		return writer.Renew(tunnelContext(t), connectorPermissionFixture())
	})
	updateMessage, err := tunnelv1.ReadConnectorControlMessage(control)
	if err != nil {
		t.Fatal(err)
	}
	update := updateMessage.(tunnelv1.ConnectorPermissionUpdate)
	for _, request := range canceled {
		for range 2 {
			if err := tunnelv1.WriteConnectorVisitorTerminalResult(control, terminalTestResult(request, tunnelv1.ConnectorTerminalAccepted)); err != nil {
				t.Fatal(err)
			}
		}
	}
	// this exact renewal is a decoder-order barrier after every old result.
	if err := tunnelv1.WriteConnectorPermissionResult(control, tunnelv1.ConnectorPermissionResult{
		Kind: tunnelv1.ConnectorPermissionAccepted, VisitorConnectionID: update.VisitorConnectionID,
		UpdateNumber: update.UpdateNumber, DeliveryGeneration: update.DeliveryGeneration,
	}); err != nil {
		t.Fatal(err)
	}
	if err := await(t, renewal); err != nil || writer.Err() != nil {
		t.Fatal("late terminal results poisoned sibling renewal", err, writer.Err())
	}
	for _, done := range pending {
		select {
		case result := <-done:
			t.Fatal("an old terminal result released a current sibling", result)
		default:
		}
	}
	for index, request := range requests {
		if err := tunnelv1.WriteConnectorVisitorTerminalResult(control, terminalTestResult(request, tunnelv1.ConnectorTerminalAccepted)); err != nil {
			t.Fatal(err)
		}
		message, err := tunnelv1.ReadConnectorControlMessage(control)
		if err != nil {
			t.Fatal(err)
		}
		observed, ok := message.(tunnelv1.ConnectorVisitorTerminalObserved)
		if !ok || observed.TerminalRequest() != request || observed.Outcome != tunnelv1.ConnectorTerminalAccepted {
			t.Fatal("actual observed write lost its exact abort binding", message)
		}
		result := await(t, pending[index])
		if result.err != nil || !result.exchange.Matched || !result.exchange.ObservedWritten ||
			result.exchange.Result.TerminalRequest() != request {
			t.Fatal("current abort did not join its actual matched exchange", result)
		}
	}
}

func TestConnectorTerminalActiveAndFutureResultsCannotReleaseAnotherCall(t *testing.T) {
	for _, boundary := range []string{"visitor", "generation", "purpose", "future"} {
		t.Run(boundary, func(t *testing.T) {
			client, server := newMemoryPair(t)
			writer, control := permissionControlPair(t, client, server)
			key := tunnelv1.ConnectorVisitorTerminalKey{VisitorConnectionID: "vc_aaaaaaaaaaaaaaaaaaaaaa", DeliveryGeneration: 7}
			done := tunnelWorker(t, func() { _ = writer.Close() }, func() terminalTestCall {
				exchange, err := writer.Complete(tunnelContext(t), key)
				return terminalTestCall{exchange, err}
			})
			message, err := tunnelv1.ReadConnectorControlMessage(control)
			if err != nil {
				t.Fatal(err)
			}
			request := message.(tunnelv1.ConnectorVisitorCompletion).TerminalRequest()
			result := terminalTestResult(request, tunnelv1.ConnectorTerminalAccepted)
			switch boundary {
			case "visitor":
				result.VisitorConnectionID = "vc_bbbbbbbbbbbbbbbbbbbbbb"
			case "generation":
				result.DeliveryGeneration++
			case "purpose":
				result.Purpose = tunnelv1.ConnectorTerminalAbort
			case "future":
				result.TerminalNumber++
			}
			_ = tunnelv1.WriteConnectorVisitorTerminalResult(control, result)
			got := await(t, done)
			if !errors.Is(got.err, ErrConnectorTerminalMismatch) || got.exchange.Matched || got.exchange.ObservedWritten {
				t.Fatal("foreign terminal result released a call", got)
			}
		})
	}
}

func TestConnectorTerminalRejectionHasNoObservedWrite(t *testing.T) {
	client, server := newMemoryPair(t)
	writer, control := permissionControlPair(t, client, server)
	key := tunnelv1.ConnectorVisitorTerminalKey{VisitorConnectionID: "vc_aaaaaaaaaaaaaaaaaaaaaa", DeliveryGeneration: 7}
	done := tunnelWorker(t, func() { _ = writer.Close() }, func() terminalTestCall {
		exchange, err := writer.Abort(tunnelContext(t), key)
		return terminalTestCall{exchange, err}
	})
	message, err := tunnelv1.ReadConnectorControlMessage(control)
	if err != nil {
		t.Fatal(err)
	}
	request := message.(tunnelv1.ConnectorVisitorAbort).TerminalRequest()
	if err := tunnelv1.WriteConnectorVisitorTerminalResult(control, terminalTestResult(request, tunnelv1.ConnectorTerminalRejected)); err != nil {
		t.Fatal(err)
	}
	result := await(t, done)
	if !errors.Is(result.err, ErrConnectorTerminalRejected) || !result.exchange.Matched || result.exchange.ObservedWritten {
		t.Fatal("rejection claimed a joined abort or observed write", result)
	}
}

func TestConnectorTerminalTimeoutCannotDecideReusedVisitor(t *testing.T) {
	client, server := newMemoryPair(t)
	writer, control := permissionControlPair(t, client, server)
	key := tunnelv1.ConnectorVisitorTerminalKey{VisitorConnectionID: "vc_aaaaaaaaaaaaaaaaaaaaaa", DeliveryGeneration: 7}
	ctx, cancel := context.WithTimeout(tunnelContext(t), 100*time.Millisecond)
	defer cancel()
	old := tunnelWorker(t, func() { _ = writer.Close() }, func() terminalTestCall {
		exchange, err := writer.Complete(ctx, key)
		return terminalTestCall{exchange, err}
	})
	message, err := tunnelv1.ReadConnectorControlMessage(control)
	if err != nil {
		t.Fatal(err)
	}
	previous := message.(tunnelv1.ConnectorVisitorCompletion).TerminalRequest()
	if got := await(t, old); !errors.Is(got.err, context.DeadlineExceeded) || got.exchange.Matched || got.exchange.ObservedWritten {
		t.Fatal("expired terminal acquired a decision", got)
	}
	current := tunnelWorker(t, func() { _ = writer.Close() }, func() terminalTestCall {
		exchange, err := writer.Abort(tunnelContext(t), key)
		return terminalTestCall{exchange, err}
	})
	message, err = tunnelv1.ReadConnectorControlMessage(control)
	if err != nil {
		t.Fatal(err)
	}
	request := message.(tunnelv1.ConnectorVisitorAbort).TerminalRequest()
	if request.TerminalNumber != previous.TerminalNumber+1 {
		t.Fatal("timeout reused a terminal number", previous, request)
	}
	for _, result := range []tunnelv1.ConnectorVisitorTerminalResult{
		terminalTestResult(previous, tunnelv1.ConnectorTerminalAccepted),
		terminalTestResult(request, tunnelv1.ConnectorTerminalAccepted),
	} {
		if err := tunnelv1.WriteConnectorVisitorTerminalResult(control, result); err != nil {
			t.Fatal(err)
		}
	}
	message, err = tunnelv1.ReadConnectorControlMessage(control)
	if err != nil {
		t.Fatal(err)
	}
	observed, ok := message.(tunnelv1.ConnectorVisitorTerminalObserved)
	if !ok || observed.TerminalRequest() != request {
		t.Fatal("late timeout result wrote an observation or decided the reused visitor", message)
	}
	if got := await(t, current); got.err != nil || !got.exchange.Matched || !got.exchange.ObservedWritten || got.exchange.Result.TerminalRequest() != request {
		t.Fatal("current numbered abort lost its matched result", got)
	}
}

func TestConnectorTerminalNumberExhaustionNeverWraps(t *testing.T) {
	client, server := newMemoryPair(t)
	writer, control := permissionControlPair(t, client, server)
	writer.mu.Lock()
	writer.terminalNext = math.MaxUint64 - 1
	writer.mu.Unlock()
	key := tunnelv1.ConnectorVisitorTerminalKey{VisitorConnectionID: "vc_aaaaaaaaaaaaaaaaaaaaaa", DeliveryGeneration: 7}
	last := tunnelWorker(t, func() { _ = writer.Close() }, func() terminalTestCall {
		exchange, err := writer.Complete(tunnelContext(t), key)
		return terminalTestCall{exchange, err}
	})
	message, err := tunnelv1.ReadConnectorControlMessage(control)
	if err != nil {
		t.Fatal(err)
	}
	request := message.(tunnelv1.ConnectorVisitorCompletion).TerminalRequest()
	if request.TerminalNumber != math.MaxUint64 {
		t.Fatal("the last representable terminal number was skipped", request)
	}
	if err := tunnelv1.WriteConnectorVisitorTerminalResult(control, terminalTestResult(request, tunnelv1.ConnectorTerminalRejected)); err != nil {
		t.Fatal(err)
	}
	if got := await(t, last); !errors.Is(got.err, ErrConnectorTerminalRejected) || !got.exchange.Matched || got.exchange.ObservedWritten {
		t.Fatal("the maximum number lost its exact rejection", got)
	}
	exchange, err := writer.Abort(tunnelContext(t), key)
	writer.mu.Lock()
	next, count := writer.terminalNext, len(writer.terminals)
	writer.mu.Unlock()
	if err == nil || exchange.Matched || exchange.ObservedWritten || next != math.MaxUint64 || count != 0 || writer.Err() != nil {
		t.Fatal("exhaustion wrapped or poisoned the shared owner", next, count, exchange, err, writer.Err())
	}
}

type terminalReturnStream struct {
	muxsession.Stream
	ctx                        context.Context
	kind                       tunnelv1.StreamKind
	entered, release, returned chan struct{}
	once                       sync.Once
}

func (s *terminalReturnStream) Write(data []byte) (n int, err error) {
	n, err = s.Stream.Write(data)
	var header struct {
		Kind tunnelv1.StreamKind `json:"kind"`
	}
	if err == nil && json.Unmarshal(data, &header) == nil && header.Kind == s.kind {
		s.once.Do(func() {
			close(s.entered)
			select {
			case <-s.release:
			case <-s.ctx.Done():
				err = context.Cause(s.ctx)
			}
			close(s.returned)
		})
	}
	return n, err
}

type terminalReturnSession struct {
	muxsession.Session
	stream *terminalReturnStream
}

func (s terminalReturnSession) OpenStream(ctx context.Context) (muxsession.Stream, error) {
	stream, err := s.Session.OpenStream(ctx)
	if err != nil {
		return nil, err
	}
	s.stream.Stream = stream
	return s.stream, nil
}

func TestConnectorTerminalObservedCanArriveBeforeResultWriteReturns(t *testing.T) {
	client, server := newMemoryPair(t)
	ctx, cancel := context.WithCancel(tunnelContext(t))
	defer cancel()
	clientLatch := &terminalReturnStream{ctx: ctx, kind: tunnelv1.ConnectorVisitorTerminalObservedKind,
		entered: make(chan struct{}), release: make(chan struct{}), returned: make(chan struct{})}
	writer, control := permissionControlPair(t, terminalReturnSession{Session: client, stream: clientLatch}, server)
	serverLatch := &terminalReturnStream{Stream: control, ctx: ctx, kind: tunnelv1.ConnectorVisitorTerminalResultKind,
		entered: make(chan struct{}), release: make(chan struct{}), returned: make(chan struct{})}
	releaseClient := sync.OnceFunc(func() { close(clientLatch.release) })
	releaseServer := sync.OnceFunc(func() { close(serverLatch.release) })
	defer releaseClient()
	defer releaseServer()
	observed := make(chan tunnelv1.ConnectorVisitorTerminalObserved, 1)
	handlers := &permissionTestHandlers{ctx: ctx, results: make(map[uint64]tunnelv1.ConnectorVisitorTerminalResult),
		update: func(tunnelv1.ConnectorPermissionUpdate, *ConnectorPermissionResponder) {
			t.Error("terminal exchange renewed authority")
		},
		completed: func(tunnelv1.ConnectorVisitorCompletion) {}, failed: func() {},
		observe: func(value tunnelv1.ConnectorVisitorTerminalObserved) { observed <- value }}
	var gate ConnectorPermissionGate
	serverDone := tunnelWorker(t, func() { releaseClient(); releaseServer(); cancel() }, func() error {
		err := ServeConnectorPermissionControl(ctx, serverLatch, permissionControlScope(), handlers, &gate)
		handlers.mu.Lock()
		handlers.closed = true
		handlers.mu.Unlock()
		handlers.workers.Wait()
		return err
	})
	done := tunnelWorker(t, func() { releaseClient(); releaseServer(); _ = writer.Close() }, func() terminalTestCall {
		exchange, err := writer.Complete(ctx, tunnelv1.ConnectorVisitorTerminalKey{VisitorConnectionID: "vc_aaaaaaaaaaaaaaaaaaaaaa", DeliveryGeneration: 7})
		return terminalTestCall{exchange, err}
	})
	await(t, serverLatch.entered)
	gotObserved := await(t, observed)
	await(t, clientLatch.entered)
	select {
	case result := <-done:
		t.Fatal("completion returned before its actual observed write joined", result)
	default:
	}
	select {
	case <-serverLatch.returned:
		t.Fatal("fixture result write was not actually held during observed dispatch")
	default:
	}
	releaseClient()
	result := await(t, done)
	if result.err != nil || !result.exchange.Matched || !result.exchange.ObservedWritten ||
		result.exchange.Result.TerminalRequest() != gotObserved.TerminalRequest() {
		t.Fatal("result/observed race lost its exact decision or write join", result)
	}
	releaseServer()
	await(t, serverLatch.returned)
	cancel()
	_ = await(t, serverDone)
}

func TestConnectorTerminalConflictingActiveOutcomeKeepsFirstDecision(t *testing.T) {
	client, server := newMemoryPair(t)
	ctx, cancel := context.WithCancel(tunnelContext(t))
	defer cancel()
	latch := &terminalReturnStream{ctx: ctx, kind: tunnelv1.ConnectorVisitorTerminalObservedKind,
		entered: make(chan struct{}), release: make(chan struct{}), returned: make(chan struct{})}
	release := sync.OnceFunc(func() { close(latch.release) })
	defer release()
	writer, control := permissionControlPair(t, terminalReturnSession{Session: client, stream: latch}, server)
	done := tunnelWorker(t, func() { release(); _ = writer.Close() }, func() terminalTestCall {
		exchange, err := writer.Complete(ctx, tunnelv1.ConnectorVisitorTerminalKey{VisitorConnectionID: "vc_aaaaaaaaaaaaaaaaaaaaaa", DeliveryGeneration: 7})
		return terminalTestCall{exchange, err}
	})
	message, err := tunnelv1.ReadConnectorControlMessage(control)
	if err != nil {
		t.Fatal(err)
	}
	request := message.(tunnelv1.ConnectorVisitorCompletion).TerminalRequest()
	if err := tunnelv1.WriteConnectorVisitorTerminalResult(control, terminalTestResult(request, tunnelv1.ConnectorTerminalAccepted)); err != nil {
		t.Fatal(err)
	}
	if _, err := tunnelv1.ReadConnectorControlMessage(control); err != nil {
		t.Fatal(err)
	}
	await(t, latch.entered)
	if err := tunnelv1.WriteConnectorVisitorTerminalResult(control, terminalTestResult(request, tunnelv1.ConnectorTerminalFailed)); err != nil {
		t.Fatal(err)
	}
	await(t, writer.Done())
	release()
	got := await(t, done)
	if !errors.Is(got.err, ErrConnectorTerminalMismatch) || !got.exchange.Matched || got.exchange.Result.Outcome != tunnelv1.ConnectorTerminalAccepted {
		t.Fatal("a conflicting active result replaced the first immutable decision", got)
	}
}

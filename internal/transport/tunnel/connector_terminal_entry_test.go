package tunnel

import (
	"context"
	"errors"
	"io"
	"testing"
	"testing/synctest"
	"time"

	"github.com/tnldotdev/tnl/internal/transport/muxsession"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

func TestConnectorTerminalAbortDistinguishesIdleFromEnteredMissingResult(t *testing.T) {
	for _, entered := range []bool{false, true} {
		t.Run(map[bool]string{false: "idle", true: "entered"}[entered], func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				client, server := newMemoryPair(t)
				writer, control := permissionControlPair(t, client, server)
				started := time.Now()
				until := started.Add(time.Second)
				ctx, cancel := context.WithDeadline(t.Context(), until)
				defer cancel()
				key := tunnelv1.ConnectorVisitorTerminalKey{VisitorConnectionID: "vc_aaaaaaaaaaaaaaaaaaaaaa", DeliveryGeneration: 7}
				if !entered {
					time.Sleep(time.Second)
					exchange, err := writer.Abort(ctx, key)
					if !errors.Is(err, context.DeadlineExceeded) || exchange.Matched || exchange.ObservedWritten {
						t.Fatal("idle expiry acquired an entered terminal result", exchange, err)
					}
				} else {
					done := make(chan terminalTestCall, 1)
					go func() {
						exchange, err := writer.Abort(ctx, key)
						done <- terminalTestCall{exchange, err}
					}()
					message, err := tunnelv1.ReadConnectorControlMessage(control)
					if err != nil {
						t.Fatal(err)
					}
					request, ok := message.(tunnelv1.ConnectorVisitorAbort)
					if !ok || request.TerminalRequest().Key != key || request.TerminalNumber != 1 {
						t.Fatal("entered Abort did not reach the exact current stream", message)
					}
					synctest.Wait()
					select {
					case result := <-done:
						t.Fatal("a written and decoded Abort fabricated its missing result", result)
					default:
					}
					time.Sleep(time.Second)
					result := <-done
					if !errors.Is(result.err, context.DeadlineExceeded) || result.exchange.Matched || result.exchange.ObservedWritten {
						t.Fatal("entered terminal deadline was omitted or promoted to a decision", result)
					}
				}
				writer.mu.Lock()
				count, next := len(writer.terminals), writer.terminalNext
				writer.mu.Unlock()
				wantNext := uint64(0)
				if entered {
					wantNext = 1
				}
				if count != 0 || next != wantNext || writer.Err() != nil || !time.Now().Equal(until) {
					t.Fatal("visitor expiry changed owner lifetime, pending state, or original bound", count, next, writer.Err(), time.Since(started))
				}
			})
		})
	}
}

func TestConnectorTerminalAbortFailedResultRemainsMatchedAndObserved(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		client, server := newMemoryPair(t)
		writer, control := permissionControlPair(t, client, server)
		started := time.Now()
		key := tunnelv1.ConnectorVisitorTerminalKey{VisitorConnectionID: "vc_aaaaaaaaaaaaaaaaaaaaaa", DeliveryGeneration: 7}
		done := make(chan terminalTestCall, 1)
		go func() {
			exchange, err := writer.Abort(tunnelContext(t), key)
			done <- terminalTestCall{exchange, err}
		}()
		message, err := tunnelv1.ReadConnectorControlMessage(control)
		if err != nil {
			t.Fatal(err)
		}
		request := message.(tunnelv1.ConnectorVisitorAbort).TerminalRequest()
		if err := tunnelv1.WriteConnectorVisitorTerminalResult(control, terminalTestResult(request, tunnelv1.ConnectorTerminalFailed)); err != nil {
			t.Fatal(err)
		}
		message, err = tunnelv1.ReadConnectorControlMessage(control)
		if err != nil {
			t.Fatal(err)
		}
		observed, ok := message.(tunnelv1.ConnectorVisitorTerminalObserved)
		if !ok || observed.TerminalRequest() != request || observed.Outcome != tunnelv1.ConnectorTerminalFailed {
			t.Fatal("failed Abort lost its exact observation", message)
		}
		result := <-done
		if !errors.Is(result.err, ErrConnectorTerminalFailed) || !result.exchange.Matched || !result.exchange.ObservedWritten ||
			result.exchange.Result.TerminalRequest() != request || result.exchange.Result.Outcome != tunnelv1.ConnectorTerminalFailed ||
			writer.Err() != nil || !time.Now().Equal(started) {
			t.Fatal("an exact failed result became expiry, success, or a shared owner failure", result, writer.Err())
		}
	})
}

type terminalReadFailureSession struct {
	muxsession.Session
	failure error
}

func (s terminalReadFailureSession) OpenStream(ctx context.Context) (muxsession.Stream, error) {
	stream, err := s.Session.OpenStream(ctx)
	if err != nil {
		return nil, err
	}
	return permissionShutdownStream{Stream: stream, eofFailure: s.failure}, nil
}

func TestConnectorTerminalAbortEnteredReaderFailureKeepsPhysicalCause(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		client, server := newMemoryPair(t)
		physical := &muxsession.QUICTransportCloseError{Err: errors.New("independent physical reader failure")}
		writer, control := permissionControlPair(t, terminalReadFailureSession{Session: client, failure: physical}, server)
		started := time.Now()
		done := make(chan terminalTestCall, 1)
		go func() {
			exchange, err := writer.Abort(tunnelContext(t), tunnelv1.ConnectorVisitorTerminalKey{
				VisitorConnectionID: "vc_aaaaaaaaaaaaaaaaaaaaaa", DeliveryGeneration: 7})
			done <- terminalTestCall{exchange, err}
		}()
		message, err := tunnelv1.ReadConnectorControlMessage(control)
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := message.(tunnelv1.ConnectorVisitorAbort); !ok {
			t.Fatal("reader failure fixture did not enter Abort", message)
		}
		if err := control.CloseWrite(); err != nil {
			t.Fatal(err)
		}
		got := <-done
		var failure *ConnectorControlFailure
		if !errors.As(got.err, &failure) || failure.Origin != ConnectorControlReaderFailure ||
			!errors.Is(got.err, physical) || !errors.Is(got.err, io.EOF) || !errors.Is(got.err, context.Canceled) ||
			got.exchange.Matched || got.exchange.ObservedWritten || !time.Now().Equal(started) {
			t.Fatal("entered reader failure became idle expiry, success, or lost physical provenance", got)
		}
		if err := writer.Close(); !errors.Is(err, physical) || !errors.Is(err, io.EOF) {
			t.Fatal("joining the reader erased its independent failure", err)
		}
	})
}

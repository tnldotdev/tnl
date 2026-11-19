package service

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	quic "github.com/quic-go/quic-go"
	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/observability/serviceaudit"
	"github.com/tnldotdev/tnl/internal/security/visitortoken"
	"github.com/tnldotdev/tnl/internal/transport/muxsession"
	"github.com/tnldotdev/tnl/internal/transport/tunnel"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

func TestConnectorTerminalAbortResultWaitsForActualOuterAuditSubmission(t *testing.T) {
	b, p, verification, opening, _ := connectorPeerFixture(t, "127.0.0.1:1")
	ctx, cancel := context.WithTimeout(t.Context(), 4*time.Second)
	defer cancel()
	entered, release := make(chan struct{}), make(chan struct{})
	unblock := sync.OnceFunc(func() { close(release) })
	defer unblock()
	b.audit = connectorAuditSink(func(serviceaudit.Observation) bool {
		close(entered)
		<-release
		return true
	})
	control := newModeledConnectorTerminal(t, p)
	client, server := connectorInnerPair(t, ctx, verification)
	visitor, err := client.OpenStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	// Abort must interrupt an actual locally reset QUIC stream. net.Pipe can
	// instead race its untyped closed-pipe error against preparation entry.
	entry := opening("A")
	written := make(chan error, 1)
	writerJoined := make(chan struct{})
	go func() {
		defer close(writerJoined)
		_, err := tunnelv1.WriteConnectorPeerVisitorOpening(visitor, entry, nil)
		written <- err
	}()
	defer func() { _ = visitor.Close(); <-writerJoined }()
	publisher, err := server.AcceptStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	a, err := p.reserve(ctx, publisher)
	if err != nil {
		t.Fatal(err)
	}
	forwarded := make(chan error, 1)
	go func() { defer p.workers.Done(); forwarded <- a.forwardPeer() }()
	if err := <-written; err != nil {
		t.Fatal(err)
	}
	if err := tunnelv1.ReadConnectorPeerVisitorAccepted(visitor, entry.VisitorConnectionID); err != nil {
		t.Fatal(err)
	}
	type exchangeResult struct {
		exchange tunnel.ConnectorTerminalExchange
		err      error
	}
	result := make(chan exchangeResult, 1)
	b.mu.Lock()
	key := a.terminalKey
	b.mu.Unlock()
	control.calls.Go(func() {
		exchange, err := control.writer.Abort(ctx, key)
		result <- exchangeResult{exchange, err}
	})
	dispatch := <-control.dispatched
	if dispatch.err != nil {
		t.Fatal(dispatch.err)
	}
	<-entered
	b.mu.Lock()
	phase := a.terminal
	pending, charged := b.connectorPending, b.reservedStreams
	decision := phase.result
	b.mu.Unlock()
	if decision != nil || pending != 0 || charged != 0 {
		t.Fatal("Result preceded audit submission, or cleanup did not release charges", decision, pending, charged)
	}
	select {
	case <-a.joined:
		t.Fatal("outer admission claimed joined while its actual audit submission was held")
	case <-result:
		t.Fatal("Abort matched before the real outer admission joined")
	default:
	}
	unblock()
	err = <-forwarded
	if serviceWorkerError(err, errConnectorAdmissionAbort) != nil {
		t.Fatal("unused preparation Abort lost typed interruption provenance", err)
	}
	got := <-result
	if got.err != nil || !got.exchange.Matched || !got.exchange.ObservedWritten ||
		got.exchange.Result.Outcome != tunnelv1.ConnectorTerminalAccepted || got.exchange.Result.TerminalNumber != dispatch.request.TerminalNumber {
		t.Fatal("Abort did not match its actual full join and Observed write", got)
	}
	<-phase.done
}

type terminalResultReturnGate struct {
	muxsession.Stream
	entered chan struct{}
	release <-chan struct{}
	once    sync.Once
}

type terminalResultFailureGate struct {
	muxsession.Stream
	entered chan struct{}
	release <-chan struct{}
	err     error
	once    sync.Once
}

func (s *terminalResultFailureGate) Write(p []byte) (int, error) {
	if bytes.Contains(p, []byte(tunnelv1.ConnectorVisitorTerminalResultKind)) {
		s.once.Do(func() { close(s.entered) })
		<-s.release
		return 0, s.err
	}
	return s.Stream.Write(p)
}

func TestConnectorTerminalNormalPeerCloseDuringResultWrite(t *testing.T) {
	normal := &quic.ApplicationError{Remote: true}
	independent := errors.New("independent terminal write failure")
	for _, test := range []struct {
		name string
		err  error
		want error
	}{
		{"normal", normal, nil},
		{"abnormal", &quic.ApplicationError{Remote: true, ErrorCode: 7}, nil},
		{"independent", errors.Join(normal, independent), independent},
		{"physical", &muxsession.QUICTransportCloseError{Err: normal}, nil},
	} {
		t.Run(test.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				entered, release := make(chan struct{}), make(chan struct{})
				unblock := sync.OnceFunc(func() { close(release) })
				defer unblock()
				b, p, a, entry, control := newConnectorDeliveryAdmission(t, config.ProtocolHTTP, 3*time.Second,
					func(stream muxsession.Stream) muxsession.Stream {
						return &terminalResultFailureGate{Stream: stream, entered: entered, release: release, err: test.err}
					})
				if test.name != "normal" {
					control.expectedFailure = test.err
				}
				finished := make(chan error, 1)
				go func() { finished <- a.finishDelivery(nil) }()
				<-a.stream.(*drainingConnectorWire).closed
				control.Complete(p, tunnelv1.ConnectorVisitorCompletion{
					Kind: tunnelv1.ConnectorVisitorCompleted, VisitorConnectionID: entry.VisitorConnectionID, DeliveryGeneration: entry.DeliveryGeneration,
				})
				if err := <-finished; err != nil {
					t.Fatal(err)
				}
				joinModeledConnectorAdmission(a, nil)
				<-entered
				// model the owner's already-observed normal whole-session end.
				// the held write must not invent ResultObserved or fence the run.
				b.mu.Lock()
				phase := a.terminal
				p.endLocked(tunnel.ConnectorTerminalEnd{Cause: tunnel.ConnectorTerminalPeerTerminated})
				b.mu.Unlock()
				unblock()
				<-phase.done
				b.mu.Lock()
				err, observed, fenced := p.err, phase.observed, b.closed
				b.mu.Unlock()
				if phase.end.Cause != tunnel.ConnectorTerminalPeerTerminated || observed || fenced {
					t.Fatal("terminal write changed peer-end provenance", phase.end, observed, fenced)
				}
				if test.name == "normal" {
					if err != nil {
						t.Fatal("normal peer close escaped toward the publication fence", err)
					}
				} else if err == nil || test.want != nil && !errors.Is(err, test.want) {
					t.Fatal("normal peer close hid an independent failure", err)
				}
			})
		})
	}
}

func (s *terminalResultReturnGate) Write(p []byte) (int, error) {
	n, err := s.Stream.Write(p)
	if err == nil && bytes.Contains(p, []byte(tunnelv1.ConnectorVisitorTerminalResultKind)) {
		s.once.Do(func() { close(s.entered); <-s.release })
	}
	return n, err
}

func TestConnectorTerminalObservedDuringResultReturnKeepsImmutableDecision(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		entered, release := make(chan struct{}), make(chan struct{})
		unblock := sync.OnceFunc(func() { close(release) })
		defer unblock()
		b, p, a, entry, control := newConnectorDeliveryAdmission(t, config.ProtocolTCP, 3*time.Second,
			func(stream muxsession.Stream) muxsession.Stream {
				return &terminalResultReturnGate{Stream: stream, entered: entered, release: release}
			})
		finished := make(chan error, 1)
		go func() { finished <- a.finishDelivery(nil) }()
		<-a.stream.(*drainingConnectorWire).closed
		control.Complete(p, tunnelv1.ConnectorVisitorCompletion{
			Kind: tunnelv1.ConnectorVisitorCompleted, VisitorConnectionID: entry.VisitorConnectionID, DeliveryGeneration: entry.DeliveryGeneration,
		})
		if err := <-finished; err != nil {
			t.Fatal(err)
		}
		joinModeledConnectorAdmission(a, nil)
		<-entered
		synctest.Wait()
		b.mu.Lock()
		phase := a.terminal
		observed, decision, until := phase.observed, *phase.result, a.terminalUntil
		b.mu.Unlock()
		if !observed || decision.Kind != tunnelv1.ConnectorVisitorTerminalResultKind || decision.Outcome != tunnelv1.ConnectorTerminalAccepted {
			t.Fatal("actual Observed did not match the decision registered before Result returned", observed, decision)
		}
		select {
		case <-phase.done:
			t.Fatal("Observed skipped the actual Result write-return join")
		default:
		}
		if err := p.Terminal(control.last.request, control.last.responder); err != nil {
			t.Fatal("exact duplicate did not reuse the entered phase", err)
		}
		wrong := control.last.request
		wrong.TerminalNumber++
		if err := p.Terminal(wrong, control.last.responder); err != tunnel.ErrConnectorTerminalRejected {
			t.Fatal("changed number replaced an entered decision", err)
		}
		b.mu.Lock()
		if a.terminal != phase || a.terminalUntil != until || *phase.result != decision {
			b.mu.Unlock()
			t.Fatal("duplicate changed its phase, deadline, or immutable result")
		}
		b.mu.Unlock()
		unblock()
		<-phase.done
		if phase.end.Cause != tunnel.ConnectorTerminalResultObserved {
			t.Fatal("exact Observed did not end its joined phase", phase.end)
		}
	})
}

func TestConnectorTerminalRejectedCreatesNoPhaseOrDrainHold(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		b, p, a, entry, control := newConnectorDeliveryAdmission(t, config.ProtocolTCP, time.Second)
		wrong := entry
		wrong.VisitorConnectionID = "vc_aaaaaaaaaaaaaaaaaaaaaa"
		control.Complete(p, tunnelv1.ConnectorVisitorCompletion{
			Kind: tunnelv1.ConnectorVisitorCompleted, VisitorConnectionID: wrong.VisitorConnectionID, DeliveryGeneration: wrong.DeliveryGeneration,
		})
		if control.last.err != tunnel.ErrConnectorTerminalRejected {
			t.Fatal("unknown request did not use the exact rejection leaf", control.last.err)
		}
		b.mu.Lock()
		if a.terminal != nil || a.completionConsumed {
			b.mu.Unlock()
			t.Fatal("rejected request entered a terminal phase")
		}
		b.terminalEntrySealed = true
		b.mu.Unlock()
		request := tunnelv1.ConnectorVisitorTerminalRequest{Key: a.terminalKey, Purpose: tunnelv1.ConnectorTerminalAbort, TerminalNumber: 2}
		if err := p.Terminal(request, control.last.responder); err != tunnel.ErrConnectorTerminalRejected {
			t.Fatal("sealed request created a terminal hold", err)
		}
		b.terminalWorkers.Wait()
	})
}

func TestConnectorAbortClassificationKeepsJoinedIndependentFailures(t *testing.T) {
	ctx, abort := context.WithCancelCause(t.Context())
	abort(errConnectorAdmissionAbort)
	independent := errors.New("independent physical cleanup failed")
	err := connectorAbortOperation(errors.Join(context.Canceled, independent), &connectorAdmission{ctx: ctx})
	if !errors.Is(err, errConnectorAdmissionAbort) || !errors.Is(err, independent) ||
		serviceWorkerError(err, errConnectorAdmissionAbort) == nil {
		t.Fatal("owned Abort hid an independent joined failure", err)
	}
	for _, test := range []struct {
		name  string
		err   error
		owned bool
	}{
		{"exact-stop", errConnectorAdmissionAbort, true},
		{"joined-stops", errors.Join(errConnectorAdmissionAbort, errors.Join(errConnectorAdmissionAbort)), true},
		{"nil", nil, false},
		{"unidentified-cancellation", context.Canceled, false},
		{"joined-independent-failure", errors.Join(errConnectorAdmissionAbort, independent), false},
		{"physical-close", &muxsession.QUICTransportCloseError{Err: errConnectorAdmissionAbort}, false},
		{"control-failure", &tunnel.ConnectorControlFailure{Origin: tunnel.ConnectorControlWriterFailure, Err: errConnectorAdmissionAbort}, false},
		{"session-cleanup", &tunnel.SessionCleanupError{Err: errConnectorAdmissionAbort}, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			if connectorAbortOnly(test.err) != test.owned {
				t.Fatal("TLS interruption matching borrowed independent or required failure provenance", test.err)
			}
		})
	}
}

func TestConnectorTerminalMissingObservedEndsOnlyWithAuthenticatedRetirement(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		b, p, _, opening, _ := connectorPeerFixture(t, "127.0.0.1:1")
		ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
		defer cancel()
		entry := opening("M")
		view, _, _ := b.prepared.policy.Current()
		permission, err := visitortoken.VerifyConnectorPeerSession(entry, nil, p.bindingSnapshot().expected(), view, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		life, stop := context.WithCancel(ctx)
		a := &connectorAdmission{peer: p, ctx: life, caller: ctx, cancel: stop,
			stream: &drainingConnectorWire{closed: make(chan struct{})}, state: readyConnectorAdmission{},
			completed: make(chan struct{}), joined: make(chan struct{}),
			terminalKey: tunnelv1.ConnectorVisitorTerminalKey{VisitorConnectionID: entry.VisitorConnectionID, DeliveryGeneration: entry.DeliveryGeneration}}
		a.guard, err = b.prepared.policy.BindConnector(permission, netip.MustParseAddr("192.0.2.1"), b.prepared.metadataRevision, a.stopAndClose)
		if err != nil {
			t.Fatal(err)
		}
		b.mu.Lock()
		p.streams[a] = struct{}{}
		b.mu.Unlock()
		left, right := net.Pipe()
		client := &terminalFixtureSession{stream: &terminalFixtureStream{left}, done: make(chan struct{})}
		server := &terminalFixtureSession{stream: &terminalFixtureStream{right}, done: make(chan struct{})}
		served := make(chan error, 1)
		go func() {
			stream, err := tunnel.AcceptConnectorPermissionControl(ctx, server)
			if err == nil {
				err = tunnel.ServeConnectorPermissionControl(ctx, stream, p.controlScope(), p, &p.permissionGate)
			}
			served <- err
		}()
		defer func() {
			stop()
			err := a.finishDelivery(context.Canceled)
			joinModeledConnectorAdmission(a, err)
			cancel()
			_ = client.Close()
			_ = server.Close()
			b.terminalWorkers.Wait()
			if err := <-served; !httpAdmissionRoutineError(err) {
				t.Error("raw terminal control cleanup", err)
			}
		}()
		raw := rawConnectorControl(t, ctx, client)
		joined := make(chan error, 1)
		go func() {
			err := a.finishDelivery(nil)
			joinModeledConnectorAdmission(a, err)
			joined <- err
		}()
		request := tunnelv1.ConnectorVisitorCompletion{Kind: tunnelv1.ConnectorVisitorCompleted,
			VisitorConnectionID: entry.VisitorConnectionID, DeliveryGeneration: entry.DeliveryGeneration, TerminalNumber: 9}
		if err := tunnelv1.WriteConnectorVisitorCompletion(raw, request); err != nil {
			t.Fatal(err)
		}
		reply, err := tunnelv1.ReadConnectorControlReply(raw)
		if err != nil {
			t.Fatal(err)
		}
		result, ok := reply.(tunnelv1.ConnectorVisitorTerminalResult)
		if !ok || result.TerminalRequest() != request.TerminalRequest() || result.Outcome != tunnelv1.ConnectorTerminalAccepted {
			t.Fatal("publisher did not return the actual joined admission result", reply)
		}
		if err := <-joined; err != nil {
			t.Fatal(err)
		}
		b.mu.Lock()
		phase := a.terminal
		b.mu.Unlock()
		select {
		case <-phase.done:
			t.Fatal("a decoded Result was treated as remote Observed")
		default:
		}
		now := time.Now()
		if err := b.observePeerOwners(now, peerRetirementPage(p.identity.pairID, now, now, now.Add(time.Minute))); err != nil {
			t.Fatal(err)
		}
		<-phase.done
		if phase.observed || phase.end.Cause != tunnel.ConnectorTerminalOwnerRetired || phase.end.Err != nil {
			t.Fatal("authenticated retirement fabricated Observed or successful copying", phase.observed, phase.end)
		}
	})
}

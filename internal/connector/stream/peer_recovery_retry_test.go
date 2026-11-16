package stream

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/tnldotdev/tnl/internal/transport/muxsession"
	"github.com/tnldotdev/tnl/internal/transport/peer"
	"github.com/tnldotdev/tnl/internal/transport/tunnel"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

// enter the existing coordinator after staging. failed dials return before any
// endpoint, publisher activation, or control mutation; none is simulated here.
func pendingRetryOwner(t *testing.T, budget context.Context) (*connectorConnection, *connectorRebindOperation) {
	t.Helper()
	signer, run, original, request, state := rebindFixture(t)
	ctx, cancel := context.WithCancelCause(budget)
	t.Cleanup(func() { cancel(nil) })
	op := &connectorRebindOperation{prepare: &connectorRebindPhase{request: request, started: state.Pending.ObservedAt},
		pair: *state.Pending, until: *state.PendingUntil, staged: true,
		initial: [2]tunnelv1.ConnectorHandoffID{{1}, {2}}}
	p := &connectorConnection{ctx: ctx, cancel: cancel, packetCtx: budget, signer: signer, owner: request.IdempotencyKey,
		run: run, pair: original, until: original.ExpiresAt, preparedUntil: original.ExpiresAt,
		permission: controlv1.VisitorTokenResponse{ExpiresAt: original.ExpiresAt}, highWater: state.HighWaterGeneration,
		recoveryState: connectorRebinding, rebind: op, changed: make(chan struct{}), recover: make(chan struct{}, 1)}
	return p, op
}

func startPendingRetryRefresh(t *testing.T, p *connectorConnection) <-chan struct{} {
	t.Helper()
	done := make(chan struct{})
	p.recover <- struct{}{}
	t.Cleanup(func() { p.cancel(context.Canceled); <-done })
	go func() { defer close(done); p.refresh() }()
	return done
}

func TestConnectorPendingLostHelloKeepsLiveOwner(t *testing.T) {
	for _, transport := range []string{"quic", "tls-tcp"} {
		t.Run(transport, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				budget, stop := context.WithTimeout(t.Context(), 5*time.Second)
				defer stop()
				p, op := pendingRetryOwner(t, budget)
				pair, initial := op.pair, op.initial
				// serialized snapshots do not alias the mutable relay/proof slices.
				pairBefore, err := json.Marshal(op.pair)
				if err != nil {
					t.Fatal(err)
				}
				prepareBefore, err := json.Marshal(op.prepare.request)
				if err != nil {
					t.Fatal(err)
				}
				ownerUntil, runUntil, permissionUntil, pendingUntil := p.until, p.run.ValidUntil, p.permission.ExpiresAt, op.until
				preparedUntil, prepareStarted := p.preparedUntil, op.prepare.started
				sessions := [2]*legRetrySession{
					newLegRetrySession(t, budget, op.pair, 0, legRetryScript{}),
					newLegRetrySession(t, budget, op.pair, 1, legRetryScript{}),
				}
				alternate := [2]error{errors.New("first slot alternate did not connect"), errors.New("second slot alternate did not connect")}
				var calls [2][2]atomic.Int32
				connector := func(hello bool) muxsession.Connector {
					kind := 1
					if hello {
						kind = 0
					}
					return muxsession.ConnectorFunc(func(call context.Context, endpoint muxsession.Endpoint) (muxsession.Session, error) {
						for slot, relay := range pair.Relays {
							if endpoint.Address != relay.RelayAddress {
								continue
							}
							if calls[slot][kind].Add(1) != 1 {
								// do not reuse a closed transport if a later tick starts.
								<-call.Done()
								return nil, context.Cause(call)
							}
							if hello {
								return sessions[slot], nil
							}
							return nil, alternate[slot]
						}
						return nil, errors.New("unexpected pending relay endpoint")
					})
				}
				p.config = Config{RelayQUIC: connector(true), RelayTCP: connector(false)}
				if transport == "tls-tcp" {
					p.config.RelayQUIC, p.config.RelayTCP = p.config.RelayTCP, p.config.RelayQUIC
				}
				startPendingRetryRefresh(t, p)
				for _, session := range sessions {
					assertLegRetryHello(t, budget, session)
				}
				synctest.Wait()
				if cause := context.Cause(p.ctx); cause != nil {
					t.Error("pending lost hello terminated an owner with live authority", cause)
				}
				p.mu.Lock()
				pairAfter, pairErr := json.Marshal(op.pair)
				prepareAfter, prepareErr := json.Marshal(op.prepare.request)
				unchanged := p.rebind == op && p.recoveryState == connectorRebinding && !op.retired && op.staged &&
					op.activate == nil && op.abort == nil && op.legs == [2]*connectorRelayLeg{} &&
					pairErr == nil && prepareErr == nil && bytes.Equal(pairBefore, pairAfter) && bytes.Equal(prepareBefore, prepareAfter) && op.initial == initial &&
					p.until.Equal(ownerUntil) && p.run.ValidUntil.Equal(runUntil) &&
					p.permission.ExpiresAt.Equal(permissionUntil) && op.until.Equal(pendingUntil) &&
					p.preparedUntil.Equal(preparedUntil) && op.prepare.started.Equal(prepareStarted) && p.highWater == pair.DeliveryGeneration
				p.mu.Unlock()
				if !unchanged {
					t.Error("retry changed the pending operation, initial handoffs, authority, or deadline")
				}
				for slot, session := range sessions {
					if calls[slot][0].Load() != 1 || calls[slot][1].Load() != 1 || session.closes.Load() != 1 {
						t.Error("pending recovery changed the two-candidate attempt budget or lost physical cleanup", slot)
					}
				}
			})
		})
	}
}

func TestConnectorPendingRetryRequiresEveryFailedSlot(t *testing.T) {
	for _, transport := range []string{"quic", "tls-tcp"} {
		for _, kind := range []string{"unrelated operation", "joined operation", "denial", "connector cleanup", "session cleanup", "physical cleanup"} {
			for _, fatalSlot := range []int{0, 1} {
				t.Run(fmt.Sprintf("%s/%s/fatal-slot=%d", transport, kind, fatalSlot), func(t *testing.T) {
					synctest.Test(t, func(t *testing.T) {
						budget, stop := context.WithTimeout(t.Context(), 5*time.Second)
						defer stop()
						p, op := pendingRetryOwner(t, budget)
						session := newLegRetrySession(t, budget, op.pair, 1-fatalSlot, legRetryScript{})
						independent := errors.New("relay slot failed independently")
						var slotFailure error = independent
						switch kind {
						case "joined operation":
							slotFailure = errors.Join(io.ErrUnexpectedEOF, independent)
						case "denial":
							slotFailure = errors.Join(&tunnel.ProtocolError{Code: tunnelv1.Unauthenticated}, independent)
						case "connector cleanup":
							slotFailure = &CleanupError{Err: errors.Join(io.ErrUnexpectedEOF, independent)}
						case "session cleanup":
							slotFailure = &tunnel.SessionCleanupError{Err: errors.Join(io.ErrUnexpectedEOF, independent)}
						case "physical cleanup":
							slotFailure = &muxsession.QUICTransportCloseError{Err: errors.Join(io.ErrUnexpectedEOF, independent)}
						}
						alternate := errors.New("retryable relay slot alternate did not connect")
						var calls [2][2]atomic.Int32
						connector := func(hello bool) muxsession.Connector {
							kind := 1
							if hello {
								kind = 0
							}
							return muxsession.ConnectorFunc(func(call context.Context, endpoint muxsession.Endpoint) (muxsession.Session, error) {
								for slot, relay := range op.pair.Relays {
									if endpoint.Address != relay.RelayAddress {
										continue
									}
									if calls[slot][kind].Add(1) != 1 {
										<-call.Done()
										return nil, context.Cause(call)
									}
									if slot == fatalSlot {
										return nil, slotFailure
									}
									if hello {
										return session, nil
									}
									return nil, alternate
								}
								return nil, errors.New("unexpected pending relay endpoint")
							})
						}
						p.config = Config{RelayQUIC: connector(true), RelayTCP: connector(false)}
						if transport == "tls-tcp" {
							p.config.RelayQUIC, p.config.RelayTCP = p.config.RelayTCP, p.config.RelayQUIC
						}
						startPendingRetryRefresh(t, p)
						assertLegRetryHello(t, budget, session)
						synctest.Wait()
						cause := context.Cause(p.ctx)
						if cause == nil || !errors.Is(cause, independent) || !errors.Is(cause, io.ErrUnexpectedEOF) ||
							!errors.Is(cause, alternate) || !errors.Is(cause, slotFailure) {
							t.Error("one relay slot's lost hello hid another slot's fatal operation or cleanup", cause)
						}
						if op.legs != [2]*connectorRelayLeg{} || op.activate != nil || op.retired {
							t.Error("failed pending dials installed or activated a leg")
						}
						for slot := range calls {
							if calls[slot][0].Load() != 1 || calls[slot][1].Load() != 1 {
								t.Error("fatal relay slot started another attempt", slot)
							}
						}
					})
				})
			}
		}
	}
}

// use the real packet owner only for staging and negative cleanup. no synthetic
// publisher proof, ready path, or successful control mutation is supplied.
func pendingRetryEndpoint(t *testing.T, ctx context.Context, p *connectorConnection, op *connectorRebindOperation) {
	t.Helper()
	for slot := range p.paths {
		p.paths[slot].carrier = peer.NewCarrierSlot()
	}
	endpoint, err := peer.New(ctx, peer.Config{Key: [32]byte{1}, Binding: connectorBindingRevision(p.pair),
		Paths: [2]peer.Carrier{p.paths[0].carrier, p.paths[1].carrier}})
	if err != nil {
		t.Fatal(err)
	}
	p.endpoint = endpoint
	t.Cleanup(func() { _ = endpoint.Close() })
	if op.staged {
		if err := endpoint.StageBinding(connectorBindingRevision(op.pair)); err != nil {
			t.Fatal(err)
		}
	}
}

func pendingRetryLeg(t *testing.T, ctx context.Context, p *connectorConnection, op *connectorRebindOperation, slot int, script legRetryScript) (*connectorRelayLeg, *legRetrySession) {
	t.Helper()
	session := newLegRetrySession(t, ctx, op.pair, slot, script)
	var calls [2]atomic.Int32
	key, err := connectorPairSecret(op.pair.Key)
	if err != nil {
		t.Fatal(err)
	}
	leg, err := dialConnectorLeg(ctx, ctx, legRetryConfig("quic", session, errors.New("alternate did not connect"), &calls),
		p.signer, op.pair, key, slot, nil, op.initial[slot])
	if err != nil {
		t.Fatal("prepare the actual pending leg", err)
	}
	t.Cleanup(func() { _ = leg.Close() })
	assertLegRetryHello(t, ctx, session)
	return leg, session
}

func TestConnectorPendingActivationLostReplyKeepsOperationAndCleanup(t *testing.T) {
	for _, boundary := range []string{"clean close", "failed close", "independent operation"} {
		t.Run(boundary, func(t *testing.T) {
			ctx, stop := context.WithTimeout(t.Context(), 5*time.Second)
			defer stop()
			p, op := pendingRetryOwner(t, ctx)
			pendingRetryEndpoint(t, ctx, p, op)
			until, initial, prepare := op.until, op.initial, op.prepare
			physical := errors.New("activation candidate close failed")
			independent := errors.New("activation operation failed independently")
			failedClose := boundary == "failed close"
			wantRetry := boundary == "clean close"
			script := legRetryScript{response: tunnelv1.HelloAccepted, activation: true}
			if failedClose {
				script.closeErr = physical
			}
			if boundary == "independent operation" {
				script.readErr = errors.Join(io.ErrUnexpectedEOF, independent)
			}
			op.legs[1], _ = pendingRetryLeg(t, ctx, p, op, 1, legRetryScript{response: tunnelv1.HelloAccepted})
			inspections := 0
			p.config.Control = recoveryPhaseControl{call: func(request controlv1.ConnectorPeerPairRebindRequest) (controlv1.ConnectorPeerPairRebindState, error) {
				inspections++
				if request.Phase != controlv1.ConnectorPeerPairInspect {
					t.Error("pending activation performed a control mutation")
				}
				active, pending := p.pair, op.pair
				pending.PublisherPreparedUntil = new(op.until)
				return controlv1.ConnectorPeerPairRebindState{Active: &active, Pending: &pending,
					HighWaterGeneration: p.highWater, ReadyRelays: pending.Relays, PendingUntil: new(op.until),
					Operation: &controlv1.ConnectorPeerPairRebindOperation{OperationId: pending.OperationId,
						DeliveryGeneration: pending.DeliveryGeneration, Status: controlv1.ConnectorPeerPairOperationPending}}, nil
			}}
			var previousNonce []byte
			for attempt := range 2 {
				leg, session := pendingRetryLeg(t, ctx, p, op, 0, script)
				if bytes.Equal(previousNonce, leg.proof.Nonce) {
					t.Fatal("activation retry reused its signed hello")
				}
				previousNonce = bytes.Clone(leg.proof.Nonce)
				op.legs[0] = leg
				result := p.connectPendingLegs(op)
				select {
				case binding := <-session.activation:
					activation, err := binding.Activation()
					operation, ok := activation.InitialOperation()
					if err != nil || !ok || operation != initial[0] || activation.SelectedHandoff() != initial[0] {
						t.Error("lost activation reply changed the initial handoff", err)
					}
				case <-ctx.Done():
					t.Fatal("activation did not reach the wire within the case budget")
				}
				if !errors.Is(result.err, io.ErrUnexpectedEOF) || result.retry != wantRetry ||
					op.legs[0] != nil || op.legs[1] == nil || op.activated[0] || !op.until.Equal(until) ||
					op.initial != initial || op.prepare != prepare || op.retired || session.closes.Load() != 1 {
					t.Error("lost activation reply reset the operation or lost its cleanup disposition", result.err)
				}
				if failedClose {
					var cleanup *CleanupError
					if !errors.Is(result.err, physical) || !errors.As(result.err, &cleanup) || errors.Is(cleanup, io.ErrUnexpectedEOF) {
						t.Error("activation cleanup hid or relabeled its independent operation", result.err)
					}
					break
				}
				if boundary == "independent operation" {
					if !errors.Is(result.err, independent) {
						t.Error("activation's unavailable diagnostic hid an independent operation", result.err)
					}
					break
				}
				if inspections != attempt+1 {
					t.Error("activation retry skipped or duplicated current-owner inspection")
				}
			}
		})
	}
}

func TestConnectorRecoveryDiscardAndStageCleanup(t *testing.T) {
	for _, boundary := range []string{"discard", "stage"} {
		t.Run(boundary, func(t *testing.T) {
			ctx, stop := context.WithTimeout(t.Context(), 5*time.Second)
			defer stop()
			p, op := pendingRetryOwner(t, ctx)
			op.staged = boundary != "stage"
			pendingRetryEndpoint(t, ctx, p, op)
			physical := [2]error{errors.New("first leg close failed"), errors.New("second leg close failed")}
			var sessions [2]*legRetrySession
			for slot := range op.legs {
				leg, session := pendingRetryLeg(t, ctx, p, op, slot, legRetryScript{response: tunnelv1.HelloAccepted, closeErr: physical[slot]})
				sessions[slot] = session
				if boundary == "discard" {
					op.legs[slot], op.installed[slot], op.activated[slot] = leg, true, true
					// create a dead transport with its independently failing close.
					_ = leg.session.Close()
				} else {
					p.paths[slot].leg = leg
				}
			}
			var dials atomic.Int32
			gate := muxsession.ConnectorFunc(func(context.Context, muxsession.Endpoint) (muxsession.Session, error) {
				dials.Add(1)
				return nil, errors.New("new dial after failed cleanup")
			})
			p.config.RelayQUIC, p.config.RelayTCP = gate, gate
			var result connectorRecoveryResult
			if boundary == "discard" {
				result = p.connectPendingLegs(op)
			} else {
				result = p.recoverBinding()
			}
			if result.retry || !errors.Is(result.err, physical[0]) || !errors.Is(result.err, physical[1]) || dials.Load() != 0 {
				t.Error("discard/stage cleanup was retried, skipped a close, or started new work", result.err)
			}
			for _, session := range sessions {
				if session.closes.Load() != 1 {
					t.Error("discard/stage acquired a second physical closing owner")
				}
			}
			if boundary == "discard" && (op.legs != [2]*connectorRelayLeg{} || op.installed != [2]bool{} || op.activated != [2]bool{}) {
				t.Error("discard left a failed pending leg installed")
			}
			if boundary == "stage" && op.staged {
				t.Error("failed old-leg cleanup advanced staging")
			}
		})
	}
}

func TestConnectorPendingStaleRetirementPreservesCleanup(t *testing.T) {
	for _, code := range []tunnelv1.ErrorCode{tunnelv1.StaleConnectionAssignment, tunnelv1.StaleNetworkBinding} {
		for _, failedClose := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/failed-close=%t", code, failedClose), func(t *testing.T) {
				ctx, stop := context.WithTimeout(t.Context(), 5*time.Second)
				defer stop()
				p, op := pendingRetryOwner(t, ctx)
				pendingRetryEndpoint(t, ctx, p, op)
				until := op.until
				physical := [2]error{errors.New("first pending retirement close failed"), errors.New("second pending retirement close failed")}
				var sessions [2]*legRetrySession
				for slot := range op.legs {
					script := legRetryScript{response: tunnelv1.HelloAccepted}
					if failedClose {
						script.closeErr = physical[slot]
					}
					op.legs[slot], sessions[slot] = pendingRetryLeg(t, ctx, p, op, slot, script)
					if err := p.endpoint.InstallBindingCarrier(connectorBindingRevision(op.pair), slot, connectorLegCarrier{op.legs[slot]}); err != nil {
						t.Fatal(err)
					}
					op.installed[slot] = true
				}
				rejected := newLegRetrySession(t, ctx, op.pair, 0, legRetryScript{response: tunnelv1.Error, code: code})
				var calls [2]atomic.Int32
				_, rejectedErr := dialConnectorLeg(ctx, ctx, legRetryConfig("quic", rejected, errors.New("alternate did not connect"), &calls),
					p.signer, op.pair, [32]byte{1}, 0, nil, op.initial[0])
				assertLegRetryHello(t, ctx, rejected)
				result := p.pendingLegFailures(op, [2]error{rejectedErr, nil})
				var stale *tunnel.ProtocolError
				if result.retry == failedClose || !errors.As(result.err, &stale) || stale.Code != code ||
					!op.retired || op.legs != [2]*connectorRelayLeg{} || op.installed != [2]bool{} ||
					!op.until.Equal(until) || p.rebind != op || context.Cause(p.ctx) != nil {
					t.Error("stale pending retirement changed authority or lost its disposition", result.err)
				}
				if failedClose && (!errors.Is(result.err, physical[0]) || !errors.Is(result.err, physical[1]) ||
					!errors.Is(p.retirePending(op), physical[0]) || !errors.Is(p.retirePending(op), physical[1])) {
					t.Error("retirement lost independent or repeated cleanup failures", result.err)
				}
				for _, session := range sessions {
					if session.closes.Load() != 1 {
						t.Error("retirement acquired a second physical closing owner")
					}
				}
			})
		}
	}
}

func TestConnectorPendingExpiryRetiresWithoutExtendingAuthority(t *testing.T) {
	for _, failedClose := range []bool{false, true} {
		t.Run(fmt.Sprintf("failed-close=%t", failedClose), func(t *testing.T) {
			ctx, stop := context.WithTimeout(t.Context(), 5*time.Second)
			defer stop()
			p, op := pendingRetryOwner(t, ctx)
			pendingRetryEndpoint(t, ctx, p, op)
			physical := errors.New("expired pending close failed")
			script := legRetryScript{response: tunnelv1.HelloAccepted}
			if failedClose {
				script.closeErr = physical
			}
			var sessions [2]*legRetrySession
			for slot := range op.legs {
				op.legs[slot], sessions[slot] = pendingRetryLeg(t, ctx, p, op, slot, script)
			}
			// retain the advertised interval, but enter with its local observation
			// already spent; no sleep or shorter production cap is introduced.
			interval := op.pair.ExpiresAt.Sub(op.pair.ObservedAt)
			op.prepare.started = time.Now().Add(-interval)
			op.until = op.prepare.started.Add(interval)
			expired, ownerUntil, runUntil, permissionUntil := op.until, p.until, p.run.ValidUntil, p.permission.ExpiresAt
			inspections := 0
			p.config.Control = recoveryPhaseControl{call: func(request controlv1.ConnectorPeerPairRebindRequest) (controlv1.ConnectorPeerPairRebindState, error) {
				inspections++
				if request.Phase != controlv1.ConnectorPeerPairInspect {
					t.Error("expired pending operation renewed or replaced its phase")
				}
				active := p.pair
				return controlv1.ConnectorPeerPairRebindState{Active: &active, HighWaterGeneration: p.highWater,
					ReadyRelays: active.Relays, Operation: &controlv1.ConnectorPeerPairRebindOperation{OperationId: op.pair.OperationId,
						DeliveryGeneration: op.pair.DeliveryGeneration, Status: controlv1.ConnectorPeerPairOperationExpired}}, nil
			}}
			result := p.recoverBinding()
			if result.retry == failedClose || !op.retired || op.legs != [2]*connectorRelayLeg{} ||
				!op.until.Equal(expired) || !p.until.Equal(ownerUntil) || !p.run.ValidUntil.Equal(runUntil) ||
				!p.permission.ExpiresAt.Equal(permissionUntil) || p.highWater != op.pair.DeliveryGeneration || op.abort != nil {
				t.Error("expiry extended authority, installed a leg, or restarted the operation", result.err)
			}
			if failedClose {
				if !errors.Is(result.err, physical) || inspections != 0 || p.rebind != op {
					t.Error("expired cleanup failure was lost behind an authority observation", result.err)
				}
			} else if inspections != 1 || p.rebind != nil || p.recoveryState != connectorRebinding {
				t.Error("expired operation did not reconcile its current owner", result.err)
			}
			for _, session := range sessions {
				if session.closes.Load() != 1 {
					t.Error("expiry acquired a second physical closing owner")
				}
			}
		})
	}
}

func TestConnectorRecoveryResultDefaultsToStop(t *testing.T) {
	if (connectorRecoveryResult{}).retry {
		t.Fatal("a zero recovery result permitted retry")
	}
	independent := errors.New("independent operation")
	if connectorRecoveryControlResult(errors.Join(io.ErrUnexpectedEOF, independent)).retry {
		t.Fatal("an arbitrary aggregate acquired an explicit retry disposition")
	}
	if connectorReconnectError(&connectorLegAttemptError{}) != terminateConnection {
		t.Fatal("an empty owned attempt supplied retry evidence")
	}
	canceled := errors.New("owned stop cause")
	if !connectorOwnedCancellationOnly(errors.Join(context.Canceled, fmt.Errorf("call: %w", canceled)), canceled) {
		t.Fatal("pure owned cancellation acquired an independent failure")
	}
	for _, cleanup := range []error{
		&CleanupError{Err: context.Canceled},
		&tunnel.SessionCleanupError{Err: context.Canceled},
		&muxsession.QUICTransportCloseError{Err: context.Canceled},
	} {
		if connectorOwnedCancellationOnly(errors.Join(canceled, cleanup), canceled) {
			t.Fatal("owned cancellation hid typed physical cleanup", cleanup)
		}
	}
	if connectorOwnedCancellationOnly(errors.Join(canceled, io.EOF), canceled) {
		t.Fatal("owned cancellation hid an independent operation")
	}
}

func TestConnectorPendingCanceledRecoveryRetainsIndependentCleanup(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		budget, stop := context.WithTimeout(t.Context(), 5*time.Second)
		defer stop()
		p, op := pendingRetryOwner(t, budget)
		entered, release := make(chan struct{}), make(chan struct{})
		unblock := sync.OnceFunc(func() { close(release) })
		defer unblock()
		physical := &muxsession.QUICTransportCloseError{Err: context.Canceled}
		canceled := errors.New("owner canceled pending recovery")
		session := newLegRetrySession(t, budget, op.pair, 0, legRetryScript{closeErr: physical, closeEntered: entered, closeRelease: release})
		p.config = Config{
			RelayQUIC: muxsession.ConnectorFunc(func(_ context.Context, endpoint muxsession.Endpoint) (muxsession.Session, error) {
				if endpoint.Address == op.pair.Relays[0].RelayAddress {
					return session, nil
				}
				return nil, errors.New("second slot did not connect")
			}),
			RelayTCP: muxsession.ConnectorFunc(func(context.Context, muxsession.Endpoint) (muxsession.Session, error) {
				return nil, errors.New("alternate did not connect")
			}),
		}
		done := startPendingRetryRefresh(t, p)
		assertLegRetryHello(t, budget, session)
		select {
		case <-entered:
		case <-budget.Done():
			t.Fatal("pending cleanup did not enter within the case budget")
		}
		p.cancel(canceled)
		synctest.Wait()
		select {
		case <-done:
			t.Error("canceled coordinator returned before joining candidate cleanup")
		default:
		}
		unblock()
		select {
		case <-done:
		case <-budget.Done():
			t.Fatal("canceled coordinator did not join within the case budget")
		}
		p.mu.Lock()
		cleanup := p.useErr
		p.mu.Unlock()
		if !errors.Is(context.Cause(p.ctx), canceled) || !errors.Is(cleanup, physical) ||
			!errors.Is(cleanup, io.ErrUnexpectedEOF) || session.closes.Load() != 1 || op.legs != [2]*connectorRelayLeg{} {
			t.Error("owner cancellation discarded an independent pending operation or physical cleanup", cleanup)
		}
	})
}

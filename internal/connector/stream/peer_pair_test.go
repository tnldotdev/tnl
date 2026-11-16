package stream

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	clientcontrol "github.com/tnldotdev/tnl/internal/client/control"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/transport/muxsession"
	"github.com/tnldotdev/tnl/internal/transport/peer"
	"github.com/tnldotdev/tnl/internal/transport/tunnel"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

// this transport script serves a framed hello and optionally loses one activation
// reply. it models neither recovery, publisher authorization, nor packet forwarding.
type legRetryScript struct {
	response     tunnelv1.MessageType
	code         tunnelv1.ErrorCode
	readErr      error
	closeErr     error
	closeEntered chan struct{}
	closeRelease <-chan struct{}
	clearEntered chan struct{}
	clearRelease <-chan struct{}
	activation   bool
}

type legRetrySession struct {
	ctx          context.Context
	local, peer  net.Conn
	script       legRetryScript
	hello        chan tunnelv1.ConnectorPairLegProof
	activation   chan tunnelv1.ConnectorLegBinding
	served, done chan struct{}
	serveErr     error
	closeErr     error
	once         sync.Once
	opens        atomic.Int32
	closes       atomic.Int32
}

func newLegRetrySession(t *testing.T, ctx context.Context, pair controlv1.ConnectorPeerPair, slot int, script legRetryScript) *legRetrySession {
	t.Helper()
	local, remote := net.Pipe()
	s := &legRetrySession{ctx: ctx, local: local, peer: remote, script: script,
		hello: make(chan tunnelv1.ConnectorPairLegProof, 1), activation: make(chan tunnelv1.ConnectorLegBinding, 1),
		served: make(chan struct{}), done: make(chan struct{})}
	until, _ := ctx.Deadline()
	if err := remote.SetDeadline(until); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close(); <-s.served })
	go func() {
		defer close(s.served)
		defer remote.Close()
		message, err := tunnelv1.ReadControl(remote)
		if err != nil {
			s.serveErr = err
			return
		}
		proof := message.ConnectorPairLegProof
		if message.Role != tunnelv1.Connector || proof == nil || proof.PairID != pair.PairId ||
			proof.DeliveryGeneration != pair.DeliveryGeneration || proof.ConnectionSlot != slot {
			s.serveErr = errors.New("fixture received a different connector hello")
			return
		}
		s.hello <- *proof
		if script.response == "" {
			_, s.serveErr = remote.Write([]byte{0})
			return
		}
		response := tunnelv1.Message{Type: script.response, ProtocolVersion: tunnelv1.Version, Code: script.code}
		if script.response == tunnelv1.HelloAccepted {
			response.ConnectorPairLegAccepted = &tunnelv1.ConnectorPairLegAccepted{PairID: pair.PairId, DeliveryID: pair.DeliveryId,
				DeliveryGeneration: pair.DeliveryGeneration, BindingState: tunnelv1.ConnectorPeerLegBindingPrepared,
				ConnectionSlot: slot, SourceIP: "192.0.2.1", ObservedAt: time.Now().UTC().Truncate(time.Microsecond), ExpiresAt: pair.ExpiresAt}
		}
		s.serveErr = tunnelv1.WriteControl(remote, response)
		if s.serveErr == nil && script.activation {
			request, err := tunnelv1.ReadControl(remote)
			if err != nil {
				s.serveErr = err
				return
			}
			if request.Type != tunnelv1.ConnectorLegActivate || request.ConnectorLegBinding == nil {
				s.serveErr = errors.New("fixture expected one connector activation")
				return
			}
			s.activation <- *request.ConnectorLegBinding
			_, s.serveErr = remote.Write([]byte{0})
			return
		}
		if s.serveErr == nil {
			select {
			case <-s.done:
			case <-ctx.Done():
			}
		}
	}()
	return s
}

func (s *legRetrySession) OpenStream(ctx context.Context) (muxsession.Stream, error) {
	if cause := context.Cause(ctx); cause != nil {
		return nil, cause
	}
	if s.opens.Add(1) != 1 {
		return nil, errors.New("fixture permits one control stream")
	}
	return legRetryControl{Conn: s.local, readErr: s.script.readErr, ctx: s.ctx,
		clearEntered: s.script.clearEntered, clearRelease: s.script.clearRelease}, nil
}

func (s *legRetrySession) AcceptStream(ctx context.Context) (muxsession.Stream, error) {
	select {
	case <-ctx.Done():
		return nil, context.Cause(ctx)
	case <-s.done:
		return nil, muxsession.ErrClosed
	}
}

func (s *legRetrySession) Close() error {
	s.closes.Add(1)
	s.once.Do(func() {
		if s.script.closeEntered != nil {
			close(s.script.closeEntered)
		}
		if s.script.closeRelease != nil {
			select {
			case <-s.script.closeRelease:
			case <-s.ctx.Done():
			}
		}
		s.closeErr = errors.Join(s.local.Close(), s.peer.Close(), s.script.closeErr)
		close(s.done)
	})
	return s.closeErr
}

func (s *legRetrySession) Done() <-chan struct{} { return s.done }
func (s *legRetrySession) Err() error {
	select {
	case <-s.done:
		return muxsession.ErrClosed
	default:
		return nil
	}
}
func (*legRetrySession) SupportsDatagrams() bool { return true }
func (*legRetrySession) SendDatagram(context.Context, []byte) error {
	return errors.New("fixture does not forward packets")
}
func (s *legRetrySession) ReceiveDatagram(ctx context.Context) ([]byte, error) {
	select {
	case <-ctx.Done():
		return nil, context.Cause(ctx)
	case <-s.done:
		return nil, muxsession.ErrClosed
	}
}

type legRetryControl struct {
	net.Conn
	readErr      error
	ctx          context.Context
	clearEntered chan struct{}
	clearRelease <-chan struct{}
}

func (s legRetryControl) SetDeadline(at time.Time) error {
	if at.IsZero() && s.clearEntered != nil {
		close(s.clearEntered)
		select {
		case <-s.clearRelease:
		case <-s.ctx.Done():
		}
	}
	return s.Conn.SetDeadline(at)
}

func (s legRetryControl) Read(p []byte) (int, error) {
	n, err := s.Conn.Read(p)
	if err != nil && s.readErr != nil {
		return n, errors.Join(err, s.readErr)
	}
	return n, err
}
func (legRetryControl) CloseWrite() error    { return nil }
func (s legRetryControl) Reset(uint32) error { return s.Close() }

func legRetryConfig(helloTransport string, session *legRetrySession, alternate error, calls *[2]atomic.Int32) Config {
	hello := muxsession.ConnectorFunc(func(context.Context, muxsession.Endpoint) (muxsession.Session, error) {
		calls[0].Add(1)
		return session, nil
	})
	failed := muxsession.ConnectorFunc(func(context.Context, muxsession.Endpoint) (muxsession.Session, error) {
		calls[1].Add(1)
		return nil, alternate
	})
	if helloTransport == "quic" {
		return Config{RelayQUIC: hello, RelayTCP: failed}
	}
	return Config{RelayQUIC: failed, RelayTCP: hello}
}

func assertLegRetryHello(t *testing.T, ctx context.Context, s *legRetrySession) {
	t.Helper()
	select {
	case proof := <-s.hello:
		if err := proof.Validate(); err != nil {
			t.Fatal("dial did not send a valid signed hello", err)
		}
	case <-ctx.Done():
		t.Fatal("dial did not reach its hello within the case budget", context.Cause(ctx))
	}
}

func TestConnectorLegDialLostHelloRetainsOwnedRetryEvidence(t *testing.T) {
	for _, transport := range []string{"quic", "tls-tcp"} {
		t.Run(transport, func(t *testing.T) {
			ctx, stop := context.WithTimeout(t.Context(), 5*time.Second)
			defer stop()
			signer, _, pair, _, _ := rebindFixture(t)
			session := newLegRetrySession(t, ctx, pair, 0, legRetryScript{})
			alternate := errors.New("alternate transport did not connect")
			var calls [2]atomic.Int32
			leg, err := dialConnectorLeg(ctx, ctx, legRetryConfig(transport, session, alternate, &calls),
				signer, pair, [32]byte{1}, 0, nil, tunnelv1.ConnectorHandoffID{1})
			assertLegRetryHello(t, ctx, session)
			if leg != nil || !errors.Is(err, io.ErrUnexpectedEOF) || !errors.Is(err, alternate) ||
				calls[0].Load() != 1 || calls[1].Load() != 1 || session.closes.Load() != 1 {
				t.Fatal("dial lost a candidate failure, exposed a leg, or changed the attempt budget", err)
			}
			if connectorReconnectError(err) != retryAttempt {
				t.Error("owned lost hello could not retry through the other transport's pre-session failure", err)
			}
			// this raw aggregate must stay strict; the owner needs provenance, not
			// a broader EOF classifier. refresh behavior is tested at its boundary.
			if connectorTemporary(errors.Join(io.ErrUnexpectedEOF, alternate)) {
				t.Error("an arbitrary aggregate acquired retry permission")
			}
			independent := errors.New("independent caller failure")
			if connectorReconnectError(errors.Join(err, independent)) != terminateConnection {
				t.Error("a nested owned attempt promoted an unrelated caller failure")
			}
		})
	}
}

func TestConnectorLegDialIndependentOperationVetoesRetry(t *testing.T) {
	for _, transport := range []string{"quic", "tls-tcp"} {
		for _, stage := range []string{"connect", "hello"} {
			t.Run(transport+"/"+stage, func(t *testing.T) {
				ctx, stop := context.WithTimeout(t.Context(), 5*time.Second)
				defer stop()
				signer, _, pair, _, _ := rebindFixture(t)
				independent, alternate := errors.New("independent operation failed"), errors.New("alternate did not connect")
				script := legRetryScript{}
				if stage == "hello" {
					script.readErr = errors.Join(io.ErrUnexpectedEOF, independent)
				} else {
					alternate = errors.Join(io.ErrUnexpectedEOF, independent)
				}
				session := newLegRetrySession(t, ctx, pair, 0, script)
				var calls [2]atomic.Int32
				leg, err := dialConnectorLeg(ctx, ctx, legRetryConfig(transport, session, alternate, &calls),
					signer, pair, [32]byte{1}, 0, nil, tunnelv1.ConnectorHandoffID{1})
				assertLegRetryHello(t, ctx, session)
				if leg != nil || !errors.Is(err, independent) || !errors.Is(err, io.ErrUnexpectedEOF) ||
					connectorReconnectError(err) != terminateConnection {
					t.Error("a raced EOF hid an independent operation failure", err)
				}
			})
		}
	}
}

func TestConnectorLegDialTypedFailureVetoesRetry(t *testing.T) {
	for _, transport := range []string{"quic", "tls-tcp"} {
		for _, kind := range []string{"connector cleanup", "session cleanup", "physical cleanup", "HTTP denial", "reasoned denial"} {
			t.Run(transport+"/"+kind, func(t *testing.T) {
				ctx, stop := context.WithTimeout(t.Context(), 5*time.Second)
				defer stop()
				signer, _, pair, _, _ := rebindFixture(t)
				independent := errors.New("independent failure")
				cause := errors.Join(io.ErrUnexpectedEOF, independent)
				var wrap func(error) error
				switch kind {
				case "connector cleanup":
					wrap = func(err error) error { return &CleanupError{Err: err} }
				case "session cleanup":
					wrap = func(err error) error { return &tunnel.SessionCleanupError{Err: err} }
				case "physical cleanup":
					wrap = func(err error) error { return &muxsession.QUICTransportCloseError{Err: err} }
				case "HTTP denial":
					wrap = func(err error) error { return errors.Join(&clientcontrol.ProblemError{Status: 403}, err) }
				case "reasoned denial":
					wrap = func(err error) error { return failure.Wrap("candidate", failure.ServerDenied, err) }
				}
				alternate := wrap(cause)
				session := newLegRetrySession(t, ctx, pair, 0, legRetryScript{})
				var calls [2]atomic.Int32
				leg, err := dialConnectorLeg(ctx, ctx, legRetryConfig(transport, session, alternate, &calls),
					signer, pair, [32]byte{1}, 0, nil, tunnelv1.ConnectorHandoffID{1})
				assertLegRetryHello(t, ctx, session)
				if leg != nil || !errors.Is(err, alternate) || !errors.Is(err, independent) ||
					connectorReconnectError(err) != terminateConnection || connectorTemporary(err) {
					t.Error("owned cleanup or denial became retryable through a sibling hello", err)
				}
				if connectorTemporary(wrap(io.ErrUnexpectedEOF)) {
					t.Error("the typed cleanup/denial marker itself allowed its EOF payload to retry")
				}
			})
		}
	}
}

func TestConnectorLegDialProtocolDenialVetoesSiblingEOF(t *testing.T) {
	for _, transport := range []string{"quic", "tls-tcp"} {
		t.Run(transport, func(t *testing.T) {
			ctx, stop := context.WithTimeout(t.Context(), 5*time.Second)
			defer stop()
			signer, _, pair, _, _ := rebindFixture(t)
			session := newLegRetrySession(t, ctx, pair, 0, legRetryScript{response: tunnelv1.Error, code: tunnelv1.Unauthenticated})
			var calls [2]atomic.Int32
			leg, err := dialConnectorLeg(ctx, ctx, legRetryConfig(transport, session, io.ErrUnexpectedEOF, &calls),
				signer, pair, [32]byte{1}, 0, nil, tunnelv1.ConnectorHandoffID{1})
			assertLegRetryHello(t, ctx, session)
			var denial *tunnel.ProtocolError
			if leg != nil || !errors.As(err, &denial) || denial.Code != tunnelv1.Unauthenticated ||
				!errors.Is(err, io.ErrUnexpectedEOF) || connectorReconnectError(err) != terminateConnection || connectorTemporary(err) {
				t.Error("delivered hello denial lost precedence over the sibling EOF", err)
			}
		})
	}
}

func TestConnectorLegDialJoinsCleanupBeforeExposingWinner(t *testing.T) {
	for _, winnerTransport := range []string{"quic", "tls-tcp"} {
		for _, failedClose := range []bool{false, true} {
			name := winnerTransport + "/clean-close"
			if failedClose {
				name = winnerTransport + "/failed-close"
			}
			t.Run(name, func(t *testing.T) {
				synctest.Test(t, func(t *testing.T) {
					ctx, stop := context.WithTimeout(t.Context(), 5*time.Second)
					defer stop()
					signer, _, pair, _, _ := rebindFixture(t)
					entered, release := make(chan struct{}), make(chan struct{})
					unblock := sync.OnceFunc(func() { close(release) })
					defer unblock()
					loserErr, winnerErr := errors.New("loser physical close failed"), errors.New("winner physical close failed")
					loserScript := legRetryScript{closeEntered: entered, closeRelease: release}
					winnerScript := legRetryScript{response: tunnelv1.HelloAccepted}
					if failedClose {
						loserScript.closeErr, winnerScript.closeErr = loserErr, winnerErr
					}
					loser := newLegRetrySession(t, ctx, pair, 0, loserScript)
					winner := newLegRetrySession(t, ctx, pair, 0, winnerScript)
					losing := muxsession.ConnectorFunc(func(context.Context, muxsession.Endpoint) (muxsession.Session, error) { return loser, nil })
					winning := muxsession.ConnectorFunc(func(call context.Context, _ muxsession.Endpoint) (muxsession.Session, error) {
						select {
						case <-entered:
							return winner, nil
						case <-call.Done():
							return nil, context.Cause(call)
						}
					})
					config := Config{RelayQUIC: losing, RelayTCP: winning}
					if winnerTransport == "quic" {
						config.RelayQUIC, config.RelayTCP = winning, losing
					}
					done := make(chan struct{})
					var leg *connectorRelayLeg
					var err error
					go func() {
						defer close(done)
						leg, err = dialConnectorLeg(ctx, ctx, config, signer, pair, [32]byte{1}, 0, nil, tunnelv1.ConnectorHandoffID{1})
					}()
					defer func() { unblock(); stop(); <-done }()
					assertLegRetryHello(t, ctx, loser)
					assertLegRetryHello(t, ctx, winner)
					synctest.Wait()
					select {
					case <-done:
						t.Error("dial returned before its losing candidate finished physical cleanup")
					default:
					}
					unblock()
					select {
					case <-done:
					case <-ctx.Done():
						t.Fatal("dial did not join released cleanup within the case budget")
					}
					if leg != nil {
						defer leg.Close()
					}
					if !failedClose {
						if leg == nil || err != nil {
							t.Error("successful losing cleanup prevented ordinary fallback", err)
						}
					} else if leg != nil || !errors.Is(err, io.ErrUnexpectedEOF) || !errors.Is(err, loserErr) ||
						!errors.Is(err, winnerErr) || winner.closes.Load() != 1 || connectorReconnectError(err) != terminateConnection {
						t.Error("failed losing cleanup exposed the winner or lost operation/cleanup causes", err)
					}
				})
			})
		}
	}
}

func TestConnectorLegDialCancellationJoinsLateSession(t *testing.T) {
	for _, withCleanupFailure := range []bool{false, true} {
		name := "clean-close"
		if withCleanupFailure {
			name = "failed-close"
		}
		t.Run(name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				budget, stop := context.WithTimeout(t.Context(), 5*time.Second)
				defer stop()
				ctx, cancel := context.WithCancelCause(budget)
				defer cancel(nil)
				signer, _, pair, _, _ := rebindFixture(t)
				script := legRetryScript{}
				physical := &muxsession.QUICTransportCloseError{Err: errors.New("late session physical close failed")}
				if withCleanupFailure {
					script.closeErr = physical
				}
				session := newLegRetrySession(t, budget, pair, 0, script)
				fallbackEntered, canceled, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
				unblock := sync.OnceFunc(func() { close(release) })
				defer unblock()
				primary := muxsession.ConnectorFunc(func(call context.Context, _ muxsession.Endpoint) (muxsession.Session, error) {
					<-call.Done()
					close(canceled)
					select {
					case <-release:
						return session, nil
					case <-budget.Done():
						return nil, context.Cause(budget)
					}
				})
				fallback := muxsession.ConnectorFunc(func(call context.Context, _ muxsession.Endpoint) (muxsession.Session, error) {
					close(fallbackEntered)
					<-call.Done()
					return nil, context.Cause(call)
				})
				done := make(chan struct{})
				var leg *connectorRelayLeg
				var err error
				go func() {
					defer close(done)
					leg, err = dialConnectorLeg(ctx, budget, Config{RelayQUIC: primary, RelayTCP: fallback},
						signer, pair, [32]byte{1}, 0, nil, tunnelv1.ConnectorHandoffID{1})
				}()
				defer func() { unblock(); cancel(nil); <-done }()
				select {
				case <-fallbackEntered:
				case <-budget.Done():
					t.Fatal("fallback did not enter within the case budget")
				}
				cause := errors.New("connector owner canceled the attempt")
				cancel(cause)
				<-canceled
				synctest.Wait()
				select {
				case <-done:
					t.Error("canceled dial returned before joining the late candidate")
				default:
				}
				unblock()
				select {
				case <-done:
				case <-budget.Done():
					t.Fatal("late candidate did not join within the case budget")
				}
				if leg != nil {
					_ = leg.Close()
					t.Error("canceled dial installed a late leg")
				}
				if !errors.Is(err, cause) || session.closes.Load() != 1 || session.opens.Load() != 0 {
					t.Error("late canceled session was opened, leaked, or lost the cancellation cause", err)
				}
				if withCleanupFailure && (!errors.Is(err, physical) || connectorReconnectError(err) != terminateConnection) {
					t.Error("owned cancellation hid independent physical cleanup", err)
				}
			})
		})
	}
}

func TestConnectorLegDialAuthenticatedLoserCleanup(t *testing.T) {
	for _, winnerTransport := range []string{"quic", "tls-tcp"} {
		for _, failedClose := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/failed-close=%t", winnerTransport, failedClose), func(t *testing.T) {
				synctest.Test(t, func(t *testing.T) {
					ctx, stop := context.WithTimeout(t.Context(), 5*time.Second)
					defer stop()
					signer, _, pair, _, _ := rebindFixture(t)
					entered, release := make(chan struct{}), make(chan struct{})
					unblock := sync.OnceFunc(func() { close(release) })
					defer unblock()
					loserErr, winnerErr := errors.New("authenticated loser close failed"), errors.New("selected winner close failed")
					loserScript := legRetryScript{response: tunnelv1.HelloAccepted, clearEntered: entered, clearRelease: release}
					winnerScript := legRetryScript{response: tunnelv1.HelloAccepted}
					if failedClose {
						loserScript.closeErr, winnerScript.closeErr = loserErr, winnerErr
					}
					loser := newLegRetrySession(t, ctx, pair, 0, loserScript)
					winner := newLegRetrySession(t, ctx, pair, 0, winnerScript)
					losing := muxsession.ConnectorFunc(func(context.Context, muxsession.Endpoint) (muxsession.Session, error) { return loser, nil })
					winning := muxsession.ConnectorFunc(func(call context.Context, _ muxsession.Endpoint) (muxsession.Session, error) {
						select {
						case <-entered:
							return winner, nil
						case <-call.Done():
							return nil, context.Cause(call)
						}
					})
					config := Config{RelayQUIC: losing, RelayTCP: winning}
					if winnerTransport == "quic" {
						config.RelayQUIC, config.RelayTCP = winning, losing
					}
					done := make(chan struct{})
					var leg *connectorRelayLeg
					var err error
					go func() {
						defer close(done)
						leg, err = dialConnectorLeg(ctx, ctx, config, signer, pair, [32]byte{1}, 0, nil, tunnelv1.ConnectorHandoffID{1})
					}()
					defer func() { unblock(); stop(); <-done }()
					assertLegRetryHello(t, ctx, loser)
					assertLegRetryHello(t, ctx, winner)
					synctest.Wait()
					select {
					case <-done:
						t.Error("winner escaped before the authenticated loser joined")
					default:
					}
					unblock()
					select {
					case <-done:
					case <-ctx.Done():
						t.Fatal("authenticated loser did not join within the case budget")
					}
					if leg != nil {
						defer leg.Close()
					}
					if loser.closes.Load() != 1 {
						t.Error("authenticated loser did not have one closing owner")
					}
					if failedClose {
						if leg != nil || !errors.Is(err, loserErr) || !errors.Is(err, winnerErr) ||
							winner.closes.Load() != 1 || connectorReconnectError(err) != terminateConnection {
							t.Error("authenticated loser cleanup exposed a winner or lost either close failure", err)
						}
					} else if leg == nil || err != nil || winner.closes.Load() != 0 {
						t.Error("ordinary authenticated loser cancellation prevented fallback", err)
					}
				})
			})
		}
	}
}

func TestConnectorLegDialUnownedWinnerRetainsCleanup(t *testing.T) {
	for _, transport := range []string{"quic", "tls-tcp"} {
		t.Run(transport, func(t *testing.T) {
			ctx, stop := context.WithTimeout(t.Context(), 5*time.Second)
			defer stop()
			lifetime, cancel := context.WithCancel(ctx)
			cancel()
			signer, _, pair, _, _ := rebindFixture(t)
			physical := errors.New("unowned winner close failed")
			session := newLegRetrySession(t, ctx, pair, 0, legRetryScript{response: tunnelv1.HelloAccepted, closeErr: physical})
			var calls [2]atomic.Int32
			leg, err := dialConnectorLeg(ctx, lifetime, legRetryConfig(transport, session, errors.New("alternate did not connect"), &calls),
				signer, pair, [32]byte{1}, 0, nil, tunnelv1.ConnectorHandoffID{1})
			assertLegRetryHello(t, ctx, session)
			var cleanup *CleanupError
			if leg != nil || !errors.Is(err, peer.ErrConfiguration) || !errors.Is(err, physical) ||
				!errors.As(err, &cleanup) || session.closes.Load() != 1 || connectorReconnectError(err) != terminateConnection {
				t.Fatal("unowned winner lost operation/cleanup provenance", err)
			}
			if errors.Is(cleanup, peer.ErrConfiguration) {
				t.Error("unowned winner cleanup marker contains its independent operation")
			}
		})
	}
}

type legRetryWithoutDatagrams struct{ muxsession.Session }

func TestConnectorLegDialCapabilityFailureRetainsCleanup(t *testing.T) {
	ctx, stop := context.WithTimeout(t.Context(), 5*time.Second)
	defer stop()
	signer, _, pair, _, _ := rebindFixture(t)
	physical := errors.New("incapable transport close failed")
	incapable := newLegRetrySession(t, ctx, pair, 0, legRetryScript{closeErr: physical})
	hello := newLegRetrySession(t, ctx, pair, 0, legRetryScript{})
	config := Config{
		RelayQUIC: muxsession.ConnectorFunc(func(context.Context, muxsession.Endpoint) (muxsession.Session, error) {
			return legRetryWithoutDatagrams{Session: incapable}, nil
		}),
		RelayTCP: muxsession.ConnectorFunc(func(context.Context, muxsession.Endpoint) (muxsession.Session, error) { return hello, nil }),
	}
	leg, err := dialConnectorLeg(ctx, ctx, config, signer, pair, [32]byte{1}, 0, nil, tunnelv1.ConnectorHandoffID{1})
	assertLegRetryHello(t, ctx, hello)
	if leg != nil || !errors.Is(err, peer.ErrConfiguration) || !errors.Is(err, physical) ||
		!errors.Is(err, io.ErrUnexpectedEOF) || incapable.opens.Load() != 0 || incapable.closes.Load() != 1 ||
		connectorReconnectError(err) != terminateConnection {
		t.Error("capability failure or its physical cleanup became a retryable sibling EOF", err)
	}
}

func TestConnectorLegDialCapacityRetainsOwnedRetryDecision(t *testing.T) {
	for _, transport := range []string{"quic", "tls-tcp"} {
		t.Run(transport, func(t *testing.T) {
			ctx, stop := context.WithTimeout(t.Context(), 5*time.Second)
			defer stop()
			signer, _, pair, _, _ := rebindFixture(t)
			session := newLegRetrySession(t, ctx, pair, 0, legRetryScript{response: tunnelv1.Error, code: tunnelv1.CapacityExceeded})
			var calls [2]atomic.Int32
			alternate := errors.New("alternate did not connect")
			leg, err := dialConnectorLeg(ctx, ctx, legRetryConfig(transport, session, alternate, &calls),
				signer, pair, [32]byte{1}, 0, nil, tunnelv1.ConnectorHandoffID{1})
			assertLegRetryHello(t, ctx, session)
			var capacity *tunnel.ProtocolError
			if leg != nil || !errors.As(err, &capacity) || capacity.Code != tunnelv1.CapacityExceeded ||
				!errors.Is(err, alternate) || connectorReconnectError(err) != retryAttempt {
				t.Error("capacity lost the owned bounded retry decision", err)
			}
		})
	}
}

func TestConnectorLegDialWinnerCancellationRetainsIndependentLoser(t *testing.T) {
	for _, boundary := range []string{"owned cancellation", "independent operation", "physical cleanup"} {
		t.Run(boundary, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				ctx, stop := context.WithTimeout(t.Context(), 5*time.Second)
				defer stop()
				signer, _, pair, _, _ := rebindFixture(t)
				independent := errors.New("loser failed independently of cancellation")
				script := legRetryScript{response: tunnelv1.HelloAccepted}
				winner := newLegRetrySession(t, ctx, pair, 0, script)
				entered := make(chan struct{})
				losing := muxsession.ConnectorFunc(func(call context.Context, _ muxsession.Endpoint) (muxsession.Session, error) {
					close(entered)
					<-call.Done()
					err := context.Cause(call)
					switch boundary {
					case "independent operation":
						err = errors.Join(err, independent)
					case "physical cleanup":
						err = errors.Join(err, &muxsession.QUICTransportCloseError{Err: errors.Join(io.EOF, independent)})
					}
					return nil, err
				})
				winning := muxsession.ConnectorFunc(func(call context.Context, _ muxsession.Endpoint) (muxsession.Session, error) {
					select {
					case <-entered:
						return winner, nil
					case <-call.Done():
						return nil, context.Cause(call)
					}
				})
				leg, err := dialConnectorLeg(ctx, ctx, Config{RelayQUIC: losing, RelayTCP: winning},
					signer, pair, [32]byte{1}, 0, nil, tunnelv1.ConnectorHandoffID{1})
				assertLegRetryHello(t, ctx, winner)
				if leg != nil {
					defer leg.Close()
				}
				if boundary == "owned cancellation" {
					if leg == nil || err != nil || winner.closes.Load() != 0 {
						t.Error("ordinary losing-candidate cancellation prevented the authenticated winner", err)
					}
				} else if leg != nil || !errors.Is(err, context.Canceled) || !errors.Is(err, independent) ||
					winner.closes.Load() != 1 || connectorReconnectError(err) != terminateConnection {
					t.Error("winner cancellation discarded an independent loser operation or cleanup", err)
				}
			})
		})
	}
}

type legRetryCloseOrder struct {
	peer.Carrier
	stopped            <-chan struct{}
	err                error
	closes             atomic.Int32
	stoppedBeforeClose bool
}

func (c *legRetryCloseOrder) Close() error {
	c.closes.Add(1)
	var order error
	select {
	case <-c.stopped:
		c.stoppedBeforeClose = true
	default:
		order = errors.New("packet registration closed before its transport stopped")
	}
	return errors.Join(order, c.Carrier.Close(), c.err)
}

func TestConnectorLegCloseStopsTransportAndRetainsEachFailure(t *testing.T) {
	ctx, stop := context.WithTimeout(t.Context(), 5*time.Second)
	defer stop()
	signer, _, pair, _, _ := rebindFixture(t)
	physical, registration := errors.New("transport close failed"), errors.New("packet registration close failed")
	session := newLegRetrySession(t, ctx, pair, 0, legRetryScript{response: tunnelv1.HelloAccepted, closeErr: physical})
	var calls [2]atomic.Int32
	leg, err := dialConnectorLeg(ctx, ctx, legRetryConfig("quic", session, errors.New("alternate did not connect"), &calls),
		signer, pair, [32]byte{1}, 0, nil, tunnelv1.ConnectorHandoffID{1})
	if err != nil {
		t.Fatal(err)
	}
	assertLegRetryHello(t, ctx, session)
	carrier := &legRetryCloseOrder{Carrier: leg.carrier, stopped: session.Done(), err: registration}
	leg.carrier = carrier
	closed := leg.Close()
	repeated := leg.Close()
	if !errors.Is(closed, physical) || !errors.Is(closed, registration) || !errors.Is(repeated, physical) ||
		!errors.Is(repeated, registration) || carrier.closes.Load() != 1 || session.closes.Load() != 1 {
		t.Error("leg cleanup lost a failure or acquired a second closing owner", closed, repeated)
	}
	if !carrier.stoppedBeforeClose {
		t.Error("leg cleanup joined packet registrations before stopping transport i/o", closed)
	}
}

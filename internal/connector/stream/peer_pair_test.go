package stream

import (
	"bytes"
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

	quic "github.com/quic-go/quic-go"
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

// this fixture serves real control frames but can end the whole session at one
// response read. ending the session and physically closing it are separate events.
type legOriginScript struct {
	phase       connectorAttemptStage
	operation   error
	ended       bool
	sessionErr  error
	closeErr    error
	reply       tunnelv1.ErrorCode
	finishCause error
	waitExpiry  bool
}

type legOriginSession struct {
	local, remote net.Conn
	script        legOriginScript
	call          context.Context
	cancel        context.CancelCauseFunc
	hello         chan tunnelv1.ConnectorPairLegProof
	activation    chan tunnelv1.ConnectorLegBinding
	atResponse    chan struct{}
	done, served  chan struct{}
	endOnce       sync.Once
	closeOnce     sync.Once
	mu            sync.Mutex
	sessionErr    error
	physicalErr   error
	serveErr      error
	beforeDone    bool
	beforeErr     error
	beforeCause   error
	raw           error
	closes        atomic.Int32
	opens         atomic.Int32
	reads         atomic.Int32
	writes        atomic.Int32
}

func newLegOriginSession(t *testing.T, call context.Context, cancel context.CancelCauseFunc, pair controlv1.ConnectorPeerPair, script legOriginScript) *legOriginSession {
	t.Helper()
	local, remote := net.Pipe()
	s := &legOriginSession{local: local, remote: remote, script: script, call: call, cancel: cancel,
		hello: make(chan tunnelv1.ConnectorPairLegProof, 1), activation: make(chan tunnelv1.ConnectorLegBinding, 1),
		atResponse: make(chan struct{}), done: make(chan struct{}), served: make(chan struct{})}
	until, _ := call.Deadline()
	if err := remote.SetDeadline(until); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = s.Close()
		<-s.served
	})
	go func() {
		defer close(s.served)
		defer remote.Close()
		message, err := tunnelv1.ReadControl(remote)
		if err != nil {
			s.serveErr = err
			return
		}
		proof := message.ConnectorPairLegProof
		if message.Type != tunnelv1.Hello || proof == nil || proof.PairID != pair.PairId || proof.ConnectionSlot != 0 {
			s.serveErr = errors.New("origin fixture received a different hello")
			return
		}
		s.hello <- *proof
		if script.phase == connectorAttemptHello {
			close(s.atResponse)
			if script.reply != "" {
				s.serveErr = tunnelv1.WriteControl(remote, tunnelv1.Message{Type: tunnelv1.Error,
					ProtocolVersion: tunnelv1.Version, Code: script.reply})
			}
			return
		}
		receipt := tunnelv1.ConnectorPairLegAccepted{PairID: pair.PairId, DeliveryID: pair.DeliveryId,
			DeliveryGeneration: pair.DeliveryGeneration, BindingState: tunnelv1.ConnectorPeerLegBindingPrepared,
			ConnectionSlot: 0, SourceIP: "192.0.2.1", ObservedAt: time.Now().UTC().Truncate(time.Microsecond), ExpiresAt: pair.ExpiresAt}
		if s.serveErr = tunnelv1.WriteControl(remote, tunnelv1.Message{Type: tunnelv1.HelloAccepted,
			ProtocolVersion: tunnelv1.Version, ConnectorPairLegAccepted: &receipt}); s.serveErr != nil {
			return
		}
		request, err := tunnelv1.ReadControl(remote)
		if err != nil {
			s.serveErr = err
			return
		}
		if request.Type != tunnelv1.ConnectorLegActivate || request.ConnectorLegBinding == nil {
			s.serveErr = errors.New("origin fixture expected one activation")
			return
		}
		s.activation <- *request.ConnectorLegBinding
		close(s.atResponse)
		if script.reply != "" {
			s.serveErr = tunnelv1.WriteControl(remote, tunnelv1.Message{Type: tunnelv1.Error,
				ProtocolVersion: tunnelv1.Version, RequestID: request.RequestID, Code: script.reply})
		}
	}()
	return s
}

func (s *legOriginSession) end(err error) {
	s.endOnce.Do(func() {
		s.mu.Lock()
		s.sessionErr = err
		s.mu.Unlock()
		close(s.done)
	})
}

func (s *legOriginSession) failResponse() error {
	select {
	case <-s.atResponse:
	case <-s.call.Done():
		return context.Cause(s.call)
	}
	s.mu.Lock()
	s.raw = s.script.operation
	s.sessionErr = s.script.sessionErr
	s.mu.Unlock()
	if s.script.ended {
		s.end(s.script.sessionErr)
	}
	if s.script.waitExpiry {
		<-s.call.Done()
	}
	if s.script.finishCause != nil {
		s.cancel(s.script.finishCause)
	}
	return s.script.operation
}

func (s *legOriginSession) OpenStream(ctx context.Context) (muxsession.Stream, error) {
	if cause := context.Cause(ctx); cause != nil {
		return nil, cause
	}
	if s.opens.Add(1) != 1 {
		return nil, errors.New("origin fixture permits one physical control")
	}
	return &legOriginControl{Conn: s.local, owner: s}, nil
}

func (s *legOriginSession) AcceptStream(ctx context.Context) (muxsession.Stream, error) {
	select {
	case <-ctx.Done():
		return nil, context.Cause(ctx)
	case <-s.done:
		return nil, muxsession.ErrClosed
	}
}

func (s *legOriginSession) Close() error {
	s.closes.Add(1)
	s.closeOnce.Do(func() {
		// snapshot before Close itself is allowed to make Done and Err normal.
		select {
		case <-s.done:
			s.beforeDone = true
		default:
		}
		s.beforeErr, s.beforeCause = s.Err(), context.Cause(s.call)
		s.end(errors.Join(muxsession.ErrClosed, &quic.ApplicationError{}))
		s.physicalErr = errors.Join(s.local.Close(), s.remote.Close(), s.script.closeErr)
	})
	return s.physicalErr
}

func (s *legOriginSession) Done() <-chan struct{} { return s.done }
func (s *legOriginSession) Err() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.sessionErr
}
func (*legOriginSession) SupportsDatagrams() bool { return true }
func (*legOriginSession) SendDatagram(context.Context, []byte) error {
	return errors.New("origin fixture does not forward packets")
}
func (s *legOriginSession) ReceiveDatagram(ctx context.Context) ([]byte, error) {
	select {
	case <-ctx.Done():
		return nil, context.Cause(ctx)
	case <-s.done:
		return nil, muxsession.ErrClosed
	}
}

type legOriginControl struct {
	net.Conn
	owner      *legOriginSession
	activation bool
	reply      []byte
}

func (s *legOriginControl) SetDeadline(at time.Time) error {
	if at.IsZero() {
		s.activation = true
		s.reply = nil
	}
	return s.Conn.SetDeadline(at)
}

func (s *legOriginControl) Read(p []byte) (int, error) {
	failure := s.owner.script.phase == connectorAttemptHello || s.activation
	if failure && s.owner.script.reply == "" {
		s.owner.reads.Add(1)
		return 0, s.owner.failResponse()
	}
	n, err := s.Conn.Read(p)
	if failure && n > 0 {
		s.reply = append(s.reply, p[:n]...)
		if response, parseErr := tunnelv1.ReadControl(bytes.NewReader(s.reply)); parseErr == nil && response.Type == tunnelv1.Error {
			// a fully received rejection has no failed physical read. a later
			// finish cause must not turn its code into local diagnostic evidence.
			if s.owner.script.ended {
				s.owner.end(s.owner.script.sessionErr)
			}
			if s.owner.script.finishCause != nil {
				s.owner.cancel(s.owner.script.finishCause)
			}
		}
	}
	return n, err
}

func (s *legOriginControl) Write(p []byte) (int, error) {
	s.owner.writes.Add(1)
	return s.Conn.Write(p)
}
func (*legOriginControl) CloseWrite() error    { return nil }
func (s *legOriginControl) Reset(uint32) error { return s.Close() }

type legOriginCase struct {
	name   string
	script legOriginScript
	retry  bool
}

func legOriginCases() []legOriginCase {
	normal := errors.Join(muxsession.ErrClosed, &quic.ApplicationError{Remote: true})
	independent := errors.New("independent response operation")
	return []legOriginCase{
		{"already ended", legOriginScript{operation: normal, ended: true, sessionErr: normal}, true},
		{"close creates done", legOriginScript{operation: normal}, false},
		{"live session reports normal error", legOriginScript{operation: normal, sessionErr: normal}, false},
		{"ended session has nil error", legOriginScript{operation: normal, ended: true}, false},
		{"ended session has abnormal error", legOriginScript{operation: normal, ended: true,
			sessionErr: &quic.ApplicationError{Remote: true, ErrorCode: 17}}, false},
		{"ended session has independent error", legOriginScript{operation: normal, ended: true,
			sessionErr: errors.Join(normal, independent)}, false},
		{"live stream reset code zero", legOriginScript{operation: &quic.StreamError{Remote: true}, sessionErr: normal}, false},
		{"ended stream reset code zero", legOriginScript{operation: &quic.StreamError{Remote: true}, ended: true, sessionErr: normal}, false},
		{"independent operation", legOriginScript{operation: errors.Join(normal, independent), ended: true, sessionErr: normal}, false},
		{"normal and EOF operation", legOriginScript{operation: errors.Join(normal, io.EOF), ended: true, sessionErr: normal}, false},
		{"operation cancellation", legOriginScript{operation: errors.Join(normal, context.Canceled), ended: true, sessionErr: normal}, false},
		{"operation deadline", legOriginScript{operation: errors.Join(normal, context.DeadlineExceeded), ended: true, sessionErr: normal}, false},
		{"typed operation cleanup", legOriginScript{operation: errors.Join(normal, &tunnel.SessionCleanupError{Err: context.Canceled}),
			ended: true, sessionErr: normal}, false},
		{"typed session cleanup", legOriginScript{operation: normal, ended: true,
			sessionErr: errors.Join(normal, &muxsession.QUICTransportCloseError{Err: context.Canceled})}, false},
		{"failed physical close", legOriginScript{operation: normal, ended: true, sessionErr: normal,
			closeErr: errors.New("origin fixture physical close failed")}, false},
		{"typed canceled physical close", legOriginScript{operation: normal, ended: true, sessionErr: normal,
			closeErr: &muxsession.QUICTransportCloseError{Err: context.Canceled}}, false},
		{"normal-looking failed close", legOriginScript{operation: normal, ended: true, sessionErr: normal, closeErr: muxsession.ErrClosed}, false},
		{"finish cancellation", legOriginScript{operation: normal, ended: true, sessionErr: normal, finishCause: context.Canceled}, false},
		{"independent finish cause", legOriginScript{operation: normal, ended: true, sessionErr: normal,
			finishCause: errors.New("independent setup finish cause")}, false},
		{"finish deadline", legOriginScript{operation: normal, ended: true, sessionErr: normal, waitExpiry: true}, false},
		{"received denial", legOriginScript{reply: tunnelv1.Unauthenticated, ended: true, sessionErr: normal}, false},
		{"received unavailable with independent finish", legOriginScript{reply: tunnelv1.Unavailable, ended: true, sessionErr: normal,
			finishCause: errors.New("independent received-response finish cause")}, false},
	}
}

func legOriginConfig(session *legOriginSession, alternate error, calls *[2]atomic.Int32) Config {
	return Config{
		RelayQUIC: muxsession.ConnectorFunc(func(context.Context, muxsession.Endpoint) (muxsession.Session, error) {
			calls[0].Add(1)
			return session, nil
		}),
		RelayTCP: muxsession.ConnectorFunc(func(context.Context, muxsession.Endpoint) (muxsession.Session, error) {
			calls[1].Add(1)
			return nil, alternate
		}),
	}
}

func assertLegOriginResult(t *testing.T, s *legOriginSession, err error, wantRetry bool) {
	t.Helper()
	if err == nil || s.opens.Load() != 1 || s.closes.Load() != 1 {
		t.Fatal("failed physical control lost its operation or single closing owner", err)
	}
	if got := connectorReconnectError(err); (got == retryAttempt) != wantRetry || !wantRetry && got != terminateConnection {
		t.Error("normal session end acquired the wrong owned decision", got, err)
	}
	if s.beforeDone != s.script.ended || !errors.Is(s.beforeErr, s.script.sessionErr) {
		t.Error("fixture did not preserve the session state preceding owned Close", s.beforeDone, s.beforeErr)
	}
	select {
	case <-s.done:
	default:
		t.Error("failed physical control did not join its session close")
	}
	for _, cause := range []error{s.script.operation, s.script.closeErr, s.script.finishCause} {
		if cause != nil && !errors.Is(err, cause) {
			t.Error("complete returned result lost a physical operation, cleanup, or finish cause", cause, err)
		}
	}
	if s.script.reply != "" {
		var protocol *tunnel.ProtocolError
		if !errors.As(err, &protocol) || protocol.Code != s.script.reply || s.reads.Load() != 0 {
			t.Error("received protocol response was confused with a failed raw read", err)
		}
	} else if s.reads.Load() != 1 || s.raw != s.script.operation {
		t.Error("fixture did not retain exactly one raw physical response failure")
	}
	if s.script.waitExpiry && (!errors.Is(err, context.DeadlineExceeded) || s.beforeCause != context.DeadlineExceeded) {
		t.Error("setup finish lost the actual call deadline", err, s.beforeCause)
	}
	if s.script.closeErr != nil {
		var cleanup *CleanupError
		var sessionCleanup *tunnel.SessionCleanupError
		marked := errors.As(err, &cleanup) || errors.As(err, &sessionCleanup)
		if !marked || cleanup != nil && errors.Is(cleanup, s.script.operation) ||
			sessionCleanup != nil && errors.Is(sessionCleanup, s.script.operation) {
			t.Error("failed Close lost its marker or absorbed the independent operation", err)
		}
	}
	independent := errors.New("unrelated caller failure")
	if connectorReconnectError(errors.Join(err, independent)) != terminateConnection ||
		connectorReconnectError(fmt.Errorf("unowned caller: %w", err)) != terminateConnection {
		t.Error("owned session-end evidence escaped into an unrelated caller aggregate", err)
	}
	if connectorTemporary(errors.Join(s.script.operation, independent)) {
		t.Error("raw operation aggregate acquired retry permission")
	}
}

func TestConnectorLegHelloNormalEndRequiresPreCloseEvidence(t *testing.T) {
	for _, test := range legOriginCases() {
		t.Run(test.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				budget, stop := context.WithTimeout(t.Context(), 5*time.Second)
				defer stop()
				call, cancel := context.WithCancelCause(budget)
				defer cancel(nil)
				if test.script.waitExpiry {
					bounded, finish := context.WithTimeout(call, time.Second)
					defer finish()
					call = bounded
				}
				signer, _, pair, _, _ := rebindFixture(t)
				script := test.script
				script.phase = connectorAttemptHello
				session := newLegOriginSession(t, call, cancel, pair, script)
				alternate := errors.New("alternate transport did not connect")
				var calls [2]atomic.Int32
				leg, err := prepareConnectorLeg(call, budget, legOriginConfig(session, alternate, &calls),
					signer, pair, [32]byte{1}, 0, nil, tunnelv1.ConnectorHandoffID{1})
				if leg != nil {
					_ = leg.Close()
					t.Fatal("lost hello exposed a relay leg")
				}
				assertLegOriginResult(t, session, err, test.retry)
				if calls[0].Load() != 1 || calls[1].Load() > 1 ||
					context.Cause(call) == nil && (calls[1].Load() != 1 || !errors.Is(err, alternate)) {
					t.Error("hello observation changed the bounded transport race", err)
				}
				if session.writes.Load() != 2 || len(session.activation) != 0 {
					t.Error("failed hello attempted activation or replayed its physical request")
				}
				<-session.served
				if session.serveErr != nil || len(session.hello) != 1 {
					t.Fatal("fixture failed before receiving the signed hello", session.serveErr)
				}
			})
		})
	}
}

func TestConnectorLegActivationNormalEndRequiresCompleteResult(t *testing.T) {
	for _, test := range legOriginCases() {
		t.Run(test.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				budget, stop := context.WithTimeout(t.Context(), 5*time.Second)
				defer stop()
				call, cancel := context.WithCancelCause(budget)
				defer cancel(nil)
				if test.script.waitExpiry {
					bounded, finish := context.WithTimeout(call, time.Second)
					defer finish()
					call = bounded
				}
				signer, _, pair, _, _ := rebindFixture(t)
				script := test.script
				script.phase = connectorAttemptActivation
				session := newLegOriginSession(t, call, cancel, pair, script)
				var calls [2]atomic.Int32
				initial := tunnelv1.ConnectorHandoffID{1}
				leg, err := prepareConnectorLeg(call, budget, legOriginConfig(session, errors.New("unused alternate"), &calls),
					signer, pair, [32]byte{1}, 0, nil, initial)
				if leg != nil {
					_ = leg.Close()
					t.Fatal("lost activation exposed a relay leg")
				}
				assertLegOriginResult(t, session, err, test.retry)
				var diagnostic *tunnel.ProtocolError
				if script.reply == "" && script.operation != nil &&
					(!errors.As(err, &diagnostic) || diagnostic.Code != tunnelv1.Unavailable) {
					t.Error("activation discarded its existing local diagnostic", err)
				}
				if calls[0].Load() != 1 || calls[1].Load() != 0 || session.writes.Load() != 4 {
					t.Error("lost activation replayed a physical control or started another candidate")
				}
				<-session.served
				if session.serveErr != nil || len(session.hello) != 1 || len(session.activation) != 1 {
					t.Fatal("fixture did not receive the real hello and activation", session.serveErr)
				}
				binding := <-session.activation
				activation, bindingErr := binding.Activation()
				operation, stable := activation.InitialOperation()
				if bindingErr != nil || !stable || operation != initial {
					t.Error("uncertain activation changed the initial operation", bindingErr)
				}
			})
		})
	}
}

func TestConnectorLegActivationNormalEndRetainsPhysicalFence(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, stop := context.WithTimeout(t.Context(), 5*time.Second)
		defer stop()
		call, cancel := context.WithCancelCause(ctx)
		defer cancel(nil)
		signer, _, pair, _, _ := rebindFixture(t)
		normal := errors.Join(muxsession.ErrClosed, &quic.ApplicationError{Remote: true})
		session := newLegOriginSession(t, call, cancel, pair, legOriginScript{
			phase: connectorAttemptActivation, operation: normal, ended: true, sessionErr: normal})
		var calls [2]atomic.Int32
		initial := tunnelv1.ConnectorHandoffID{1}
		leg, err := dialConnectorLeg(call, ctx, legOriginConfig(session, errors.New("unused alternate"), &calls),
			signer, pair, [32]byte{1}, 0, nil, initial)
		if err != nil {
			t.Fatal(err)
		}
		defer leg.Close()
		first := activateConnectorLeg(call, leg, nil, initial)
		writes := session.writes.Load()
		second := activateConnectorLeg(call, leg, nil, initial)
		var rejected *tunnel.ProtocolError
		if !errors.Is(first, normal) || !errors.As(second, &rejected) || rejected.Code != tunnelv1.InvalidMessage ||
			session.writes.Load() != writes || session.reads.Load() != 1 || calls[0].Load() != 1 || calls[1].Load() != 0 {
			t.Fatal("uncertain activation was retried on the same physical control", first, second)
		}
	})
}

func TestConnectorLegNormalEndCannotAuthorizeAnotherCandidate(t *testing.T) {
	ctx, stop := context.WithTimeout(t.Context(), 5*time.Second)
	defer stop()
	call, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)
	signer, _, pair, _, _ := rebindFixture(t)
	normal := errors.Join(muxsession.ErrClosed, &quic.ApplicationError{Remote: true})
	independent := errors.New("other hello failed independently")
	first := newLegOriginSession(t, call, cancel, pair, legOriginScript{
		phase: connectorAttemptHello, operation: normal, ended: true, sessionErr: normal})
	second := newLegOriginSession(t, call, cancel, pair, legOriginScript{
		phase: connectorAttemptHello, operation: independent, ended: true, sessionErr: normal})
	config := Config{
		RelayQUIC: muxsession.ConnectorFunc(func(context.Context, muxsession.Endpoint) (muxsession.Session, error) { return first, nil }),
		RelayTCP:  muxsession.ConnectorFunc(func(context.Context, muxsession.Endpoint) (muxsession.Session, error) { return second, nil }),
	}
	leg, err := prepareConnectorLeg(call, ctx, config, signer, pair, [32]byte{1}, 0, nil, tunnelv1.ConnectorHandoffID{1})
	if leg != nil {
		_ = leg.Close()
		t.Fatal("normal session end exposed an independently failed candidate")
	}
	if !errors.Is(err, normal) || !errors.Is(err, independent) || connectorReconnectError(err) != terminateConnection ||
		first.closes.Load() != 1 || second.closes.Load() != 1 {
		t.Fatal("one candidate's normal end authorized another candidate's independent failure", err)
	}
}

package stream

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	quic "github.com/quic-go/quic-go"
	"github.com/tnldotdev/tnl/internal/testutil/connectorfixture"
	"github.com/tnldotdev/tnl/internal/transport/muxsession"
	"github.com/tnldotdev/tnl/internal/transport/tunnel"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

type peerShutdownReset struct {
	code                 uint32
	retired, sessionDone bool
}

type peerShutdownSession struct {
	muxsession.Session
	retired      <-chan struct{}
	closeEntered chan bool
	resetEntered chan peerShutdownReset
	resetRelease chan struct{}
	closeErr     error
	resetErr     error
}

func (s *peerShutdownSession) OpenStream(ctx context.Context) (muxsession.Stream, error) {
	stream, err := s.Session.OpenStream(ctx)
	if err != nil {
		return nil, err
	}
	return &peerShutdownControlStream{Stream: stream, owner: s}, nil
}

func (s *peerShutdownSession) Close() error {
	retired := false
	select {
	case <-s.retired:
		retired = true
	default:
	}
	s.closeEntered <- retired
	return errors.Join(s.Session.Close(), s.closeErr)
}

type peerShutdownControlStream struct {
	muxsession.Stream
	owner *peerShutdownSession
}

func (s *peerShutdownControlStream) Read(p []byte) (int, error) {
	n, err := s.Stream.Read(p)
	if err != nil && muxsession.NormalSessionCloseOnly(err) {
		// quic wakes stream reads before publishing connection Done. hold only
		// that normal read return until actual termination; resets stay ungated.
		<-s.owner.Session.Done()
	}
	return n, err
}

func (s *peerShutdownControlStream) Reset(code uint32) error {
	event := peerShutdownReset{code: code}
	select {
	case <-s.owner.Session.Done():
		event.sessionDone = true
	default:
	}
	select {
	case <-s.owner.retired:
		event.retired = true
	default:
	}
	err := s.Stream.Reset(code)
	s.owner.resetEntered <- event
	// the real reset has run; only its return is held to prove the owner join.
	<-s.owner.resetRelease
	return errors.Join(err, s.owner.resetErr)
}

type peerShutdownFixture struct {
	ctx          context.Context
	owner        *connectorConnection
	session      *peerShutdownSession
	server       muxsession.Session
	control      muxsession.Stream
	controlDone  <-chan error
	retired      <-chan struct{}
	retirements  atomic.Int32
	releaseReset func()
}

func newPeerShutdownFixture(t *testing.T, closeErr, resetErr error) *peerShutdownFixture {
	t.Helper()
	client, server := stdioTransportSessions(t, "quic")
	ctx, stop := context.WithTimeout(t.Context(), 5*time.Second)
	serving, stopServing := context.WithCancelCause(context.WithoutCancel(ctx))
	packets, stopPackets := context.WithCancelCause(context.WithoutCancel(ctx))
	serverLife, stopServer := context.WithCancel(context.WithoutCancel(ctx))
	retired := make(chan struct{})
	session := &peerShutdownSession{Session: client, retired: retired,
		closeEntered: make(chan bool, 1), resetEntered: make(chan peerShutdownReset, 1),
		resetRelease: make(chan struct{}), closeErr: closeErr, resetErr: resetErr}
	f := &peerShutdownFixture{ctx: ctx, session: session, server: server, retired: retired,
		releaseReset: sync.OnceFunc(func() { close(session.resetRelease) })}
	f.owner = &connectorConnection{ctx: serving, packetCtx: packets, packetCancel: stopPackets,
		cleanup: newConnectorCleanup(ctx, nil), session: session, owner: "ik_aaaaaaaaaaaaaaaaaaaaaa"}
	f.owner.cancel = func(cause error) { f.owner.cleanup.begin(); stopServing(cause) }
	var workers sync.WaitGroup
	t.Cleanup(func() {
		f.releaseReset()
		_ = f.owner.Close(context.WithoutCancel(ctx))
		stopPackets(context.Canceled)
		_ = server.Close()
		stopServer()
		stop()
		workers.Wait()
	})

	scope := connectorTestControlScope()
	key := [32]byte{7, 9}
	private := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{19}, ed25519.SeedSize))
	public := private.Public().(ed25519.PublicKey)
	f.owner.signer = Signer{PublicKey: public, Sign: func(message []byte) []byte {
		return ed25519.Sign(private, message)
	}}
	now := time.Now()
	pair := controlv1.ConnectorPeerPair{
		ServiceId: scope.ServiceID, ServiceRunId: scope.ServiceRunID, RunNumber: int64(scope.RunNumber),
		PublisherIdentityId: scope.PublisherIdentityID, PairId: scope.PairID,
		DeliveryId: "AQEBAQEBAQEBAQEBAQEBAQ", ObservedAt: now, ExpiresAt: now.Add(time.Minute),
		SessionKey: base64.RawURLEncoding.EncodeToString(key[:]),
	}
	authority := connectorfixture.NewRetirement(pair, f.owner.owner, public, key)
	recordRetirement := sync.OnceFunc(func() { close(retired) })
	config := unreachableControlConfig()
	config.RetirePair = func(ctx context.Context, service, pairID string, body controlv1.ConnectorPeerPairRetireRequest) (controlv1.ConnectorPeerPairRetirement, error) {
		f.retirements.Add(1)
		receipt, err := authority.Retire(ctx, service, pairID, body)
		if err == nil {
			recordRetirement()
		}
		return receipt, err
	}
	control, err := NewControlWithConfig(config)
	if err != nil {
		t.Fatal(err)
	}
	f.owner.config.Control = control
	if err := f.owner.captureRetirement(pair); err != nil {
		t.Fatal(err)
	}

	accepted := make(chan muxsession.Stream, 1)
	done := make(chan error, 1)
	f.controlDone = done
	setup, stopSetup := context.WithTimeout(ctx, 3*time.Second)
	defer stopSetup()
	workers.Go(func() {
		stream, err := tunnel.AcceptConnectorPermissionControl(setup, server)
		if err == nil {
			accepted <- stream
			// retirement validates its actual signed receipt but deliberately
			// does not notify this observer before whole-session termination.
			joined := connectorfixture.NewJoinedControl(serverLife, scope, func(tunnelv1.ConnectorVisitorTerminalKey) *connectorfixture.JoinedVisitor {
				return nil
			})
			var gate tunnel.ConnectorPermissionGate
			err = joined.Serve(stream, &gate)
		}
		done <- err
	})
	f.owner.permissions, err = tunnel.OpenConnectorPermissionControl(packets, setup, session, scope)
	if err != nil {
		t.Fatal(err)
	}
	select {
	case f.control = <-accepted:
	case err := <-done:
		t.Fatal("permission control handshake failed", err)
	case <-setup.Done():
		t.Fatal("permission control did not join its handshake", context.Cause(setup))
	}
	return f
}

func TestConnectorPeerShutdownClosesSessionBeforePermissionResetAndJoins(t *testing.T) {
	for _, mixed := range []bool{false, true} {
		t.Run(map[bool]string{false: "clean", true: "mixed physical failures"}[mixed], func(t *testing.T) {
			sessionFailure := errors.New("independent whole-session physical close failure")
			resetFailure := errors.New("independent permission-reset physical close failure")
			var sessionErr, resetErr error
			if mixed {
				sessionErr = &muxsession.QUICTransportCloseError{Err: errors.Join(context.Canceled, sessionFailure)}
				resetErr = &muxsession.QUICTransportCloseError{Err: errors.Join(context.Canceled, resetFailure)}
			}
			f := newPeerShutdownFixture(t, sessionErr, resetErr)
			useEntered, useRelease := make(chan struct{}), make(chan struct{})
			releaseUse := sync.OnceFunc(func() { close(useRelease) })
			f.owner.uses.Go(func() { close(useEntered); <-useRelease })
			var callers sync.WaitGroup
			defer func() { releaseUse(); f.releaseReset(); callers.Wait() }()
			ownerTeardownAwait(t, f.ctx, useEntered)
			cleanup := f.owner.cleanup.context()
			deadline, _ := cleanup.Deadline()
			result := make(chan error, 1)
			callers.Go(func() { result <- f.owner.Close(cleanup) })
			ownerTeardownAwait(t, f.ctx, f.owner.ctx.Done())
			ownerTeardownPending(t, f.retired, "retirement preceded the entered use join")
			ownerTeardownPending(t, f.session.closeEntered, "whole-session close preceded the entered use join")
			ownerTeardownPending(t, f.session.resetEntered, "permission reset preceded the entered use join")
			releaseUse()
			event := ownerTeardownAwait(t, f.ctx, f.session.resetEntered)
			if event.code != 0 || !event.retired || !event.sessionDone {
				t.Fatal("permission cancellation reset a live session or preceded authenticated retirement", event)
			}
			if retired := ownerTeardownAwait(t, f.ctx, f.session.closeEntered); !retired {
				t.Fatal("whole-session close preceded authenticated retirement")
			}
			ownerTeardownPending(t, result, "owner did not join the held reset callback")
			if f.owner.packetCtx.Err() != nil {
				t.Fatal("packet lifetime ended before permission reset joined")
			}
			f.releaseReset()
			join, stop := context.WithTimeout(f.ctx, time.Second)
			defer stop()
			err := ownerTeardownAwait(t, join, result)
			if !mixed && err != nil {
				t.Fatal("clean whole-session termination became a cleanup failure", err)
			}
			if mixed && (!errors.Is(err, sessionErr) || !errors.Is(err, resetErr) ||
				!errors.Is(err, sessionFailure) || !errors.Is(err, resetFailure) || !errors.Is(err, context.Canceled)) {
				t.Fatal("shutdown lost a session, permission, or joined physical failure", err)
			}
			if err := ownerTeardownAwait(t, f.ctx, f.controlDone); !muxsession.NormalSessionCloseOnly(err) {
				t.Fatal("whole-session close became an independent remote control failure", err)
			}
			if f.retirements.Load() != 1 {
				t.Fatal("shutdown added retirement polling or replay", f.retirements.Load())
			}
			if next, _ := f.owner.cleanup.context().Deadline(); !next.Equal(deadline) {
				t.Fatal("session or permission cleanup restarted the first-stop budget")
			}
			callers.Wait()
		})
	}
}

func TestConnectorPeerShutdownKeepsLiveControlResetFailures(t *testing.T) {
	for _, code := range []uint32{0, 7} {
		t.Run(map[uint32]string{0: "remote zero reset", 7: "remote nonzero reset"}[code], func(t *testing.T) {
			f := newPeerShutdownFixture(t, nil, nil)
			if err := f.control.Reset(code); err != nil {
				t.Fatal(err)
			}
			event := ownerTeardownAwait(t, f.ctx, f.session.resetEntered)
			if event.sessionDone || event.retired {
				t.Fatal("reset contrast did not interrupt a live unretired session", event)
			}
			select {
			case <-f.server.Done():
				t.Fatal("control-only reset was replaced by whole-session termination")
			default:
			}
			var reset *quic.StreamError
			if err := f.owner.permissions.Err(); !errors.As(err, &reset) ||
				reset.StreamID != 0 || !reset.Remote || reset.ErrorCode != quic.StreamErrorCode(code) {
				t.Fatal("real control reset lost its stream identity or code", err)
			}
			f.releaseReset()
			err := f.owner.Close(f.owner.cleanup.context())
			var retained *quic.StreamError
			if err == nil || !errors.Is(err, reset) || !errors.As(err, &retained) ||
				retained.StreamID != 0 || !retained.Remote || retained.ErrorCode != quic.StreamErrorCode(code) {
				t.Fatal("whole-session cleanup hid an earlier control reset", err)
			}
			if err := ownerTeardownAwait(t, f.ctx, f.controlDone); err == nil || muxsession.NormalSessionCloseOnly(err) {
				t.Fatal("live control reset was reported as a normal remote session end", err)
			}
		})
	}
}

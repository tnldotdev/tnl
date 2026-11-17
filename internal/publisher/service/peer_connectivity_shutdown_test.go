package service

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	quic "github.com/quic-go/quic-go"
	"github.com/tnldotdev/tnl/internal/transport/muxsession"
	"github.com/tnldotdev/tnl/internal/transport/tunnel"
)

type closingConnectivitySession struct {
	muxsession.Session
	done <-chan struct{}
	err  error
}

func (s closingConnectivitySession) Done() <-chan struct{} { return s.done }
func (s closingConnectivitySession) Err() error            { return s.err }

func TestPeerConnectivityShutdownJoinsPendingQUICClose(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		p := &PeerSession{bound: &Bound{boundState: &boundState{}}, ctx: ctx, cancel: cancel, changed: make(chan struct{})}
		raw := &quic.ApplicationError{Remote: true}
		done := make(chan struct{})
		session := closingConnectivitySession{done: done, err: errors.Join(muxsession.ErrClosed, raw)}
		result := make(chan error, 1)
		go func() { result <- p.finishConnectivity(session, raw) }()
		synctest.Wait()
		select {
		case err := <-result:
			t.Fatal("raw signaling return ended the peer before its connection confirmed closure", err)
		default:
		}
		close(done)
		if err := <-result; err != nil || p.ctx.Err() != nil ||
			p.terminalEnd.Cause != tunnel.ConnectorTerminalPeerTerminated || p.terminalEnd.Err != nil {
			t.Fatal("normal QUIC close escaped the peer", p.terminalEnd, err)
		}
	})
}

// these barriers hold only observation of real transport returns. they do not
// change the connection's Done/Err facts or manufacture a connectivity result.
type connectivityShutdownSession struct {
	muxsession.Session
	acceptEntered, controlEntered chan struct{}
	acceptRelease, controlRelease chan struct{}
	acceptOnce, controlOnce       sync.Once
}

func (s *connectivityShutdownSession) AcceptStream(ctx context.Context) (muxsession.Stream, error) {
	stream, err := s.Session.AcceptStream(ctx)
	if err != nil {
		s.acceptOnce.Do(func() { close(s.acceptEntered) })
		<-s.acceptRelease
		return nil, err
	}
	return &connectivityShutdownStream{Stream: stream, owner: s}, nil
}

type connectivityShutdownStream struct {
	muxsession.Stream
	owner *connectivityShutdownSession
}

func (s *connectivityShutdownStream) Read(p []byte) (int, error) {
	n, err := s.Stream.Read(p)
	if err != nil {
		s.owner.controlOnce.Do(func() { close(s.owner.controlEntered) })
		<-s.owner.controlRelease
	}
	return n, err
}

func connectivityShutdownPair(t *testing.T, ctx context.Context) (*PeerSession, *quic.Conn, *quic.Conn, muxsession.Session, muxsession.Session) {
	t.Helper()
	_, p, _, _, _ := connectorPeerFixture(t, "127.0.0.1:1")
	certificate, trust := managedTestCertificate(t, "connectivity.example")
	packet, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	serverTransport := &quic.Transport{Conn: packet}
	t.Cleanup(func() { _ = serverTransport.Close(); _ = packet.Close() })
	listener, err := serverTransport.Listen(&tls.Config{
		MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{certificate},
		NextProtos: []string{muxsession.ALPN},
	}, tunnel.ConnectorQUICConfig())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	clientPacket, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	clientTransport := &quic.Transport{Conn: clientPacket}
	t.Cleanup(func() { _ = clientTransport.Close(); _ = clientPacket.Close() })
	trust = trust.Clone()
	trust.NextProtos = []string{muxsession.ALPN}
	client, err := clientTransport.Dial(ctx, packet.LocalAddr(), trust, tunnel.ConnectorQUICConfig())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.CloseWithError(0, "") })
	server, err := listener.Accept(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.CloseWithError(0, "") })
	clientSession, err := muxsession.AdoptQUIC(client)
	if err != nil {
		t.Fatal(err)
	}
	serverSession, err := muxsession.AdoptQUIC(server)
	if err != nil {
		t.Fatal(err)
	}
	return p, client, server, clientSession, serverSession
}

func connectivityShutdownRawEnd(t *testing.T, ctx context.Context, client, server *quic.Conn, code quic.ApplicationErrorCode) error {
	t.Helper()
	if err := client.CloseWithError(code, ""); err != nil {
		t.Fatal(err)
	}
	// this is the raw operation used by connectivity's signaling reader.
	_, err := server.AcceptUniStream(ctx)
	var application *quic.ApplicationError
	if !errors.As(err, &application) || !application.Remote || application.ErrorCode != code {
		t.Fatal("raw connectivity accept did not retain the actual remote whole-session error", err)
	}
	awaitPeerSignal(t, ctx, server.Context().Done())
	return err
}

func TestPeerConnectivityShutdown(t *testing.T) {
	t.Run("peer closes before permission control setup", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
		defer cancel()
		p, client, server, _, session := connectivityShutdownPair(t, ctx)
		_ = connectivityShutdownRawEnd(t, ctx, client, server, 0)
		if err := p.serveSession(session); err != nil {
			t.Fatal("a normal unused peer close escaped toward the publication fence", err)
		}
	})

	t.Run("normal ended session before other observations", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
		defer cancel()
		p, client, server, clientSession, session := connectivityShutdownPair(t, ctx)
		held := &connectivityShutdownSession{Session: session,
			acceptEntered: make(chan struct{}), controlEntered: make(chan struct{}),
			acceptRelease: make(chan struct{}), controlRelease: make(chan struct{})}
		release := sync.OnceFunc(func() { close(held.acceptRelease); close(held.controlRelease) })
		var joined error
		checked := false
		done := make(chan struct{})
		go func() { defer close(done); joined = p.serveSession(held) }()
		t.Cleanup(func() {
			release()
			p.cancel()
			if err := clientSession.Close(); err != nil {
				t.Errorf("client session cleanup retained a failure: %v", err)
			}
			if err := session.Close(); err != nil {
				t.Errorf("publisher session cleanup retained a failure: %v", err)
			}
			<-done
			if !checked && joined != nil {
				t.Errorf("joined peer session retained an unexpected cleanup failure: %v", joined)
			}
		})
		writer, err := tunnel.OpenConnectorPermissionControl(ctx, ctx, clientSession, p.controlScope())
		if err != nil {
			t.Fatal(err)
		}
		defer writer.Close()
		raw := connectivityShutdownRawEnd(t, ctx, client, server, 0)
		awaitPeerSignal(t, ctx, held.acceptEntered)
		awaitPeerSignal(t, ctx, held.controlEntered)
		if p.ctx.Err() != nil || !muxsession.NormalSessionCloseOnly(session.Err()) {
			t.Fatal("finish-stage precondition lost the live owner or actual normal session end", p.ctx.Err(), session.Err())
		}
		// this forces the owning finish stage, not selection order inside the
		// concrete Connectivity.Serve. the runtime capture proves that branch.
		got := p.finishConnectivity(held, raw)
		p.bound.mu.Lock()
		end, controlFailed, fenced := p.terminalEnd, p.controlFailed, p.bound.closed
		p.bound.mu.Unlock()
		t.Logf("finish stage: session_done=true raw=%T owner_canceled=%t end=%q control_failed=%t bound_closed=%t",
			raw, p.ctx.Err() != nil, end.Cause, controlFailed, fenced)
		if got != nil || p.ctx.Err() != nil || end.Cause != tunnel.ConnectorTerminalPeerTerminated ||
			end.Err != nil || controlFailed || fenced {
			t.Errorf("normal whole-session connectivity return stopped the owner or escaped toward the publication fence: %v", got)
		}
		release()
		// actual session termination and released observations must join on
		// their own. cleanup cancellation is a fallback, not this proof.
		awaitPeerSignal(t, ctx, done)
		checked = true
		if joined != nil {
			t.Errorf("actual normal session termination retained a joined failure: %v", joined)
		}
	})

	for _, contrast := range []string{"abnormal whole session", "independent joined failure", "physical joined failure", "canceled owner", "canceled owner with independent failure"} {
		t.Run(contrast, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			p, client, server, _, session := connectivityShutdownPair(t, ctx)
			code := quic.ApplicationErrorCode(0)
			if contrast == "abnormal whole session" {
				code = 7
			}
			raw := connectivityShutdownRawEnd(t, ctx, client, server, code)
			independent := errors.New("independent connectivity cleanup failure")
			incoming := raw
			switch contrast {
			case "independent joined failure":
				incoming = errors.Join(raw, independent)
			case "physical joined failure":
				incoming = errors.Join(raw, &muxsession.QUICTransportCloseError{Err: errors.Join(context.Canceled, independent)})
			case "canceled owner":
				p.stop()
				incoming = context.Canceled
			case "canceled owner with independent failure":
				p.stop()
				incoming = errors.Join(context.Canceled, independent)
			}
			p.bound.mu.Lock()
			before := p.stopUntil
			p.bound.mu.Unlock()
			got := p.finishConnectivity(session, incoming)
			if got != incoming || p.ctx.Err() == nil {
				t.Fatal("finish stage discarded a failure or failed to stop its owner", got)
			}
			if contrast != "abnormal whole session" && contrast != "canceled owner" && !errors.Is(got, independent) {
				t.Fatal("finish stage lost the independent leaf", got)
			}
			if contrast == "physical joined failure" {
				var physical *muxsession.QUICTransportCloseError
				if !errors.As(got, &physical) || !errors.Is(got, context.Canceled) {
					t.Fatal("finish stage lost physical cleanup provenance", got)
				}
			}
			p.bound.mu.Lock()
			after := p.stopUntil
			p.bound.mu.Unlock()
			if !before.IsZero() && !before.Equal(after) {
				t.Fatal("an already-stopped owner restarted its cleanup interval")
			}
		})
	}

	for _, code := range []uint32{0, 7} {
		t.Run(map[uint32]string{0: "live control reset zero", 7: "live control reset nonzero"}[code], func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			p, _, _, clientSession, session := connectivityShutdownPair(t, ctx)
			accepted := make(chan muxsession.Stream, 1)
			setup := make(chan error, 1)
			setupDone := make(chan struct{})
			go func() {
				defer close(setupDone)
				stream, err := tunnel.AcceptConnectorPermissionControl(ctx, session)
				if err == nil {
					accepted <- stream
				}
				setup <- err
			}()
			t.Cleanup(func() { cancel(); _ = session.Close(); <-setupDone })
			writer, err := tunnel.OpenConnectorPermissionControl(ctx, ctx, clientSession, p.controlScope())
			if err != nil {
				t.Fatal(err)
			}
			defer writer.Close()
			if err := <-setup; err != nil {
				t.Fatal(err)
			}
			if err := (<-accepted).Reset(code); err != nil {
				t.Fatal(err)
			}
			awaitPeerSignal(t, ctx, writer.Done())
			incoming := writer.Err()
			var reset *quic.StreamError
			if !errors.As(incoming, &reset) || !reset.Remote || reset.ErrorCode != quic.StreamErrorCode(code) {
				t.Fatal("live control reset lost its actual wire cause", incoming)
			}
			select {
			case <-clientSession.Done():
				t.Fatal("control-reset contrast closed the whole session")
			default:
			}
			if got := p.finishConnectivity(clientSession, incoming); got != incoming || p.ctx.Err() == nil {
				t.Fatal("whole-session handling hid a live control reset", got)
			}
		})
	}
}

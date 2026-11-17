package stream

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	quic "github.com/quic-go/quic-go"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/transport/muxsession"
	"github.com/tnldotdev/tnl/internal/transport/tunnel"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestPreparedSessionOwnsLifetimeAfterSetupEnds(t *testing.T) {
	fixture := newConnectorFixture(t, "wss")
	lifetime, stop := context.WithCancel(t.Context())
	defer stop()
	setup, finish := context.WithTimeout(lifetime, 5*time.Second)
	config := fixture.config
	config.WebSocketOnly = true
	config.RelayWebSocket = muxsession.WebSocketConnector{TLSConfig: config.TransportTLS}
	session, err := Prepare(lifetime, setup, config)
	finish()
	if err != nil {
		t.Fatal(err)
	}
	if session.connection.socket != nil || session.connection.udpTransport != nil {
		t.Fatal("WSS-only session opened UDP")
	}
	if session.Context().Err() != nil {
		t.Fatal("setup cancellation ended retained lifetime")
	}
	pair := session.connection.pair.PairId
	for range 2 {
		// the first use was prepared before Forward; the next is admitted from
		// the same signed pool. both must bind to their own abort operation.
		app, local := net.Pipe()
		forward, cancelForward := context.WithCancel(lifetime)
		forwarded := make(chan error, 1)
		go func() { forwarded <- session.Forward(forward, &ownedStdioPipe{Conn: local}) }()
		if err := app.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
			t.Fatal(err)
		}
		if _, err := app.Write([]byte("session echo")); err != nil {
			t.Fatal(err)
		}
		response := make([]byte, len("session echo"))
		if _, err := io.ReadFull(app, response); err != nil || string(response) != "session echo" {
			t.Fatal(string(response), err)
		}
		session.connection.mu.Lock()
		for use := range session.connection.active {
			use.prepared.mu.Lock()
			selected := use.prepared.stdio
			use.prepared.mu.Unlock()
			if selected == nil || selected.owner.caller != forward {
				t.Error("prepared use did not bind to this caller's operation")
			}
		}
		session.connection.mu.Unlock()
		cancelForward()
		if err := <-forwarded; err != nil {
			t.Fatal("explicit stream abort failed", err)
		}
		_ = app.Close()
		if session.Context().Err() != nil || session.connection.pair.PairId != pair {
			t.Fatal("stream abort replaced or canceled its retained session")
		}
	}
	if err := session.Close(); err != nil {
		t.Fatal(err)
	}
	if session.Context().Err() == nil {
		t.Fatal("session Close did not end lifetime")
	}
	if err := session.Close(); err != nil {
		t.Fatal("idempotent close changed result", err)
	}
}

func TestPreparedSessionRetainsControlCleanupFailure(t *testing.T) {
	fixture := newConnectorFixture(t, "wss")
	cleanup := errors.New("control cleanup failed")
	control := &closeSessionControl{Control: fixture, err: cleanup}
	config := fixture.config
	config.Control = control
	config.WebSocketOnly = true
	config.RelayWebSocket = muxsession.WebSocketConnector{TLSConfig: config.TransportTLS}
	session, err := Prepare(t.Context(), t.Context(), config)
	if err != nil {
		t.Fatal(err)
	}
	if err := session.Close(); !errors.Is(err, cleanup) {
		t.Fatal("lost independent control close failure", err)
	}
}

type closeSessionControl struct {
	Control
	err error
}

func (c *closeSessionControl) Close(context.Context) error { return c.err }

func TestPreparedSessionFailedSignerRetainsIndependentCanceledCleanup(t *testing.T) {
	setup, cancel := context.WithCancel(t.Context())
	cancel()
	control := &failedSessionControl{}
	_, err := Prepare(t.Context(), setup, Config{
		Control: control, ServiceID: "svc_aaaaaaaaaaaaaaaaaaaaaa", Protocol: "tcp", TrustRevision: 1,
		Endpoint:   &controlv1.ServiceEndpoint{Hostname: "service.example.test"},
		ServiceTLS: &tls.Config{},
	})
	var cleanup *CleanupError
	if !errors.Is(err, context.Canceled) || !errors.As(err, &cleanup) || cleanup.Err != context.Canceled {
		t.Fatal("failed preparation lost its independently canceled cleanup", err)
	}
	if connectorOwnedCancellationOnly(err, context.Canceled) {
		t.Fatal("independent cleanup was classified as operation cancellation only", err)
	}
	if control.closed != 1 {
		t.Fatal("failed preparation did not join exactly one control close", control.closed)
	}
}

type failedSessionControl struct {
	Control
	closed int
}

func (*failedSessionControl) ConnectorSigner(context.Context, string) (Signer, error) {
	return Signer{}, context.Canceled
}

func (c *failedSessionControl) Close(context.Context) error {
	c.closed++
	return context.Canceled
}

type sessionReadFailure struct {
	net.Conn
	entered chan struct{}
	release chan struct{}
	err     error
	once    sync.Once
}

type sessionAbortPipe struct {
	*ownedStdioPipe
	done chan struct{}
	once sync.Once
}

func (p *sessionAbortPipe) Abort(cause error) error {
	err := p.ownedStdioPipe.Abort(cause)
	p.once.Do(func() { close(p.done) })
	return err
}

func (s *sessionReadFailure) Read([]byte) (int, error) {
	s.once.Do(func() { close(s.entered) })
	<-s.release
	return 0, s.err
}

func TestPreparedSessionAbortKeepsIndependentOperationAndCleanup(t *testing.T) {
	for _, independent := range []error{
		&tls.RecordHeaderError{Msg: "independent TLS failure"},
		failure.Wrap("permission", failure.ServerDenied, io.ErrClosedPipe),
		&quic.StreamError{Remote: true, ErrorCode: 7},
		&quic.StreamError{ErrorCode: 9},
		fmt.Errorf("independent read: %w", io.EOF), io.ErrClosedPipe,
		&CleanupError{Err: context.Canceled},
		tunnel.ErrConnectorTerminalFailed,
	} {
		t.Run(independent.Error(), func(t *testing.T) {
			raw, _ := stdioTransportPair(t, "quic")
			remote := &sessionReadFailure{Conn: raw, entered: make(chan struct{}), release: make(chan struct{}), err: independent}
			release := sync.OnceFunc(func() { close(remote.release) })
			defer release()
			until := time.Now().Add(time.Minute)
			prepared := &PreparedConnector{ctx: t.Context(), conn: remote, raw: raw,
				stream: streamPrepared{}, permission: permissionUsable{}, permissionUntil: until, stop: func() bool { return true }}
			defer prepared.Close()
			use := &connectorUse{prepared: prepared, until: until}
			connection := &connectorConnection{ctx: t.Context(), until: until, preparedUntil: until,
				run: Run{ValidUntil: until}, permission: controlv1.VisitorTokenResponse{ExpiresAt: until},
				config: Config{MaxConnections: 1}, warm: use, active: map[*connectorUse]struct{}{use: {}}, refill: make(chan struct{}, 1)}
			session := &Session{connection: connection}
			app, local := net.Pipe()
			defer app.Close()
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			done := make(chan error, 1)
			owned := &sessionAbortPipe{ownedStdioPipe: &ownedStdioPipe{Conn: local}, done: make(chan struct{})}
			go func() { done <- session.Forward(ctx, owned) }()
			select {
			case <-remote.entered:
			case <-time.After(5 * time.Second):
				t.Fatal("prepared copy did not enter")
			}
			cancel()
			select {
			case <-owned.done:
			case <-time.After(5 * time.Second):
				t.Fatal("caller abort did not reach its local pipe")
			}
			release()
			select {
			case err := <-done:
				if !errors.Is(err, independent) {
					t.Fatal("owned abort hid an independent failure", err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("prepared operation did not join")
			}
		})
	}
}

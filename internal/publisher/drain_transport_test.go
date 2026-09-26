package publisher

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/muxsession"
	"github.com/tnldotdev/tnl/internal/relay"
	"github.com/tnldotdev/tnl/internal/tunnel"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
	"github.com/tnldotdev/tnl/pkg/api/relayv1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

type drainTestRelay struct {
	connection *relay.PublisherConnection
	err        error
}

func drainTestConnections(t *testing.T, ctx context.Context, control *certificateTestControl, kind string) (muxsession.Connector, <-chan drainTestRelay, <-chan muxsession.Session) {
	t.Helper()
	ctx, cancel := context.WithCancel(ctx)
	certificate := publicURLTestCertificate(t, "relay.example")
	serverTLS := &tls.Config{Certificates: []tls.Certificate{certificate}}
	clientTLS := &tls.Config{RootCAs: rootsForCertificate(t, certificate)}
	relays, publishers := make(chan drainTestRelay, 2), make(chan muxsession.Session, 2)
	var connector muxsession.Connector
	var listeners []io.Closer
	var workers sync.WaitGroup
	t.Cleanup(func() {
		cancel()
		for _, listener := range listeners {
			_ = listener.Close()
		}
		joined := make(chan struct{})
		go func() { workers.Wait(); close(joined) }()
		awaitPublisherTest(t, joined)
	})
	for slot := range 2 {
		var address string
		var accept func() (muxsession.Session, error)
		if kind == "quic" {
			listener, err := muxsession.ListenQUIC("127.0.0.1:0", serverTLS, muxsession.QUICConfig{})
			if err != nil {
				t.Fatal(err)
			}
			listeners = append(listeners, listener)
			address = listener.Addr().String()
			accept = func() (muxsession.Session, error) { return listener.Accept(ctx) }
			connector = muxsession.QUICConnector{TLSConfig: clientTLS}
		} else {
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			listeners = append(listeners, listener)
			address = listener.Addr().String()
			accept = func() (muxsession.Session, error) {
				connection, err := listener.Accept()
				if err != nil {
					return nil, err
				}
				stop := context.AfterFunc(ctx, func() { _ = connection.Close() })
				defer stop()
				transport, err := muxsession.AcceptTLSYamux(ctx, connection, serverTLS, muxsession.TLSYamuxConfig{})
				if err != nil {
					_ = connection.Close()
				}
				return transport, err
			}
			connector = muxsession.TLSYamuxConnector{TLSConfig: clientTLS}
		}
		control.setup.PublisherConnections = append(control.setup.PublisherConnections, controlv1.ConnectionAssignment{
			ConnectionSlot: slot, ConnectionAssignmentRevision: 1, PublisherConnectionId: fmt.Sprintf("drain_connection_%d", slot),
			PublisherConnectionCredential: "test-credential", PublisherConnectionCredentialExpiresAt: time.Now().Add(time.Hour),
			RelayServiceId: fmt.Sprintf("relay_service_%d", slot), RelayAddress: address, TlsServerName: "relay.example", State: controlv1.PublisherConnectionStateAssigned,
		})
		workers.Go(func() {
			transport, err := accept()
			if err != nil {
				relays <- drainTestRelay{err: err}
				return
			}
			defer transport.Close()
			stop := context.AfterFunc(ctx, func() { _ = transport.Close() })
			defer stop()
			session, hello, err := tunnel.Accept(ctx, transport, func(_ context.Context, hello tunnelv1.Message) error {
				if hello.Role != tunnelv1.Publisher || hello.Credential != "test-credential" || hello.PublisherConnection == nil || hello.PublisherConnection.ConnectionSlot != uint8(slot) {
					return fmt.Errorf("unexpected publisher hello: %#v", hello)
				}
				return nil
			})
			if err != nil {
				relays <- drainTestRelay{err: err}
				return
			}
			ref := *hello.PublisherConnection
			connection, err := relay.NewPublisherConnection(ref, relayv1.ClaimedPublisherConnection{
				ConnectionAssignmentRevision: int64(ref.ConnectionAssignmentRevision), ConnectionSlot: int(ref.ConnectionSlot),
				PublisherConnectionId: ref.PublisherConnectionID, RelayId: "relay_1", RelayLeaseRevision: 1,
				RelayRunId: "relay_run_1", RelayServiceId: ref.RelayServiceID, PublicUrlId: ref.PublicURLID, PublishRunId: ref.PublishRunID, PublishRunNumber: int64(ref.PublishRunNumber),
			}, session)
			if err != nil {
				relays <- drainTestRelay{err: err}
				return
			}
			defer connection.Close()
			relays <- drainTestRelay{connection: connection}
			if err := session.HandlePublisherDrain(ctx, connection.Drain); err == nil {
				select {
				case <-ctx.Done():
				case <-session.Done():
				}
			}
		})
	}
	return muxsession.ConnectorFunc(func(ctx context.Context, endpoint muxsession.Endpoint) (muxsession.Session, error) {
		transport, err := connector.Connect(ctx, endpoint)
		if err == nil {
			select {
			case publishers <- transport:
			case <-ctx.Done():
				_ = transport.Close()
				return nil, ctx.Err()
			}
		}
		return transport, err
	}), relays, publishers
}

package ingress

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"testing"

	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/transport/muxsession"
	"github.com/tnldotdev/tnl/internal/transport/streamcopy"
	"github.com/tnldotdev/tnl/internal/transport/tunnel"
	ingressv1 "github.com/tnldotdev/tnl/pkg/api/control/private/ingress/v1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

type serviceTransportFixture struct {
	forwarder       *Forwarder
	publisher       *tunnel.Session
	relayPublisher  *tunnel.Session
	publisherServer *forwardingTestServer
	relayServer     *forwardingTestServer
	ref             tunnelv1.ServicePublisherConnectionRef
	relay           ingressv1.ServiceRelay
	transfers       chan serviceTransportTransfer
	close           func() error
}

type serviceTransportTransfer struct {
	streamcopy.Result
	err error
}

// both hops use verified WSS/yamux and real service stream acknowledgments.
func newServiceTransportFixture(t *testing.T, ref tunnelv1.ServicePublisherConnectionRef, relay ingressv1.ServiceRelay) *serviceTransportFixture {
	t.Helper()
	material := newForwardingTestMaterial(t)
	f := &serviceTransportFixture{ref: ref, relay: relay, transfers: make(chan serviceTransportTransfer, 8)}
	registered := make(chan *tunnel.Session, 1)
	f.publisherServer = startForwardingTestServer(t, material, func(ctx context.Context, transport muxsession.Session) error {
		session, _, err := tunnel.Accept(ctx, transport, func(_ context.Context, hello tunnelv1.Message) error {
			if hello.Role != tunnelv1.Publisher || hello.Credential != "service-publisher-credential" ||
				hello.ServiceConnection == nil || *hello.ServiceConnection != ref {
				return &tunnel.ProtocolError{Code: tunnelv1.Unauthenticated}
			}
			return nil
		})
		if err != nil {
			return err
		}
		defer session.Close()
		registered <- session
		return session.ServeServiceCapacity(ctx)
	})
	setup := ingressContext(t)
	transport, err := (muxsession.WebSocketConnector{TLSConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: material.roots}}).Connect(
		setup, muxsession.Endpoint{Address: f.publisherServer.address(), ServerName: material.serverName})
	if err != nil {
		t.Fatal(err)
	}
	f.publisher, err = tunnel.Dial(setup, transport, tunnelv1.Message{
		Type: tunnelv1.Hello, ProtocolVersion: tunnelv1.Version, Role: tunnelv1.Publisher,
		Credential: "service-publisher-credential", ServiceConnection: &ref,
	})
	if err != nil {
		_ = transport.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.publisher.Close() })
	f.relayPublisher = ingressAwait(t, registered)
	f.relayServer = startForwardingTestServer(t, material, func(ctx context.Context, transport muxsession.Session) error {
		session, _, err := tunnel.Accept(ctx, transport, func(_ context.Context, hello tunnelv1.Message) error {
			if hello.Role != tunnelv1.Ingress || hello.Credential != forwardingClusterSecret ||
				hello.ServiceConnection != nil {
				return &tunnel.ProtocolError{Code: tunnelv1.Unauthenticated}
			}
			return nil
		})
		if err != nil {
			return err
		}
		defer session.Close()
		for {
			incoming, err := session.AcceptServiceForwardingStream(ctx)
			if err != nil {
				if failure.Only(err, context.Canceled) || failure.Only(err, io.EOF) || failure.Only(err, net.ErrClosed) || failure.Only(err, muxsession.ErrClosed) {
					return nil
				}
				return err
			}
			request := incoming
			if request.Header.Validate() != nil || tunnel.ServiceForwardingRef(request.Header) != ref ||
				request.Header.RelayID != relay.RelayId || request.Header.RelayRunID != relay.RelayRunId ||
				request.Header.RelayLeaseRevision != uint64(relay.RelayLeaseRevision) {
				_ = incoming.Stream().Close()
				return errors.New("service relay received another run or relay lease")
			}
			if err := func() error {
				defer incoming.Stream().Close()
				unregister, err := f.relayPublisher.RegisterServiceCapacity(ctx, request.Header, func(call context.Context) error {
					return session.RequestServiceCapacity(call, request.Header)
				})
				if err != nil {
					return err
				}
				defer unregister()
				upstream, err := f.relayPublisher.OpenServiceForwardingStream(ctx, request.Header)
				if err != nil {
					return err
				}
				defer upstream.Close()
				// publisher acceptance precedes relay acceptance, which precedes all
				// metadata and visitor bytes from ingress.
				if err := incoming.Accept(); err != nil {
					return err
				}
				copied, err := streamcopy.Copy(incoming.Stream(), upstream)
				// a visitor stream failure does not close the shared relay session.
				// callers assert each transfer's bytes and expected close result.
				f.transfers <- serviceTransportTransfer{Result: copied, err: err}
				return nil
			}(); err != nil {
				return err
			}
		}
	})
	f.relay.InternalRelayAddress, f.relay.TlsServerName = f.relayServer.address(), material.serverName
	connector, err := newWebSocketRelayConnector(&tls.Config{MinVersion: tls.VersionTLS13, RootCAs: material.roots}, forwardingClusterSecret, muxsession.WebSocketConfig{})
	if err != nil {
		t.Fatal(err)
	}
	f.forwarder = newForwarder(connector)
	f.close = sync.OnceValue(func() error {
		f.relayServer.cancel()
		f.publisherServer.cancel()
		_ = f.relayServer.listener.Close()
		_ = f.publisherServer.listener.Close()
		err := errors.Join(f.forwarder.Close(), f.publisher.Close(), f.relayPublisher.Close())
		f.relayServer.active.Wait()
		f.publisherServer.active.Wait()
		return err
	})
	t.Cleanup(func() {
		if err := f.close(); err != nil {
			t.Error("close service transport fixture", err)
		}
	})
	return f
}

func (f *serviceTransportFixture) open(ctx context.Context, header tunnelv1.ServiceForwardingHeader, reserveCapacity func(context.Context) error) (net.Conn, error) {
	if tunnel.ServiceForwardingRef(header) != f.ref {
		return nil, fmt.Errorf("service forwarding changed the claimed publisher connection")
	}
	return f.forwarder.OpenService(ctx, f.relay, header, reserveCapacity)
}

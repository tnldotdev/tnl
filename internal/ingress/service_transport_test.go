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
	close           func() error
}

// both hops use verified TLS/yamux and real service stream acknowledgments.
func newServiceTransportFixture(t *testing.T, ref tunnelv1.ServicePublisherConnectionRef, relay ingressv1.ServiceRelay) *serviceTransportFixture {
	t.Helper()
	material := newForwardingTestMaterial(t)
	f := &serviceTransportFixture{ref: ref, relay: relay}
	registered := make(chan *tunnel.Session, 1)
	f.publisherServer = startForwardingTestServer(t, material, func(ctx context.Context, transport muxsession.Session) error {
		session, _, err := tunnel.Accept(ctx, transport, func(_ context.Context, hello tunnelv1.Message) error {
			if hello.Role != tunnelv1.Publisher || hello.Credential != "service-publisher-credential" ||
				hello.PublisherConnection != nil || hello.ServiceConnection == nil || *hello.ServiceConnection != ref {
				return &tunnel.ProtocolError{Code: tunnelv1.Unauthenticated}
			}
			return nil
		})
		if err != nil {
			return err
		}
		defer session.Close()
		registered <- session
		select {
		case <-ctx.Done():
		case <-session.Done():
		}
		return nil
	})
	setup := ingressContext(t)
	transport, err := (muxsession.TLSYamuxConnector{TLSConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: material.roots}}).Connect(
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
				hello.PublisherConnection != nil || hello.ServiceConnection != nil {
				return &tunnel.ProtocolError{Code: tunnelv1.Unauthenticated}
			}
			return nil
		})
		if err != nil {
			return err
		}
		defer session.Close()
		for {
			incoming, err := session.AcceptInternalForwardingStream(ctx)
			if err != nil {
				if failure.Only(err, context.Canceled) || failure.Only(err, io.EOF) || failure.Only(err, net.ErrClosed) || failure.Only(err, muxsession.ErrClosed) {
					return nil
				}
				return err
			}
			request, ok := incoming.(*tunnel.IncomingServiceForwardingStream)
			if !ok {
				_ = incoming.Stream().Close()
				return errors.New("service relay received another forwarding kind")
			}
			if request.Header.Validate() != nil || tunnel.ServiceForwardingRef(request.Header) != ref ||
				request.Header.RelayID != relay.RelayId || request.Header.RelayRunID != relay.RelayRunId ||
				request.Header.RelayLeaseRevision != uint64(relay.RelayLeaseRevision) {
				_ = incoming.Stream().Close()
				return errors.New("service relay received another run or relay lease")
			}
			if err := func() error {
				defer incoming.Stream().Close()
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
				_, err = streamcopy.Copy(incoming.Stream(), upstream)
				return err
			}(); err != nil {
				return err
			}
		}
	})
	f.relay.InternalRelayAddress, f.relay.TlsServerName = f.relayServer.address(), material.serverName
	connector, err := newTLSRelayConnector(&tls.Config{MinVersion: tls.VersionTLS13, RootCAs: material.roots}, forwardingClusterSecret, muxsession.TLSYamuxConfig{})
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

func (f *serviceTransportFixture) open(ctx context.Context, header tunnelv1.ServiceForwardingHeader) (net.Conn, error) {
	if tunnel.ServiceForwardingRef(header) != f.ref {
		return nil, fmt.Errorf("service forwarding changed the claimed publisher connection")
	}
	return f.forwarder.OpenPrivate(ctx, f.relay, header)
}

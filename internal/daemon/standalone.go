package daemon

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"sync"
	"time"

	quic "github.com/quic-go/quic-go"
	controlingress "github.com/tnldotdev/tnl/internal/control/api/private/ingress"
	controlrelay "github.com/tnldotdev/tnl/internal/control/api/private/relay"
	daemonconfig "github.com/tnldotdev/tnl/internal/daemon/config"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/ingress"
	"github.com/tnldotdev/tnl/internal/observability"
	"github.com/tnldotdev/tnl/internal/relay"
	"github.com/tnldotdev/tnl/internal/transport/muxsession"
	relayv1 "github.com/tnldotdev/tnl/pkg/api/control/private/relay/v1"
)

const standaloneIngressID = "standalone-ingress"

var standaloneRelays = [...]struct {
	serviceID string
	relayID   string
}{
	{serviceID: "standalone-a", relayID: "standalone-relay-a"},
	{serviceID: "standalone-b", relayID: "standalone-relay-b"},
}

type standaloneSettings struct {
	control                controlSettings
	publicListen           string
	publicListener         net.Listener
	relayUDPListen         string
	quicIdleTimeout        time.Duration
	quicMaxIncomingStreams int64
	serverHostname         string
	relayHostname          string
	relayTransportTLS      *tls.Config
	ingressLeaseDuration   time.Duration
	relayLeaseDuration     time.Duration
	ingress                ingressSettings
	relay                  relaySettings
	configureDirect        func(*ingress.DirectServicesConfig)
}

func standaloneSettingsFrom(cfg daemonconfig.Config) standaloneSettings {
	return standaloneSettings{
		control:                controlSettingsFrom(cfg),
		publicListen:           cfg.IngressListen,
		relayUDPListen:         cfg.RelayUDPListen,
		quicIdleTimeout:        cfg.QUICIdleTimeout,
		quicMaxIncomingStreams: cfg.QUICMaxIncomingStreams,
		serverHostname:         cfg.ServerHostname(),
		relayHostname:          cfg.StandaloneRelayHostname(),
		ingressLeaseDuration:   cfg.IngressLeaseDuration,
		relayLeaseDuration:     cfg.RelayLeaseDuration,
		ingress:                ingressSettingsFrom(cfg),
		relay:                  relaySettingsFrom(cfg),
	}
}

func (d *daemon) startStandalone(
	ctx context.Context,
	settings standaloneSettings,
	metrics *observability.Metrics,
	controlHandler http.Handler,
) error {
	publicListener := settings.publicListener
	if publicListener == nil {
		listener, err := listenIngress(settings.publicListen, settings.ingress.servicePortRanges.Ranges(), settings.ingress.requireProxyHeader)
		if err != nil {
			return fmt.Errorf("listen for standalone public traffic: %w", err)
		}
		publicListener = listener
	}
	publicOwned := false
	defer func() {
		if !publicOwned {
			_ = publicListener.Close()
		}
	}()

	relayListener := newConnectionListener(publicListener.Addr())
	if err := d.startControl(settings.control, controlHandler); err != nil {
		return err
	}

	transportTLS := settings.relayTransportTLS
	var certificateChanged func(relayv1.RelayTransportCertificate) error
	if transportTLS == nil {
		serviceIDs := make([]string, len(standaloneRelays))
		for index, identity := range standaloneRelays {
			serviceIDs[index] = identity.serviceID
		}
		certificateSource, err := newSharedRelayCertificateSource(serviceIDs, settings.relayHostname)
		if err != nil {
			return err
		}
		transportTLS = certificateSource.TLSConfig()
		certificateChanged = certificateSource.Install
	}
	maxStreams, err := runtimeCapacity("publisher connection stream", settings.quicMaxIncomingStreams)
	if err != nil {
		return err
	}
	targets := make(map[string]*relayRuntime, len(standaloneRelays))
	relayClient, err := controlrelay.NewDirectClient(controlrelay.DirectConfig{
		Store: d.database, LeaseDuration: settings.relayLeaseDuration,
	})
	if err != nil {
		return err
	}
	for _, identity := range standaloneRelays {
		internalListener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			return fmt.Errorf("listen for standalone internal forwarding: %w", err)
		}
		runtime, err := d.startRelayRuntime(ctx, settings.relay, relayRuntimeConfig{
			client: relayClient, relayServiceID: identity.serviceID, relayID: identity.relayID,
			relayAddress: net.JoinHostPort(settings.relayHostname, "443"), tlsServerName: settings.relayHostname,
			transportTLS: transportTLS, certificateChanged: certificateChanged, clusterSecrets: d.clusterSecrets,
			internalAddress: internalListener.Addr().String(), internalListener: internalListener, metrics: metrics,
		})
		if err != nil {
			_ = internalListener.Close()
			return err
		}
		targets[identity.serviceID] = runtime
	}
	publisher, err := relay.NewPublisherAcceptor(relay.PublisherAcceptorConfig{
		Observer: metrics,
		Native: func(id string) (*relay.NativeConnectorAcceptor, bool) {
			runtime, ok := targets[id]
			if !ok {
				return nil, false
			}
			return runtime.native, true
		},
		Private: &relay.ServicePublisherAcceptor{Select: func(id string) (relay.ServicePublisherTarget, bool) {
			runtime, ok := targets[id]
			if !ok {
				return relay.ServicePublisherTarget{}, false
			}
			return relay.ServicePublisherTarget{Control: runtime.controller, Registry: runtime.serviceRegistry}, true
		}},
		Select: func(relayServiceID string) (relay.PublisherConnectionController, *relay.Registry, bool) {
			runtime, ok := targets[relayServiceID]
			if !ok {
				return nil, nil, false
			}
			return runtime.controller, runtime.registry, true
		},
		ReadyConnectionsDelta: func(delta int) { metrics.AddReadyPublisherConnections(delta) },
		ConnectionExited:      func(unexpected bool) { metrics.ObservePublisherExit(unexpected) },
		CapacityRejected:      func() { metrics.IncCapacityRejection("publisher_connections") },
		Report: func(err error) {
			logOperationalError(ctx, "serve standalone relay publisher", failure.ServerConnectionFailed, err)
		},
	})
	if err != nil {
		return err
	}
	d.relays[0].tcpListener = relayListener
	d.start("serve TLS/TCP publisher connections", func() error {
		return serveTLSYamuxSessions(ctx, relayListener, transportTLS,
			muxsession.TLSYamuxConfig{MaxIncomingStreams: maxStreams}, publisher.Accept)
	})

	ingressClient, err := controlingress.NewDirectClient(controlingress.DirectConfig{
		Store: d.database, LeaseDuration: settings.ingressLeaseDuration,
	})
	if err != nil {
		return err
	}
	if err := d.startIngressRuntime(ctx, settings.ingress, metrics, ingressRuntimeConfig{
		client: ingressClient, ingressID: standaloneIngressID, listener: publicListener,
		clusterSecret: d.clusterSecret, configureDirect: settings.configureDirect,
		configure: func(ingressConfig *ingress.Config) {
			// only publisher transport is handed off from raw visitor ingress.
			ingressConfig.RelayHostname = settings.relayHostname
			ingressConfig.HandleRelay = relayListener.Enqueue
		},
	}); err != nil {
		return err
	}
	sharedTLS := &tls.Config{MinVersion: tls.VersionTLS13, GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
		if hello.ServerName != settings.relayHostname {
			return nil, errors.New("standalone QUIC infrastructure hostname is not configured")
		}
		selected := transportTLS.Clone()
		selected.NextProtos = []string{muxsession.ALPN}
		selected.MinVersion = tls.VersionTLS13
		selected.GetConfigForClient = nil
		return selected, nil
	}}
	udpListener, err := muxsession.ListenQUIC(settings.relayUDPListen, sharedTLS, muxsession.QUICConfig{Config: &quic.Config{
		MaxIdleTimeout: settings.quicIdleTimeout, MaxIncomingStreams: settings.quicMaxIncomingStreams,
		EnableDatagrams: true,
	}})
	if err != nil {
		return fmt.Errorf("listen for standalone QUIC infrastructure: %w", err)
	}
	d.relays[0].udpListener = udpListener
	d.start("serve standalone QUIC infrastructure", func() error {
		return serveQUICSessions(ctx, udpListener, func(ctx context.Context, session muxsession.Session) error {
			peer, ok := session.(muxsession.AcceptedPeer)
			if !ok {
				_ = session.Close()
				return errors.New("standalone QUIC handshake identity is unavailable")
			}
			state := peer.TLSConnectionState()
			if state.NegotiatedProtocol == muxsession.ALPN && state.ServerName == settings.relayHostname {
				return publisher.Accept(ctx, session)
			}
			_ = session.Close()
			return errors.New("standalone QUIC role does not match its infrastructure hostname")
		})
	})
	publicOwned = true
	log.Printf("relay publisher TCP listening on %s for %s", publicListener.Addr(), settings.relayHostname)
	log.Printf("relay publisher UDP listening on %s", udpListener.Addr())
	return nil
}

type connectionListener struct {
	address     net.Addr
	connections chan net.Conn
	closed      chan struct{}
	once        sync.Once
}

func newConnectionListener(address net.Addr) *connectionListener {
	return &connectionListener{address: address, connections: make(chan net.Conn), closed: make(chan struct{})}
}

func (l *connectionListener) Accept() (net.Conn, error) {
	select {
	case connection := <-l.connections:
		return connection, nil
	case <-l.closed:
		return nil, net.ErrClosed
	}
}

func (l *connectionListener) Close() error {
	l.once.Do(func() { close(l.closed) })
	return nil
}

func (l *connectionListener) Addr() net.Addr { return l.address }

func (l *connectionListener) Enqueue(connection net.Conn) bool {
	select {
	case l.connections <- connection:
		return true
	case <-l.closed:
		return false
	}
}

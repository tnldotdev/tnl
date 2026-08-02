package tnldruntime

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"net/http"
	"sync"
	"time"

	quic "github.com/quic-go/quic-go"
	"github.com/tnldotdev/tnl/internal/ingress"
	"github.com/tnldotdev/tnl/internal/ingressapi"
	"github.com/tnldotdev/tnl/internal/muxsession"
	"github.com/tnldotdev/tnl/internal/observability"
	"github.com/tnldotdev/tnl/internal/relay"
	"github.com/tnldotdev/tnl/internal/relayapi"
	"github.com/tnldotdev/tnl/internal/tnldconfig"
	"github.com/tnldotdev/tnl/pkg/api/relayv1"
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
	publicListen           string
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
}

func standaloneSettingsFrom(cfg tnldconfig.Config) standaloneSettings {
	return standaloneSettings{
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
	publicListener, err := net.Listen("tcp", settings.publicListen)
	if err != nil {
		return fmt.Errorf("listen for standalone public traffic: %w", err)
	}
	publicOwned := false
	defer func() {
		if !publicOwned {
			_ = publicListener.Close()
		}
	}()

	controlListener := newConnectionListener(publicListener.Addr())
	relayListener := newConnectionListener(publicListener.Addr())
	d.controlListener = controlListener
	d.controlServer = controlHTTPServer(controlHandler, d.controlTLS)
	d.forward("serve control API", serveTLS(d.controlServer, controlListener))

	transportTLS := settings.relayTransportTLS
	var certificateChanged func(relayv1.RelayServiceCertificate) error
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
	targets := make(map[string]*relayRuntime, len(standaloneRelays))
	relayClient, err := relayapi.NewDirectClient(relayapi.DirectConfig{
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
		Select: func(relayServiceID string) (relay.PublisherConnectionController, *relay.Registry, bool) {
			runtime, ok := targets[relayServiceID]
			if !ok {
				return nil, nil, false
			}
			return runtime.controller, runtime.registry, true
		},
		ReadyConnectionsDelta: func(delta int) { metrics.AddPublisherConnections("ready", delta) },
		Report:                func(err error) { log.Printf("relay publisher: %v", err) },
	})
	if err != nil {
		return err
	}
	maxStreams, err := runtimeCapacity("publisher connection stream", settings.quicMaxIncomingStreams)
	if err != nil {
		return err
	}
	udpListener, err := muxsession.ListenQUIC(settings.relayUDPListen, transportTLS, muxsession.QUICConfig{Config: &quic.Config{
		MaxIdleTimeout: settings.quicIdleTimeout, MaxIncomingStreams: settings.quicMaxIncomingStreams,
	}})
	if err != nil {
		return fmt.Errorf("listen for standalone QUIC publisher connections: %w", err)
	}
	d.relays[0].tcpListener = relayListener
	d.relays[0].udpListener = udpListener
	d.forward("serve TLS/TCP publisher connections", serveTLSYamuxSessions(
		ctx, relayListener, transportTLS,
		muxsession.TLSYamuxConfig{MaxIncomingStreams: maxStreams}, publisher.Accept,
	))
	d.forward("serve QUIC publisher connections", serveQUICSessions(ctx, udpListener, publisher.Accept))

	ingressClient, err := ingressapi.NewDirectClient(ingressapi.DirectConfig{
		Store: d.database, LeaseDuration: settings.ingressLeaseDuration,
	})
	if err != nil {
		return err
	}
	if err := d.startIngressRuntime(ctx, settings.ingress, metrics, ingressRuntimeConfig{
		client: ingressClient, ingressID: standaloneIngressID, listener: publicListener,
		clusterSecret: d.clusterSecret,
		configure: func(ingressConfig *ingress.Config) {
			ingressConfig.ServerHostname = settings.serverHostname
			ingressConfig.HandleControl = controlListener.Enqueue
			ingressConfig.RelayHostname = settings.relayHostname
			ingressConfig.HandleRelay = relayListener.Enqueue
			ingressConfig.HandleRelayChallenge = controlListener.Enqueue
		},
	}); err != nil {
		return err
	}
	publicOwned = true
	log.Printf("control API listening on %s for %s", publicListener.Addr(), settings.serverHostname)
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

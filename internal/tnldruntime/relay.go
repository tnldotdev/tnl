package tnldruntime

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
	"github.com/tnldotdev/tnl/internal/muxsession"
	"github.com/tnldotdev/tnl/internal/observability"
	"github.com/tnldotdev/tnl/internal/opaqueid"
	"github.com/tnldotdev/tnl/internal/relay"
	"github.com/tnldotdev/tnl/internal/serviceapi"
	"github.com/tnldotdev/tnl/internal/tnldconfig"
	"github.com/tnldotdev/tnl/pkg/api/relayv1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

type relayRuntime struct {
	controller       *relay.Controller
	registry         *relay.Registry
	publisher        *relay.PublisherAcceptor
	transportTLS     *tls.Config
	tcpListener      net.Listener
	udpListener      *muxsession.QUICListener
	internalListener net.Listener
	drainOnce        sync.Once
}

type relayProcessSettings struct {
	controlEndpoint        string
	controlAddress         string
	clusterSecret          string
	relayServiceID         string
	relayID                string
	relayAddress           string
	tlsServerName          string
	transportTLS           *tls.Config
	internalListen         string
	internalAddress        string
	tcpListen              string
	udpListen              string
	quicPacketIOMode       tnldconfig.RelayQUICPacketIOMode
	quicIdleTimeout        time.Duration
	quicMaxIncomingStreams int64
	runtime                relaySettings
}

func relayProcessSettingsFrom(cfg tnldconfig.Config) relayProcessSettings {
	tlsServerName, _, _ := net.SplitHostPort(cfg.RelayAddress)
	return relayProcessSettings{
		controlEndpoint: cfg.PrivateControlEndpoint(), controlAddress: cfg.PrivateControlAddress,
		clusterSecret:  cfg.ClusterSecret,
		relayServiceID: cfg.RelayServiceID, relayID: cfg.RelayID,
		relayAddress: cfg.RelayAddress, tlsServerName: tlsServerName,
		internalListen:         cfg.InternalRelayListen,
		internalAddress:        cfg.InternalRelayAddress,
		tcpListen:              cfg.RelayTCPListen,
		udpListen:              cfg.RelayUDPListen,
		quicPacketIOMode:       cfg.RelayQUICPacketIOMode,
		quicIdleTimeout:        cfg.QUICIdleTimeout,
		quicMaxIncomingStreams: cfg.QUICMaxIncomingStreams,
		runtime:                relaySettingsFrom(cfg),
	}
}

func (d *daemon) startRelay(ctx context.Context, settings relayProcessSettings, metrics *observability.Metrics) error {
	privateClient, err := newRelayControlClient(
		settings.controlEndpoint, settings.clusterSecret, d.serviceHTTP, settings.controlAddress,
	)
	if err != nil {
		return err
	}
	internalListener, err := net.Listen("tcp", settings.internalListen)
	if err != nil {
		return fmt.Errorf("listen for internal forwarding: %w", err)
	}
	transportTLS := settings.transportTLS
	var certificateChanged func(relayv1.RelayServiceCertificate) error
	if transportTLS == nil {
		certificateSource, err := newRelayCertificateSource(settings.relayServiceID, settings.tlsServerName)
		if err != nil {
			_ = internalListener.Close()
			return err
		}
		transportTLS = certificateSource.TLSConfig()
		certificateChanged = certificateSource.Install
	}
	runtime, err := d.startRelayRuntime(ctx, settings.runtime, relayRuntimeConfig{
		client: privateClient, relayServiceID: settings.relayServiceID, relayID: settings.relayID,
		relayAddress: settings.relayAddress, tlsServerName: settings.tlsServerName,
		transportTLS: transportTLS, certificateChanged: certificateChanged, clusterSecrets: d.clusterSecrets,
		internalAddress: settings.internalAddress, internalListener: internalListener, metrics: metrics,
	})
	if err != nil {
		_ = internalListener.Close()
		return err
	}
	tcpListener, err := net.Listen("tcp", settings.tcpListen)
	if err != nil {
		return fmt.Errorf("listen for TLS/TCP publisher connections: %w", err)
	}
	runtime.tcpListener = tcpListener
	udpListener, err := muxsession.ListenQUIC(settings.udpListen, runtime.transportTLS, muxsession.QUICConfig{
		Config: &quic.Config{
			MaxIdleTimeout: settings.quicIdleTimeout, MaxIncomingStreams: settings.quicMaxIncomingStreams,
		},
		PacketIOMode: muxsession.QUICPacketIOMode(settings.quicPacketIOMode),
	})
	if err != nil {
		return fmt.Errorf("listen for QUIC publisher connections: %w", err)
	}
	runtime.udpListener = udpListener
	maxStreams, err := runtimeCapacity("publisher connection stream", settings.quicMaxIncomingStreams)
	if err != nil {
		return err
	}
	d.forward("serve TLS/TCP publisher connections", serveTLSYamuxSessions(
		ctx, tcpListener, runtime.transportTLS,
		muxsession.TLSYamuxConfig{MaxIncomingStreams: maxStreams}, runtime.publisher.Accept,
	))
	d.forward("serve QUIC publisher connections", serveQUICSessions(ctx, udpListener, runtime.publisher.Accept))
	log.Printf("relay publisher TCP listening on %s", tcpListener.Addr())
	log.Printf("relay publisher UDP listening on %s", udpListener.Addr())
	return nil
}

type relayRuntimeConfig struct {
	client             relay.ControlClient
	relayServiceID     string
	relayID            string
	relayAddress       string
	tlsServerName      string
	transportTLS       *tls.Config
	certificateChanged func(relayv1.RelayServiceCertificate) error
	clusterSecrets     serviceapi.BearerSecrets
	internalAddress    string
	internalListener   net.Listener
	metrics            *observability.Metrics
}

type relaySettings struct {
	publisherConnectionLimit int64
	streamCapacity           int64
	leaseRenewalInterval     time.Duration
	controlRetryInterval     time.Duration
}

func relaySettingsFrom(cfg tnldconfig.Config) relaySettings {
	return relaySettings{
		publisherConnectionLimit: cfg.PublisherConnectionLimit,
		streamCapacity:           cfg.RelayStreamCapacity,
		leaseRenewalInterval:     cfg.LeaseRenewalInterval,
		controlRetryInterval:     cfg.ControlRetryInterval,
	}
}

func (d *daemon) startRelayRuntime(
	ctx context.Context,
	settings relaySettings,
	runtimeConfig relayRuntimeConfig,
) (*relayRuntime, error) {
	if runtimeConfig.transportTLS == nil {
		return nil, errors.New("relay TLS certificate is not configured")
	}
	runtime := &relayRuntime{internalListener: runtimeConfig.internalListener}
	if runtimeConfig.metrics != nil {
		runtimeConfig.metrics.AddRelayLeases("active", 0)
		runtimeConfig.metrics.AddRelayLeases("draining", 0)
		runtimeConfig.metrics.AddPublisherConnections("ready", 0)
	}
	runID, err := opaqueid.New("relay_run_")
	if err != nil {
		return nil, fmt.Errorf("create relay process run ID: %w", err)
	}
	registry := relay.NewRegistry()
	runtime.registry = registry
	controller, err := relay.NewController(relay.ControllerConfig{
		Client: runtimeConfig.client,
		Registration: relayv1.RelayRegistration{
			RelayServiceId: runtimeConfig.relayServiceID, RelayId: runtimeConfig.relayID, RelayRunId: runID,
			ProtocolVersion: tunnelv1.Version, RelayAddress: runtimeConfig.relayAddress,
			TlsServerName: runtimeConfig.tlsServerName, InternalRelayAddress: runtimeConfig.internalAddress,
			InternalNetworks: []string{}, ConnectionCapacity: settings.publisherConnectionLimit,
			StreamCapacity: settings.streamCapacity,
		},
		RenewalInterval: settings.leaseRenewalInterval, RetryInterval: settings.controlRetryInterval,
		CertificateChanged: runtimeConfig.certificateChanged,
		Load:               registry.Load, LeaseChanged: func(previous, current relayv1.RelayLease) {
			if !previous.Draining && current.Draining && current.DrainDeadline != nil {
				deadline := *current.DrainDeadline
				runtime.drainOnce.Do(func() {
					go func() {
						ctx, cancel := context.WithDeadline(context.Background(), deadline)
						defer cancel()
						_ = runtime.registry.Drain(ctx)
						_ = runtime.registry.Close()
					}()
				})
			}
			previousState, currentState := relayLeaseMetricState(previous), relayLeaseMetricState(current)
			if previousState == currentState || runtimeConfig.metrics == nil {
				return
			}
			if previousState != "" {
				runtimeConfig.metrics.AddRelayLeases(previousState, -1)
			}
			if currentState != "" {
				runtimeConfig.metrics.AddRelayLeases(currentState, 1)
			}
		},
	})
	if err != nil {
		return nil, err
	}
	runtime.controller = controller
	publisherAcceptor, err := relay.NewPublisherAcceptor(relay.PublisherAcceptorConfig{
		Control: controller, Registry: registry,
		ReadyConnectionsDelta: func(delta int) {
			if runtimeConfig.metrics != nil {
				runtimeConfig.metrics.AddPublisherConnections("ready", delta)
			}
		},
		Report: func(err error) { log.Printf("relay publisher: %v", err) },
	})
	if err != nil {
		return nil, err
	}
	runtime.publisher = publisherAcceptor
	streamCapacity, err := runtimeCapacity("relay stream", settings.streamCapacity)
	if err != nil {
		return nil, err
	}
	forwardingAcceptor, err := relay.NewForwardingAcceptor(relay.ForwardingAcceptorConfig{
		Registry: registry, ClusterSecrets: runtimeConfig.clusterSecrets, StreamCapacity: streamCapacity,
		Report: func(err error) { log.Printf("relay forwarding: %v", err) },
	})
	if err != nil {
		return nil, err
	}
	runtime.transportTLS = runtimeConfig.transportTLS
	d.relays = append(d.relays, runtime)

	d.forward("run relay control", runAsync(func() error { return controller.Run(ctx) }))
	d.forward("serve internal forwarding", serveTLSYamuxSessions(
		ctx, runtimeConfig.internalListener, runtimeConfig.transportTLS,
		muxsession.TLSYamuxConfig{MaxIncomingStreams: streamCapacity}, forwardingAcceptor.Accept,
	))
	log.Printf("relay internal forwarding listening on %s", runtimeConfig.internalListener.Addr())
	return runtime, nil
}

func relayLeaseMetricState(lease relayv1.RelayLease) string {
	if lease.RelayLeaseRevision == 0 {
		return ""
	}
	if lease.Draining {
		return "draining"
	}
	return "active"
}

func newRelayControlClient(endpoint, clusterSecret string, base *http.Client, dialAddress string) (*relayv1.ClientWithResponses, error) {
	client, err := newPrivateServiceHTTPClient(base, clusterSecret, dialAddress)
	if err != nil {
		return nil, err
	}
	return relayv1.NewClientWithResponses(endpoint, relayv1.WithHTTPClient(client))
}

type sessionAcceptFunc func(context.Context, muxsession.Session) error

func serveTLSYamuxSessions(
	ctx context.Context,
	listener net.Listener,
	tlsConfig *tls.Config,
	transportConfig muxsession.TLSYamuxConfig,
	accept sessionAcceptFunc,
) <-chan error {
	return runAsync(func() error {
		var active sync.WaitGroup
		defer active.Wait()
		for {
			connection, err := listener.Accept()
			if err != nil {
				if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
					return nil
				}
				return err
			}
			active.Go(func() {
				transport, err := muxsession.AcceptTLSYamux(ctx, connection, tlsConfig, transportConfig)
				if err == nil {
					err = accept(ctx, transport)
				}
				if err != nil && ctx.Err() == nil {
					log.Printf("relay TLS/TCP session: %v", err)
				}
			})
		}
	})
}

func serveQUICSessions(
	ctx context.Context,
	listener *muxsession.QUICListener,
	accept sessionAcceptFunc,
) <-chan error {
	return runAsync(func() error {
		var active sync.WaitGroup
		defer active.Wait()
		for {
			transport, err := listener.Accept(ctx)
			if err != nil {
				if ctx.Err() != nil || errors.Is(err, net.ErrClosed) || errors.Is(err, muxsession.ErrClosed) {
					return nil
				}
				return err
			}
			active.Go(func() {
				if err := accept(ctx, transport); err != nil && ctx.Err() == nil {
					log.Printf("relay QUIC session: %v", err)
				}
			})
		}
	})
}

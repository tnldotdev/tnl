// package stream owns connector service preparation, local listeners and stream use.
package stream

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"errors"
	"net"
	"time"

	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/observability"
	"github.com/tnldotdev/tnl/internal/transport/muxsession"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

var ErrServiceConnection = errors.New("service: authenticated connection is unavailable")

// Signer binds one tagged subject to its enrolled key. signing is preparation
// work; neither local application arrival nor a copied application stream signs.
type Signer struct {
	Subject   tunnelv1.VisitorSubject
	PublicKey ed25519.PublicKey
	Sign      func([]byte) []byte `json:"-"`
}

func (Signer) String() string   { return "private connector signer" }
func (Signer) GoString() string { return "private connector signer" }

// Run is control's selected publisher and approved visitor TLS identity. target
// trust stays at the publisher; a selection alone does not admit a stream.
type Run struct {
	ServiceID, ServiceRunID string
	RunNumber               uint64
	ValidUntil              time.Time
	Protocol                string
	TrustRevision           int64
	Endpoint                *controlv1.ServiceEndpoint
	ServiceTLS              *tls.Config `json:"-"`
	PairReady               *controlv1.ConnectorPeerPairReady
}

func (Run) String() string   { return "selected service run" }
func (Run) GoString() string { return "selected service run" }

type Control interface {
	ConnectorSigner(context.Context, string) (Signer, error)
	ResolveService(context.Context, string) (Run, error)
	PrepareConnectorPeerPair(context.Context, string, controlv1.ConnectorPeerPairRequest) (controlv1.ConnectorPeerPair, error)
	RenewConnectorPeerPair(context.Context, string, controlv1.ConnectorPeerPairRequest) (controlv1.ConnectorPeerPairRenewal, error)
	VisitorPermission(context.Context, string) (controlv1.VisitorTokenResponse, error)
}

type Config struct {
	Control                         Control
	ServiceID, IdentityID, Protocol string
	TrustRevision                   int64
	Ready                           func() error
	TransportTLS                    *tls.Config
	MaxConnections                  int
	Endpoint                        *controlv1.ServiceEndpoint
	ServiceTLS                      *tls.Config            `json:"-"`
	CleanupContext                  func() context.Context `json:"-"`
	RelayQUIC, RelayTCP             muxsession.Connector
}

func (Config) String() string   { return "private connector configuration" }
func (Config) GoString() string { return "private connector configuration" }

// Serve prepares both relay carriers, the publisher's actual inner QUIC session
// and signed openings before advertising local readiness. switching to the warm
// sibling changes packet delivery, never an application stream or its target.
func Serve(ctx context.Context, listener net.Listener, config Config) error {
	if listener == nil {
		return ErrServiceConnection
	}
	address, ok := listener.Addr().(*net.TCPAddr)
	if !ok || !address.IP.IsLoopback() {
		return ErrServiceConnection
	}
	return serveConnections(ctx, config, func(ctx context.Context, forward func(context.Context, net.Conn) error) error {
		return serveLoopback(ctx, listener, config.MaxConnections, config.Ready, func(ctx context.Context, local net.Conn) { _ = forward(ctx, local) })
	})
}

// Stream owns exactly one stdio application stream, including both copy
// directions. a failed admitted stream is never retried on another carrier.
func Stream(ctx context.Context, local net.Conn, config Config) error {
	if local == nil || config.Protocol != "tcp" {
		return ErrServiceConnection
	}
	defer local.Close()
	closed := make(chan struct{})
	stop := context.AfterFunc(ctx, func() { defer close(closed); _ = local.Close() })
	defer func() {
		if !stop() {
			<-closed
		}
	}()
	return serveConnections(ctx, config, func(ctx context.Context, forward func(context.Context, net.Conn) error) error {
		return forward(ctx, local)
	})
}

type connectionConsumer func(context.Context, func(context.Context, net.Conn) error) error

func serveConnections(ctx context.Context, config Config, consume connectionConsumer) (result error) {
	p, err := Prepare(ctx, config)
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, p.Close()) }()
	err = consume(p.Context(), p.Forward)
	if ctx.Err() != nil {
		if errors.Is(context.Cause(ctx), context.Canceled) {
			return nil
		}
		return errors.Join(context.Cause(ctx), err)
	}
	if p.Context().Err() != nil {
		return errors.Join(ErrServiceConnection, context.Cause(p.Context()), err)
	}
	return err
}

// Prepare owns the same paired relay and retained inner QUIC lifetime as Serve.
// a caller without a local listener supplies application connections to Forward
// and must Close to join transport, authority, and forwarding work.
func Prepare(ctx context.Context, config Config) (_ *Session, result error) {
	startup, finish := observability.ClientOperation(ctx, "connector.startup")
	defer func() { finish(result) }()
	if config.Control == nil || !opaqueid.Valid(config.ServiceID, opaqueid.ServicePrefix) || config.IdentityID != "" && !opaqueid.Valid(config.IdentityID, opaqueid.IdentityPrefix) || !ValidProtocol(config.Protocol) || config.TrustRevision < 1 || config.Endpoint == nil || config.Endpoint.Hostname == "" || config.Endpoint.Port < 1024 || config.Endpoint.Port > 65535 {
		return nil, ErrServiceConnection
	}
	if config.TransportTLS != nil && config.TransportTLS.InsecureSkipVerify || config.ServiceTLS == nil || config.ServiceTLS.InsecureSkipVerify || len(config.ServiceTLS.Certificates) != 0 || config.ServiceTLS.GetClientCertificate != nil {
		return nil, ErrServiceConnection
	}
	if config.MaxConnections == 0 {
		config.MaxConnections = 64
	}
	if config.MaxConnections < 1 || config.MaxConnections > 4096 {
		return nil, ErrServiceConnection
	}
	s := &Session{config: config, parent: ctx}
	defer func() {
		if result != nil {
			result = errors.Join(result, s.Close())
		}
	}()
	setup, stop := context.WithTimeout(startup, 30*time.Second)
	defer stop()
	signer, err := config.Control.ConnectorSigner(setup, config.IdentityID)
	if err != nil {
		return nil, err
	}
	if signer.Subject.Validate() != nil || signer.Subject.IdentityID != config.IdentityID || len(signer.PublicKey) != ed25519.PublicKeySize || signer.Sign == nil {
		return nil, ErrServiceConnection
	}
	p, err := prepareConnectorConnection(ctx, setup, config, signer)
	if err != nil {
		return nil, err
	}
	s.connection = p
	p.mu.Lock()
	s.initialRelayAddress = p.pair.Relays[0].RelayAddress
	p.mu.Unlock()
	return s, nil
}

// ValidProtocol identifies protocols supported by connector preparation.
func ValidProtocol(protocol string) bool {
	return protocol == "http" || protocol == "tcp" || protocol == "mysql" || protocol == "postgres" || protocol == "kubernetes"
}

func sameEndpoint(left, right *controlv1.ServiceEndpoint) bool {
	if left == nil || right == nil {
		return left == right
	}
	return left.Hostname == right.Hostname && left.Port == right.Port && left.Public == right.Public
}

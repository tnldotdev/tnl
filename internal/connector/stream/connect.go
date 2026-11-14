// package stream owns connector service preparation, local listeners and stream use.
package stream

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"errors"
	"net"
	"time"

	clienttelemetry "github.com/tnldotdev/tnl/internal/client/telemetry"

	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/observability"
	"github.com/tnldotdev/tnl/internal/policy/serviceendpoint"
	"github.com/tnldotdev/tnl/internal/transport/muxsession"
	"github.com/tnldotdev/tnl/internal/transport/peer"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

var ErrServiceConnection = errors.New("service: authenticated connection is unavailable")

// CleanupError distinguishes a failed resource close from the operation that
// stopped the connector. callers retain both through normal error unwrapping.
type CleanupError struct{ Err error }

func (e *CleanupError) Error() string { return "connector cleanup: " + e.Err.Error() }
func (e *CleanupError) Unwrap() error { return e.Err }

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
	RebindConnectorPeerPair(context.Context, string, string, controlv1.ConnectorPeerPairRebindRequest) (controlv1.ConnectorPeerPairRebindState, error)
	VisitorPermission(context.Context, string) (controlv1.VisitorTokenResponse, error)
	Close(context.Context) error
}

type Config struct {
	Telemetry                       *clienttelemetry.Collector
	telemetry                       *clienttelemetry.Scope
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
	Connectivity                    peer.ConnectivityOptions
	// PeerSocket is borrowed by qualification; the default connection owns one.
	PeerSocket *peer.Socket
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
	return newStdioOperation(ctx, local).serve(config)
}

type connectionConsumer func(context.Context, func(context.Context, net.Conn) error) error

func serveConnections(ctx context.Context, config Config, consume connectionConsumer) (result error) {
	startup, finish := observability.ClientOperation(ctx, "connector.startup")
	defer func() { finish(result) }()
	if config.Control == nil || !opaqueid.Valid(config.ServiceID, opaqueid.ServicePrefix) || config.IdentityID != "" && !opaqueid.Valid(config.IdentityID, opaqueid.IdentityPrefix) || !validProtocol(config.Protocol) || config.TrustRevision < 1 || config.Endpoint == nil || !serviceendpoint.Valid(config.Protocol, config.Endpoint.Hostname, config.Endpoint.Port, config.Endpoint.Public) {
		return ErrServiceConnection
	}
	if config.TransportTLS != nil && config.TransportTLS.InsecureSkipVerify || config.ServiceTLS == nil || config.ServiceTLS.InsecureSkipVerify || len(config.ServiceTLS.Certificates) != 0 || config.ServiceTLS.GetClientCertificate != nil {
		return ErrServiceConnection
	}
	if config.MaxConnections == 0 {
		config.MaxConnections = 64
	}
	if config.MaxConnections < 1 || config.MaxConnections > 4096 {
		return ErrServiceConnection
	}
	defer func() {
		cleanup := observability.Independent(context.WithoutCancel(ctx))
		if config.CleanupContext != nil {
			cleanup = config.CleanupContext()
		}
		bounded, stop := context.WithTimeout(cleanup, 5*time.Second)
		defer stop()
		err := config.Control.Close(bounded)
		if err != nil {
			result = errors.Join(result, &CleanupError{Err: err})
		}
	}()
	setup, stop := context.WithTimeout(startup, 30*time.Second)
	defer stop()
	signer, err := config.Control.ConnectorSigner(setup, config.IdentityID)
	if err != nil {
		return err
	}
	if signer.Subject.Validate() != nil || signer.Subject.IdentityID != config.IdentityID || len(signer.PublicKey) != ed25519.PublicKeySize || signer.Sign == nil {
		return ErrServiceConnection
	}
	p, err := prepareConnectorConnection(ctx, setup, config, signer)
	if err != nil {
		return err
	}
	defer p.Close()
	finish(nil)
	err = consume(p.ctx, p.Forward)
	if ctx.Err() != nil {
		if context.Cause(ctx) == context.Canceled {
			return err // the consumer already joins its owned work and classifies its stop.
		}
		return errors.Join(context.Cause(ctx), err)
	}
	if p.ctx.Err() != nil {
		// retain the established connection's retirement boundary regardless of
		// which authority or transport worker ends it first, plus its exact cause.
		return errors.Join(ErrServiceConnection, context.Cause(p.ctx), err)
	}
	return err
}

func validProtocol(protocol string) bool {
	return protocol == "http" || protocol == "tcp" || protocol == "mysql" || protocol == "postgres" || protocol == "kubernetes"
}

func sameEndpoint(left, right *controlv1.ServiceEndpoint) bool {
	if left == nil || right == nil {
		return left == right
	}
	return left.Hostname == right.Hostname && left.Port == right.Port
}

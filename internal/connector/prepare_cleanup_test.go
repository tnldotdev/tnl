package connector

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"sync/atomic"
	"testing"

	connectorruntime "github.com/tnldotdev/tnl/internal/connector/runtime"
	connectorstream "github.com/tnldotdev/tnl/internal/connector/stream"
	"github.com/tnldotdev/tnl/internal/failure"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestConnectionPreparationRetirementCleanupOrder(t *testing.T) {
	cleanupFailure := errors.New("control cleanup failed")
	for _, beforeCancel := range []bool{false, true} {
		for _, cleanup := range []struct {
			name string
			err  error
		}{
			{name: "clean"},
			{name: "failed", err: cleanupFailure},
			{name: "failed with cancellation", err: errors.Join(context.Canceled, cleanupFailure)},
			{name: "failed with closed socket", err: errors.Join(net.ErrClosed, cleanupFailure)},
			{name: "failed with obsolete connection", err: errors.Join(connectorstream.ErrServiceConnection, cleanupFailure)},
		} {
			t.Run(fmt.Sprintf("finish-before-cancel=%t/%s", beforeCancel, cleanup.name), func(t *testing.T) {
				for _, cause := range []struct {
					name string
					err  error
				}{
					{name: "expiry", err: fmt.Errorf("connector authority expired: %w", connectorstream.ErrServiceConnection)},
					{name: "transport", err: errors.New("transport failed")},
					{name: "authorization", err: failure.Wrap("renew connector authority", failure.ServerDenied, errors.New("control denied"))},
				} {
					t.Run(cause.name, func(t *testing.T) {
						// obtain the real stream result, including its actual adapter close,
						// before either controlled owner-completion ordering runs.
						var closes atomic.Int32
						control, err := connectorstream.NewControlWithConfig(connectorstream.ControlConfig{
							Signer: func(context.Context, string) (connectorstream.Signer, error) {
								return connectorstream.Signer{}, cause.err
							},
							Resolve: func(context.Context, string) (connectorstream.Run, error) { panic("unexpected selection") },
							Pair: func(context.Context, string, controlv1.ConnectorPeerPairRequest) (controlv1.ConnectorPeerPair, error) {
								panic("unexpected pair")
							},
							RenewPair: func(context.Context, string, controlv1.ConnectorPeerPairRequest) (controlv1.ConnectorPeerPairRenewal, error) {
								panic("unexpected renewal")
							},
							RebindPair: func(context.Context, string, string, controlv1.ConnectorPeerPairRebindRequest) (controlv1.ConnectorPeerPairRebindState, error) {
								panic("unexpected rebind")
							},
							Permission: func(context.Context, string) (controlv1.VisitorTokenResponse, error) { panic("unexpected permission") },
							Close:      func(context.Context) error { closes.Add(1); return cleanup.err },
						})
						if err != nil {
							t.Fatal(err)
						}
						listener, err := net.Listen("tcp4", "127.0.0.1:0")
						if err != nil {
							t.Fatal(err)
						}
						defer listener.Close()
						service := controlv1.Service{Id: "svc_aaaaaaaaaaaaaaaaaaaaaa", Protocol: controlv1.ServiceProtocolHTTP, Endpoint: &controlv1.ServiceEndpoint{Hostname: "api.example.test", Port: 443}}
						serveErr := connectorstream.Serve(t.Context(), listener, connectorstream.Config{Control: control, ServiceID: service.Id, Protocol: "http", TrustRevision: 1, Endpoint: service.Endpoint, ServiceTLS: &tls.Config{MinVersion: tls.VersionTLS13}})
						if !errors.Is(serveErr, cause.err) || closes.Load() != 1 {
							t.Fatal("stream lost its operation or joined cleanup", serveErr, closes.Load())
						}
						lifetime, cancel := context.WithCancel(t.Context())
						defer cancel()
						p := &servicePreparation{service: service, state: &servingService{}}
						owner := &ownedServiceListener{attempt: p}
						b := &connectorConnectionBackend{lifetime: lifetime, cancel: cancel, services: map[string]controlv1.Service{"api": service}, listeners: map[string]*ownedServiceListener{"api": owner}}
						if !beforeCancel {
							cancel()
						}
						b.finishPreparationLocked("api", owner, p, serveErr)
						cancel()
						if _, err := p.result(); !errors.Is(err, cause.err) || !errors.Is(err, connectorruntime.ErrUnavailable) {
							t.Fatal("retirement cause was not retained", err)
						}
						if _, err := b.Prepared("api"); !errors.Is(err, cause.err) {
							t.Fatal("prepared readers lost the retirement cause", err)
						}
						for range 2 {
							err := b.Close(t.Context())
							if cleanup.err == nil && err != nil || cleanup.err != nil && !errors.Is(err, cleanup.err) {
								t.Fatal("shutdown confused retirement with cleanup", err)
							}
							if errors.Is(err, cause.err) {
								t.Fatal("shutdown retained the operation as cleanup", err)
							}
						}
					})
				}
			})
		}
	}
}

func TestConnectionPreparationReplacedAttemptRetainsCleanup(t *testing.T) {
	for _, replacedListener := range []bool{false, true} {
		t.Run(fmt.Sprintf("listener=%t", replacedListener), func(t *testing.T) {
			old := &servicePreparation{state: &servingService{}}
			current := &servicePreparation{state: &servingService{}}
			owner := &ownedServiceListener{attempt: old}
			b := &connectorConnectionBackend{listeners: map[string]*ownedServiceListener{"api": owner}}
			if replacedListener {
				b.listeners["api"] = &ownedServiceListener{attempt: current}
			} else {
				owner.attempt = current
			}
			cleanup := errors.New("old adapter close failed")
			b.finishPreparationLocked("api", owner, old, errors.Join(connectorstream.ErrServiceConnection, &connectorstream.CleanupError{Err: cleanup}))
			if _, err := current.result(); err != nil {
				t.Fatal("old completion invalidated its replacement", err)
			}
			for range 2 {
				if err := b.Close(t.Context()); !errors.Is(err, cleanup) || errors.Is(err, connectorstream.ErrServiceConnection) {
					t.Fatal("replacement lost or misclassified old cleanup", err)
				}
			}
		})
	}
}

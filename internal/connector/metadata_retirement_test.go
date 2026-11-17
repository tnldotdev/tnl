package connector

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"math/big"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	connectorstream "github.com/tnldotdev/tnl/internal/connector/stream"
	installedjobs "github.com/tnldotdev/tnl/internal/installed"
	"github.com/tnldotdev/tnl/internal/observability"
	"github.com/tnldotdev/tnl/internal/testutil/connectorfixture"
	"github.com/tnldotdev/tnl/internal/transport/muxsession"
	"github.com/tnldotdev/tnl/internal/transport/peer"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

type metadataRetirementListener struct {
	net.Listener
	closed chan struct{}
	once   sync.Once
}

func (l *metadataRetirementListener) Close() error {
	err := l.Listener.Close()
	l.once.Do(func() { close(l.closed) })
	return err
}

// real relay TLS/TCP and inner QUIC exercise the stream owner, not a fabricated
// reload return. control facts are local fixtures; no application byte is sent.
func TestConnectRealMetadataRetirement(t *testing.T) {
	for _, kind := range []string{"clean", "operation", "connection-operation", "metadata-operation", "unowned-cancellation", "control-cleanup", "canceled-cleanup", "metadata-cleanup", "retirement-cleanup"} {
		for _, canceled := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/canceled=%t", kind, canceled), func(t *testing.T) {
				var mu sync.Mutex
				var processUntil, originalUntil time.Time
				base := observability.WithShutdownDeadline(t.Context(), func(until time.Time) time.Time {
					mu.Lock()
					defer mu.Unlock()
					if processUntil.IsZero() || until.Before(processUntil) {
						processUntil = until
					}
					return processUntil
				})
				parent, cancel := context.WithCancel(base)
				defer cancel()
				operation := errors.New("actual ready callback failed")
				cleanup := errors.New("actual control cleanup failed")
				switch kind {
				case "connection-operation":
					operation = connectorstream.ErrServiceConnection
				case "unowned-cancellation", "canceled-cleanup":
					operation, cleanup = context.Canceled, context.Canceled
				case "metadata-cleanup":
					cleanup = &connectorstream.MetadataReloadError{ServiceID: "cleanup-is-not-a-reload"}
				case "metadata-operation":
					operation = &connectorstream.MetadataReloadError{ServiceID: "independent-operation-is-not-the-owned-stop"}
				}
				operationFault := kind == "operation" || kind == "connection-operation" || kind == "metadata-operation" || kind == "unowned-cancellation"
				controlFault := kind == "control-cleanup" || kind == "canceled-cleanup" || kind == "metadata-cleanup"
				config, closes := metadataRetirementConfiguration(t, func() error {
					if canceled {
						cancel()
					}
					if controlFault {
						return cleanup
					}
					return nil
				}, func() error {
					if kind == "retirement-cleanup" {
						return cleanup
					}
					return nil
				})
				listener, err := net.Listen("tcp4", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				defer listener.Close()
				address := listener.Addr().String()
				job := installedjobs.Job{ServiceID: config.ServiceID, Name: "api", Protocol: "http", TrustRevision: 1, Target: address, Endpoint: config.Endpoint}
				calls, reads, reopened := 0, 0, 0
				replacement := errors.New("replacement runner reached")
				var produced error
				result := runConnectorLifecycle(parent, listener, job, "", connectorLifecycle{
					services: connectServiceReaderFunc(func(context.Context) ([]controlv1.ServiceSummary, error) {
						reads++
						mu.Lock()
						defer mu.Unlock()
						if !processUntil.IsZero() {
							t.Error("clean metadata retirement consumed the process exit budget before refresh", processUntil)
						}
						return []controlv1.ServiceSummary{{Id: job.ServiceID, Name: job.Name, Protocol: "http", TrustRevision: 2, Endpoint: config.Endpoint}}, nil
					}),
					listen: func(_ context.Context, next installedjobs.Job) (net.Listener, error) {
						reopened++
						if next.Target != address || next.TrustRevision != 2 || next.ServiceID != job.ServiceID {
							t.Error("metadata refresh changed the reserved listener or retained old trust")
						}
						return net.Listen("tcp4", address)
					},
					serve: func(ctx context.Context, listener net.Listener, current installedjobs.Job, ready func() error) error {
						calls++
						if calls != 1 {
							return replacement
						}
						owned := &metadataRetirementListener{Listener: listener, closed: make(chan struct{})}
						handoff, finish := connectorShutdownHandoff(ctx)
						ctx = observability.WithShutdownDeadline(handoff, func(until time.Time) time.Time {
							mu.Lock()
							originalUntil = until
							mu.Unlock()
							return observability.ShutdownDeadline(handoff, until)
						})
						config.Ready = func() error {
							if err := ready(); err != nil {
								return err
							}
							if operationFault {
								select {
								case <-owned.closed:
								case <-time.After(10 * time.Second):
									return errors.New("metadata did not retire the actual listener")
								}
								if canceled {
									cancel()
								}
								return operation
							}
							return nil
						}
						produced = connectorstream.Serve(ctx, owned, config)
						t.Logf("actual stream result: %v", produced)
						finish(produced)
						return produced
					},
					ready: func(installedjobs.Job) error { return nil },
				})
				if *closes != 1 {
					t.Error("stream did not join its actual control close", *closes)
				}
				var metadata *connectorstream.MetadataReloadError
				if !errors.As(produced, &metadata) || metadata.ServiceID != config.ServiceID {
					t.Fatal("actual stream lost the selected service's metadata stop", produced)
				}
				if kind == "clean" {
					if errors.Is(produced, connectorstream.ErrServiceConnection) {
						t.Error("clean metadata retirement manufactured a connection failure", produced)
					}
					if canceled {
						if result != nil || calls != 1 || reads != 0 || reopened != 0 {
							t.Error("clean metadata plus parent stop changed cancellation behavior", result, calls, reads, reopened)
						}
					} else if result != replacement || calls != 2 || reads != 1 || reopened != 1 {
						t.Error("actual clean stream retirement did not refresh the foreground runner", result, calls, reads, reopened)
					}
					if !processUntil.IsZero() {
						t.Error("clean metadata retirement consumed the process exit budget", processUntil)
					}
				} else {
					fault := cleanup
					if operationFault {
						fault = operation
					}
					if result != produced || !errors.Is(result, fault) || calls != 1 || reads != 0 || reopened != 0 {
						t.Error("actual mixed retirement lost a cause or restarted", result, calls, reads, reopened)
					}
					if controlFault {
						var report *connectorstream.CleanupError
						if !errors.As(result, &report) || !errors.Is(report, cleanup) {
							t.Error("actual control cleanup lost its typed report", result)
						}
					}
					if originalUntil.IsZero() || !processUntil.Equal(originalUntil) {
						t.Error("actual terminal result replaced its original cleanup deadline", processUntil, originalUntil)
					}
				}
			})
		}
	}
}

func metadataRetirementConfiguration(t *testing.T, closeControl, closeRetirement func() error) (connectorstream.Config, *int) {
	t.Helper()
	caPublic, caKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, ca, ca, caPublic, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, err = x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	service, run, workload := "svc_"+strings.Repeat("s", 22), "srun_"+strings.Repeat("r", 22), "wls_"+strings.Repeat("w", 22)
	const hostname = "metadata.example.test"
	native := connectorfixture.NewConnector(t, ca, caKey, service, run, workload, hostname, "127.0.0.1:1")
	endpoint := &controlv1.ServiceEndpoint{Hostname: hostname, Port: 443}
	permission := func(revision int64, expires time.Time) controlv1.VisitorTokenResponse {
		return controlv1.VisitorTokenResponse{Resource: controlv1.VisitorResourceScope{Kind: controlv1.VisitorResourceScopeKindService, Id: service},
			Hostname: hostname, Port: 443, ServiceTrustRevision: &revision, VisitorToken: "fixture-permission", ExpiresAt: expires}
	}
	closes := new(int)
	control, err := connectorstream.NewControlWithConfig(connectorstream.ControlConfig{
		Signer: func(context.Context, string) (connectorstream.Signer, error) {
			return connectorstream.Signer{Subject: tunnelv1.VisitorSubject{Kind: tunnelv1.VisitorWorkloadSession, WorkloadSessionID: workload}, PublicKey: public, Sign: func(message []byte) []byte { return ed25519.Sign(private, message) }}, nil
		},
		Resolve: func(context.Context, string) (connectorstream.Run, error) {
			return connectorstream.Run{ServiceID: service, ServiceRunID: run, RunNumber: 1, Protocol: "http", TrustRevision: 1, Endpoint: endpoint, PairReady: &native.Ready, ValidUntil: now.Add(time.Minute)}, nil
		},
		Pair: func(ctx context.Context, _ string, body controlv1.ConnectorPeerPairRequest) (controlv1.ConnectorPeerPair, error) {
			return native.Prepare(ctx, body, public)
		},
		RenewPair: func(ctx context.Context, _ string, body controlv1.ConnectorPeerPairRequest) (controlv1.ConnectorPeerPairRenewal, error) {
			pair, err := native.Prepare(ctx, body, public)
			return controlv1.ConnectorPeerPairRenewal{Pair: pair, RunValidUntil: pair.ExpiresAt, Protocol: "http", TrustRevision: 2, Endpoint: *endpoint, VisitorPermission: permission(2, pair.ExpiresAt)}, err
		},
		RebindPair: func(context.Context, string, string, controlv1.ConnectorPeerPairRebindRequest) (controlv1.ConnectorPeerPairRebindState, error) {
			return controlv1.ConnectorPeerPairRebindState{}, errors.New("unexpected fixture rebind")
		},
		RetirePair: func(ctx context.Context, _ string, pair string, body controlv1.ConnectorPeerPairRetireRequest) (controlv1.ConnectorPeerPairRetirement, error) {
			receipt, err := native.Retire(ctx, pair, body)
			return receipt, errors.Join(err, closeRetirement())
		},
		Permission: func(context.Context, string) (controlv1.VisitorTokenResponse, error) {
			return permission(1, now.Add(time.Minute)), nil
		},
		Close: func(context.Context) error { *closes++; return closeControl() },
	})
	if err != nil {
		t.Fatal(err)
	}
	return connectorstream.Config{Control: control, ServiceID: service, Protocol: "http", TrustRevision: 1, Endpoint: endpoint,
		TransportTLS: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots}, ServiceTLS: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots},
		RelayQUIC: muxsession.ConnectorFunc(func(context.Context, muxsession.Endpoint) (muxsession.Session, error) {
			return nil, muxsession.ErrConnectorDisabled
		}),
		Connectivity: peer.ConnectivityOptions{DisableDirect: true}}, closes
}

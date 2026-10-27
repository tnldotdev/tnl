package connector

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	clientcontrol "github.com/tnldotdev/tnl/internal/client/control"
	"github.com/tnldotdev/tnl/internal/client/supervisor"
	"github.com/tnldotdev/tnl/internal/config"
	connectorstream "github.com/tnldotdev/tnl/internal/connector/stream"
	publisheridentity "github.com/tnldotdev/tnl/internal/publisher/identity"
	"github.com/tnldotdev/tnl/internal/security/targettrust"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type connectServiceReaderFunc func(context.Context) ([]controlv1.Service, error)

func (f connectServiceReaderFunc) ListAvailableServices(ctx context.Context) ([]controlv1.Service, error) {
	return f(ctx)
}

func TestConnectMetadataLifecycle(t *testing.T) {
	for _, scenario := range []string{"tls-on-off", "tls-off-on", "public-to-private", "private-to-public", "wrapped", "joined", "revoked", "protocol-change", "protocol-constraint", "invalid-trust", "ordinary-error"} {
		t.Run(scenario, func(t *testing.T) {
			trust, err := targettrust.NewCache(nil).Capture(t.Context(), "", "localhost:443", config.TrustSource{CA: "system"})
			if err != nil {
				t.Fatal(err)
			}
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			job := supervisor.Job{ServiceID: "exact-approved-id", IdentityID: "identity", Name: "database", Protocol: "tcp", TrustRevision: 1, Target: listener.Addr().String()}
			service := controlv1.Service{Id: job.ServiceID, Name: job.Name, Protocol: "tcp", TrustRevision: 2}
			requested := ""
			switch scenario {
			case "tls-on-off":
				job.Trust = &trust
			case "tls-off-on":
				service.TargetTls = publisheridentity.ServiceTargetTLS(&trust)
			case "public-to-private", "private-to-public":
				job.Endpoint = &controlv1.ServiceEndpoint{Hostname: "database.example.test", Port: 25443, Public: scenario == "public-to-private"}
				service.Endpoint = &controlv1.ServiceEndpoint{Hostname: "database.example.test", Port: 25443, Public: scenario == "private-to-public"}
			case "protocol-change", "protocol-constraint":
				service.Protocol = "postgres"
				if scenario == "protocol-constraint" {
					requested = "tcp"
				}
			case "invalid-trust":
				service.TargetTls = &controlv1.ServiceTargetTLS{Hostname: "localhost", Digest: "invalid"}
			}
			state := ""
			calls, reads, readyCalls, publicationReadyCalls := 0, 0, 0, 0
			stop := errors.New("ordinary runner failure")
			err = runConnectorLifecycle(t.Context(), listener, job, requested, connectorLifecycle{
				starting: func(context.Context) { state = "starting" },
				publicationReady: func(context.Context) {
					if state != "starting" || readyCalls != calls {
						t.Fatal("runner published readiness before its ready callback completed")
					}
					state = "ready"
					publicationReadyCalls++
				},
				services: connectServiceReaderFunc(func(context.Context) ([]controlv1.Service, error) {
					reads++
					if state != "starting" {
						t.Fatal("refresh retained stale readiness")
					}
					if scenario == "revoked" {
						return []controlv1.Service{{Id: "different-id", Name: job.Name, Protocol: "tcp", TrustRevision: 2}}, nil
					}
					return []controlv1.Service{service}, nil
				}),
				listen: func(_ context.Context, next supervisor.Job) (net.Listener, error) {
					if next.Target != job.Target || next.ServiceID != job.ServiceID || next.IdentityID != job.IdentityID {
						t.Fatal("refresh changed reserved listener identity")
					}
					return net.Listen("tcp", next.Target)
				},
				serve: func(_ context.Context, listener net.Listener, current supervisor.Job, ready func() error) error {
					calls++
					defer listener.Close()
					if state != "starting" {
						t.Fatal("runner started ready")
					}
					if err := ready(); err != nil {
						return err
					}
					if state != "ready" {
						t.Fatal("runner did not report readiness")
					}
					if calls == 2 {
						if current.TrustRevision != service.TrustRevision || string(current.Protocol) != string(service.Protocol) || current.Trust != nil {
							t.Fatal("runner retained stale metadata")
						}
						if (current.Endpoint == nil) != (service.Endpoint == nil) || current.Endpoint != nil && *current.Endpoint != *service.Endpoint {
							t.Fatal("runner retained the old access path")
						}
						return stop
					}
					var reload error = &connectorstream.MetadataReloadError{ServiceID: job.ServiceID, ApprovedRevision: 1, SelectedRevision: 2}
					switch scenario {
					case "wrapped":
						reload = fmt.Errorf("runner: %w", reload)
					case "joined":
						reload = errors.Join(reload, io.ErrClosedPipe)
					case "ordinary-error":
						reload = stop
					}
					return reload
				},
				ready: func(supervisor.Job) error {
					if state != "starting" {
						t.Fatal("ready callback retained stale readiness")
					}
					readyCalls++
					return nil
				},
			})
			switch scenario {
			case "revoked", "protocol-constraint":
				if err == nil || calls != 1 || reads != 1 || state != "starting" {
					t.Fatal("invalid current metadata reopened a listener")
				}
			case "ordinary-error":
				if !errors.Is(err, stop) || calls != 1 || reads != 0 {
					t.Fatal("ordinary failure restarted the runner")
				}
			default:
				if !errors.Is(err, stop) || calls != 2 || reads != 1 {
					t.Fatalf("metadata refresh did not complete: calls=%d reads=%d err=%v", calls, reads, err)
				}
			}
			if readyCalls != calls || publicationReadyCalls != calls {
				t.Fatal("duplicate readiness callback")
			}
		})
	}
}

func TestConnectorRevalidatesExpiredSelectionThroughPublisherReplacement(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	job := supervisor.Job{ServiceID: "exact-approved-id", IdentityID: "identity", Name: "api", Protocol: "http", TrustRevision: 1, Target: listener.Addr().String()}
	service := controlv1.Service{Id: job.ServiceID, Name: job.Name, Protocol: "http", TrustRevision: 2}
	reads, calls, ready := 0, 0, 0
	end := errors.New("finished")
	err = runConnectorLifecycle(t.Context(), listener, job, "", connectorLifecycle{
		services: connectServiceReaderFunc(func(context.Context) ([]controlv1.Service, error) {
			reads++
			if reads == 1 {
				return nil, clientcontrol.ErrUnavailable
			}
			return []controlv1.Service{service}, nil
		}),
		listen: func(_ context.Context, next supervisor.Job) (net.Listener, error) {
			if next.ServiceID != job.ServiceID || next.Target != job.Target || next.TrustRevision != service.TrustRevision {
				t.Fatal("recovery changed the reserved service or retained stale metadata")
			}
			return net.Listen("tcp", next.Target)
		},
		serve: func(_ context.Context, listener net.Listener, _ supervisor.Job, reportReady func() error) error {
			defer listener.Close()
			calls++
			if calls > 1 {
				if err := listener.(*net.TCPListener).SetDeadline(time.Now().Add(time.Second)); err != nil {
					t.Fatal("recovery tried to serve on a closed listener", err)
				}
			}
			if calls == 1 || calls == 4 {
				if err := reportReady(); err != nil {
					return err
				}
			}
			switch calls {
			case 1:
				return connectorstream.ErrSelectionExpired
			case 2:
				return context.DeadlineExceeded
			case 3:
				return clientcontrol.ErrUnavailable
			default:
				return end
			}
		},
		ready: func(supervisor.Job) error { ready++; return nil },
	})
	if !errors.Is(err, end) || calls != 4 || reads != 4 || ready != 2 {
		t.Fatalf("publisher replacement: err=%v calls=%d inventory=%d ready=%d", err, calls, reads, ready)
	}
}

func TestConnectorCancellationDuringRecoveryPreparation(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	job := supervisor.Job{ServiceID: "exact-approved-id", IdentityID: "identity", Name: "api", Protocol: "http", TrustRevision: 1, Target: listener.Addr().String()}
	service := controlv1.Service{Id: job.ServiceID, Name: job.Name, Protocol: "http", TrustRevision: 1}
	calls := 0
	current := listener
	err = runConnectorLifecycle(ctx, listener, job, "", connectorLifecycle{
		services: connectServiceReaderFunc(func(context.Context) ([]controlv1.Service, error) {
			return []controlv1.Service{service}, nil
		}),
		listen: func(_ context.Context, next supervisor.Job) (net.Listener, error) {
			var err error
			current, err = net.Listen("tcp", next.Target)
			return current, err
		},
		serve: func(_ context.Context, listener net.Listener, _ supervisor.Job, _ func() error) error {
			defer listener.Close()
			calls++
			if calls == 1 {
				return connectorstream.ErrSelectionExpired
			}
			cancel()
			return context.DeadlineExceeded
		},
	})
	if err != nil || calls != 2 {
		t.Fatalf("canceled recovery leaked its preparation deadline: calls=%d err=%v", calls, err)
	}
	if connected, err := current.Accept(); !errors.Is(err, net.ErrClosed) {
		if connected != nil {
			_ = connected.Close()
		}
		t.Fatalf("canceled recovery retained its local listener: %v", err)
	}
}

func TestConnectorDeadlineWhileOfflineReturnsFailure(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
	defer cancel()
	job := supervisor.Job{ServiceID: "offline-service", Target: listener.Addr().String()}
	err = runConnectorLifecycle(ctx, listener, job, "", connectorLifecycle{
		serve: func(ctx context.Context, _ net.Listener, _ supervisor.Job, _ func() error) error {
			<-ctx.Done()
			return nil
		},
	})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("offline service returned success at caller deadline: %v", err)
	}
	if connected, err := listener.Accept(); !errors.Is(err, net.ErrClosed) {
		if connected != nil {
			_ = connected.Close()
		}
		t.Fatalf("timed-out connector retained its listener: %v", err)
	}
}

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"testing"

	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/privatetrust"
	nativeauth "github.com/tnldotdev/tnl/internal/publisheridentity/native"
	"github.com/tnldotdev/tnl/internal/publisherjob"
	"github.com/tnldotdev/tnl/internal/tcpconnect"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

type connectServiceReaderFunc func(context.Context) ([]controlv1.PrivateService, error)

func (f connectServiceReaderFunc) ListAvailablePrivateServices(ctx context.Context) ([]controlv1.PrivateService, error) {
	return f(ctx)
}

func TestConnectMetadataLifecycle(t *testing.T) {
	for _, scenario := range []string{"tls-on-off", "tls-off-on", "public-to-private", "private-to-public", "wrapped", "joined", "revoked", "protocol-change", "protocol-constraint", "invalid-trust", "ordinary-error"} {
		t.Run(scenario, func(t *testing.T) {
			trust, err := privatetrust.NewCache(nil).Capture(t.Context(), "", "localhost:443", config.TrustSource{CA: "system"})
			if err != nil {
				t.Fatal(err)
			}
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			job := publisherjob.Job{PrivateServiceID: "exact-approved-id", IdentityID: "identity", Name: "database", Protocol: "tcp", TrustRevision: 1, Target: listener.Addr().String()}
			service := controlv1.PrivateService{Id: job.PrivateServiceID, Name: job.Name, Protocol: "tcp", TrustRevision: 2}
			requested := ""
			switch scenario {
			case "tls-on-off":
				job.Trust = &trust
			case "tls-off-on":
				service.TargetTls = nativeauth.PrivateServiceTLS(&trust)
			case "public-to-private", "private-to-public":
				job.ManagedTLS = &controlv1.ManagedServiceTLS{Hostname: "database.example.test", Port: 25443, Public: scenario == "public-to-private"}
				service.ManagedTls = &controlv1.ManagedServiceTLS{Hostname: "database.example.test", Port: 25443, Public: scenario == "private-to-public"}
			case "protocol-change", "protocol-constraint":
				service.Protocol = "postgres"
				if scenario == "protocol-constraint" {
					requested = "tcp"
				}
			case "invalid-trust":
				service.TargetTls = &controlv1.PrivateServiceTLS{Hostname: "localhost", Digest: "invalid"}
			}
			state := &detachedControl{}
			ctx := context.WithValue(t.Context(), detachedControlKey{}, state)
			calls, reads, readyCalls := 0, 0, 0
			stop := errors.New("ordinary runner failure")
			err = runPrivateConnectorLifecycle(ctx, listener, job, requested, privateConnectorLifecycle{
				services: connectServiceReaderFunc(func(context.Context) ([]controlv1.PrivateService, error) {
					reads++
					if state.get() != "starting" {
						t.Fatal("refresh retained stale readiness")
					}
					if scenario == "revoked" {
						return []controlv1.PrivateService{{Id: "different-id", Name: job.Name, Protocol: "tcp", TrustRevision: 2}}, nil
					}
					return []controlv1.PrivateService{service}, nil
				}),
				listen: func(_ context.Context, next publisherjob.Job) (net.Listener, error) {
					if next.Target != job.Target || next.PrivateServiceID != job.PrivateServiceID || next.IdentityID != job.IdentityID {
						t.Fatal("refresh changed reserved listener identity")
					}
					return net.Listen("tcp", next.Target)
				},
				serve: func(_ context.Context, listener net.Listener, current publisherjob.Job, ready func() error) error {
					calls++
					defer listener.Close()
					if state.get() != "starting" {
						t.Fatal("runner started ready")
					}
					if err := ready(); err != nil {
						return err
					}
					if state.get() != "ready" {
						t.Fatal("runner did not report readiness")
					}
					if calls == 2 {
						if current.TrustRevision != service.TrustRevision || string(current.Protocol) != string(service.Protocol) || current.Trust != nil {
							t.Fatal("runner retained stale metadata")
						}
						if (current.ManagedTLS == nil) != (service.ManagedTls == nil) || current.ManagedTLS != nil && *current.ManagedTLS != *service.ManagedTls {
							t.Fatal("runner retained the old access path")
						}
						return stop
					}
					var reload error = &tcpconnect.MetadataReloadError{PrivateServiceID: job.PrivateServiceID, ApprovedRevision: 1, SelectedRevision: 2}
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
				ready: func(publisherjob.Job) error { readyCalls++; return nil },
			})
			switch scenario {
			case "revoked", "protocol-constraint":
				if err == nil || calls != 1 || reads != 1 || state.get() != "starting" {
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
			if readyCalls != calls {
				t.Fatal("duplicate readiness callback")
			}
		})
	}
}

package connector

import (
	"context"
	"errors"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	clientproject "github.com/tnldotdev/tnl/internal/client/project"
	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/connector/kubeconfig"
	connectorruntime "github.com/tnldotdev/tnl/internal/connector/runtime"
	connectorstream "github.com/tnldotdev/tnl/internal/connector/stream"
	"github.com/tnldotdev/tnl/internal/connector/workload"
	authorityv1 "github.com/tnldotdev/tnl/pkg/api/control/authority/v1"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func connectionPreparationFixture(t *testing.T) (*connectorConnectionBackend, controlv1.Service) {
	t.Helper()
	service := controlv1.Service{Id: "svc_" + strings.Repeat("s", 22), Enabled: true, Protocol: controlv1.ServiceProtocolHTTP, Endpoint: &controlv1.ServiceEndpoint{Hostname: "api.example.test", Port: 15443}}
	lifetime, cancel := context.WithCancel(t.Context())
	b := &connectorConnectionBackend{
		scope: connectorruntime.Context{Services: []string{"api"}}, parentPID: 1,
		connectorConnectionSession: connectorConnectionSession{deadline: time.Now().Add(time.Hour)},
		project:                    projectConfiguration{Project: clientproject.Project{Config: config.TNL{Services: config.Services{"api": {Protocol: new("http")}}}}},
		services:                   map[string]controlv1.Service{"api": service}, listeners: map[string]*ownedServiceListener{},
		lifetime: lifetime, cancel: cancel,
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if err := b.Close(ctx); err != nil {
			t.Error(err)
		}
	})
	return b, service
}

func TestConnectionPreparationTransitions(t *testing.T) {
	for _, ready := range []bool{false, true} {
		name := "startup-failure"
		if ready {
			name = "failure-after-ready"
		}
		t.Run(name, func(t *testing.T) {
			b, service := connectionPreparationFixture(t)
			p := &servicePreparation{service: service, state: preparingService{}}
			owner := &ownedServiceListener{attempt: p}
			b.listeners["api"] = owner
			b.publishLocked()
			if _, err := b.Prepared("api"); !errors.Is(err, connectorruntime.ErrUnprepared) {
				t.Fatal("starting attempt was published", err)
			}
			if ready {
				if err := b.publishServiceLocked("api", owner, p, &servingService{connection: connectorruntime.Connection{Protocol: "http", Host: "127.0.0.1", Port: 25443}}, serviceKubeconfig{}, nil); err != nil {
					t.Fatal(err)
				}
				if _, err := b.Prepared("api"); err != nil {
					t.Fatal("successful attempt was not published", err)
				}
			}
			failure := errors.New("transport failed")
			b.finishPreparationLocked("api", owner, p, failure)
			if _, err := p.result(); !errors.Is(err, failure) {
				t.Fatal("attempt lost its failure", err)
			}
			_, err := b.Prepared("api")
			if ready && (!errors.Is(err, failure) || !errors.Is(err, connectorruntime.ErrUnavailable)) || !ready && !errors.Is(err, connectorruntime.ErrUnprepared) {
				t.Fatal("prepared failure contract changed", err)
			}
			b.finishPreparationLocked("api", owner, p, errors.New("later cleanup failure"))
			if _, err := p.result(); !errors.Is(err, failure) {
				t.Fatal("terminal failure was overwritten", err)
			}
			if err := b.publishServiceLocked("api", owner, p, &servingService{}, serviceKubeconfig{}, nil); !errors.Is(err, connectorruntime.ErrUnprepared) {
				t.Fatal("failed attempt returned to serving", err)
			}
		})
	}
}

func TestConnectionPreparationRejectsStalePublication(t *testing.T) {
	for _, scenario := range []string{"listener", "attempt", "service", "protocol", "endpoint", "closed", "session"} {
		t.Run(scenario, func(t *testing.T) {
			b, service := connectionPreparationFixture(t)
			p := &servicePreparation{service: service, state: preparingService{}}
			owner := &ownedServiceListener{attempt: p}
			b.listeners["api"] = owner
			switch scenario {
			case "listener":
				b.listeners["api"] = &ownedServiceListener{attempt: &servicePreparation{service: service, state: preparingService{}}}
			case "attempt":
				owner.attempt = &servicePreparation{service: service, state: preparingService{}}
			case "service":
				service.Id = "svc_" + strings.Repeat("n", 22)
				b.services["api"] = service
			case "protocol":
				service.Protocol = controlv1.Postgres
				b.services["api"] = service
			case "endpoint":
				endpoint := *service.Endpoint
				endpoint.Port++
				service.Endpoint = &endpoint
				b.services["api"] = service
			case "closed":
				b.closed = true
			case "session":
				b.workload = &workload.Client{}
			}
			if err := b.publishServiceLocked("api", owner, p, &servingService{}, serviceKubeconfig{}, nil); !errors.Is(err, connectorruntime.ErrUnprepared) {
				t.Fatal("stale preparation was published", err)
			}
			if _, starting := p.state.(preparingService); !starting {
				t.Fatal("rejected publication changed the attempt")
			}
			b.publishLocked()
			if _, err := b.Prepared("api"); !errors.Is(err, connectorruntime.ErrUnprepared) {
				t.Fatal("stale transport reached prepared readers", err)
			}
		})
	}
}

func TestConnectionPreparationNewTransportIdentity(t *testing.T) {
	b, service := connectionPreparationFixture(t)
	owner := &ownedServiceListener{}
	b.listeners["api"] = owner
	var first string
	for range 2 {
		p := &servicePreparation{service: service, state: preparingService{}}
		owner.attempt = p
		serving := &servingService{connection: connectorruntime.Connection{Protocol: "http", Host: "127.0.0.1", Port: 25443}}
		if err := b.publishServiceLocked("api", owner, p, serving, serviceKubeconfig{}, nil); err != nil {
			t.Fatal(err)
		}
		connection, err := b.Prepared("api")
		if err != nil || connection.TransportID == "" || connection.TransportID == first || connection.Port != 25443 {
			t.Fatal("replacement reused transport identity or changed local address", connection, err)
		}
		first = connection.TransportID
		// an old completion cannot invalidate the replacement's publication.
		stale := &servicePreparation{service: service, state: &servingService{}}
		b.finishPreparationLocked("api", owner, stale, errors.New("old transport stopped"))
		if _, err := b.Prepared("api"); err != nil {
			t.Fatal("stale completion invalidated the current transport", err)
		}
	}
}

func TestConnectionPreparationPublicationSessionFence(t *testing.T) {
	for _, scenario := range []string{"current", "old-session", "unapproved-service"} {
		t.Run(scenario, func(t *testing.T) {
			b := connectionBackendFixture(t, func(w http.ResponseWriter, r *http.Request, _ authorityv1.WorkloadSession) {
				t.Error("publication performed network work", r.URL.Path)
				w.WriteHeader(500)
			})
			session, err := b.workload.Session()
			if err != nil {
				t.Fatal(err)
			}
			service := b.services["api"]
			serving := &servingService{sessionID: session.Id}
			switch scenario {
			case "old-session":
				serving.sessionID = "wls_" + strings.Repeat("o", 22)
			case "unapproved-service":
				service.Id = "svc_" + strings.Repeat("u", 22)
				b.services["api"] = service
			}
			p := &servicePreparation{service: service, state: preparingService{}}
			owner := &ownedServiceListener{attempt: p}
			b.listeners["api"] = owner
			err = b.publishServiceLocked("api", owner, p, serving, serviceKubeconfig{}, b.workload)
			if scenario == "current" {
				if err != nil {
					t.Fatal(err)
				}
				connection, err := b.Prepared("api")
				if err != nil || !connection.ExpiresAt.Equal(session.LeaseExpiresAt) {
					t.Fatal("publication lost the current session's lease fence", err)
				}
			} else if !errors.Is(err, connectorruntime.ErrUnprepared) {
				t.Fatal("publication escaped the exact session/service fence", err)
			}
		})
	}
}

func TestConnectionPreparationRetainsKubeconfigForRepair(t *testing.T) {
	b, service := connectionPreparationFixture(t)
	service.Protocol = controlv1.Kubernetes
	b.services["api"] = service
	kube := serviceKubeconfig{result: kubeconfig.Result{File: "owned-kubeconfig", Context: "owned-context"}}
	p := &servicePreparation{service: service, state: preparingService{}}
	owner := &ownedServiceListener{attempt: p, kube: kube}
	b.listeners["api"] = owner
	if _, ok := owner.kubeconfig(); ok {
		t.Fatal("starting replacement exposed the previous kubeconfig")
	}
	if err := b.publishServiceLocked("api", owner, p, &servingService{}, kube, nil); err != nil {
		t.Fatal(err)
	}
	b.finishPreparationLocked("api", owner, p, errors.New("transport failed"))
	if retained, ok := owner.kubeconfig(); !ok || retained.result.File != kube.result.File || retained.result.Context != kube.result.Context || b.Kubeconfig() != kube.result.File {
		t.Fatal("transport failure discarded the kubeconfig needed for credential repair")
	}
}

type preparationListener struct {
	net.Listener
	closes atomic.Int32
}

func (l *preparationListener) Close() error {
	l.closes.Add(1)
	return l.Listener.Close()
}

func TestConnectionPreparationInvalidResolvedRunClosesAdapterOnce(t *testing.T) {
	for _, revision := range []int64{0, -1} {
		t.Run(strconv.FormatInt(revision, 10), func(t *testing.T) {
			b, service := connectionPreparationFixture(t)
			var closes atomic.Int32
			control, err := connectorstream.NewControlWithConfig(connectorstream.ControlConfig{
				Resolve: func(context.Context, string) (connectorstream.Run, error) {
					return connectorstream.Run{Protocol: string(service.Protocol), Endpoint: service.Endpoint, TrustRevision: revision}, nil
				},
				Signer: func(context.Context, string) (connectorstream.Signer, error) {
					t.Error("invalid resolved run reached signer preparation")
					return connectorstream.Signer{}, connectorstream.ErrServiceConnection
				},
				Pair: func(context.Context, string, controlv1.ConnectorPeerPairRequest) (controlv1.ConnectorPeerPair, error) {
					t.Error("invalid resolved run reached pair preparation")
					return controlv1.ConnectorPeerPair{}, connectorstream.ErrServiceConnection
				},
				Permission: func(context.Context, string) (controlv1.VisitorTokenResponse, error) {
					t.Error("invalid resolved run reached visitor permission")
					return controlv1.VisitorTokenResponse{}, connectorstream.ErrServiceConnection
				},
				Close: func() error { closes.Add(1); return nil },
			})
			if err != nil {
				t.Fatal(err)
			}
			p, err := b.prepareListener(t.Context(), "api", nil, service, nil, control, "")
			if p != nil || !errors.Is(err, connectorruntime.ErrUnavailable) || !errors.Is(err, connectorstream.ErrServiceConnection) {
				t.Fatal("invalid resolved run changed the startup failure", err)
			}
			if closes.Load() != 1 {
				t.Error("invalid resolved run did not close its adapter exactly once", closes.Load())
			}
			if len(b.listeners) != 0 {
				t.Error("invalid resolved run acquired listener ownership")
			}
			if err := b.Close(t.Context()); err != nil {
				t.Fatal(err)
			}
			if closes.Load() != 1 {
				t.Error("owner shutdown changed the adapter close count", closes.Load())
			}
		})
	}
}

func TestConnectionPreparationFailureJoinsResourcesAndReusesListener(t *testing.T) {
	for _, scenario := range []string{"selection", "endpoint", "startup", "canceled", "replacement"} {
		t.Run(scenario, func(t *testing.T) {
			b, service := connectionPreparationFixture(t)
			failure := errors.New("preparation failed")
			entered, closed := make(chan struct{}), make(chan struct{})
			var closes atomic.Int32
			control, err := connectorstream.NewControlWithConfig(connectorstream.ControlConfig{
				Resolve: func(context.Context, string) (connectorstream.Run, error) {
					if scenario == "selection" {
						return connectorstream.Run{}, failure
					}
					endpoint := *service.Endpoint
					if scenario == "endpoint" {
						endpoint.Port++
					}
					return connectorstream.Run{Protocol: "http", Endpoint: &endpoint, TrustRevision: 1}, nil
				},
				Signer: func(ctx context.Context, _ string) (connectorstream.Signer, error) {
					close(entered)
					if scenario == "canceled" {
						<-ctx.Done()
					}
					return connectorstream.Signer{}, failure
				},
				Pair: func(context.Context, string, controlv1.ConnectorPeerPairRequest) (controlv1.ConnectorPeerPair, error) {
					t.Error("failed preparation reached pair creation")
					return controlv1.ConnectorPeerPair{}, failure
				},
				Permission: func(context.Context, string) (controlv1.VisitorTokenResponse, error) {
					t.Error("failed preparation reached visitor permission")
					return controlv1.VisitorTokenResponse{}, failure
				},
				Close: func() error { closes.Add(1); close(closed); return nil },
			})
			if err != nil {
				t.Fatal(err)
			}
			var previous *ownedServiceListener
			var base *preparationListener
			oldCanceled, release := make(chan struct{}), make(chan struct{})
			if scenario == "replacement" {
				listener, err := net.Listen("tcp4", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				base = &preparationListener{Listener: listener}
				oldCtx, cancel := context.WithCancel(b.lifetime)
				old := &servicePreparation{service: service, state: &servingService{}, cancel: cancel, done: make(chan struct{})}
				previous = &ownedServiceListener{listener: connectorruntime.NewListenerSwitch(base), attempt: old, kube: serviceKubeconfig{result: kubeconfig.Result{File: "retained-kubeconfig", Context: "retained-context"}}}
				b.listeners["api"] = previous
				b.publishLocked()
				if _, err := b.Prepared("api"); err != nil {
					t.Fatal("old transport was not initially published", err)
				}
				generation := previous.listener.Next()
				b.workers.Go(func() {
					defer close(old.done)
					<-oldCtx.Done()
					close(oldCanceled)
					<-release
					_ = generation.Close()
				})
			}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			done := make(chan error, 1)
			go func() { _, err := b.prepareListener(ctx, "api", previous, service, nil, control, ""); done <- err }()
			if scenario == "replacement" {
				<-oldCanceled
				if _, err := b.Prepared("api"); !errors.Is(err, connectorruntime.ErrUnprepared) {
					t.Error("old transport stayed published during replacement", err)
				}
				select {
				case <-entered:
					t.Error("replacement started before old cleanup joined")
				default:
				}
				close(release)
			}
			if scenario == "canceled" {
				<-entered
				cancel()
			}
			if err := <-done; err == nil || scenario != "endpoint" && scenario != "canceled" && !errors.Is(err, failure) || scenario == "canceled" && !errors.Is(err, context.Canceled) {
				t.Fatal("preparation failure changed", err)
			}
			select {
			case <-closed:
			default:
				t.Fatal("preparation returned before adapter cleanup joined")
			}
			if closes.Load() != 1 {
				t.Fatal("adapter was not closed exactly once", closes.Load())
			}
			if _, err := b.Prepared("api"); !errors.Is(err, connectorruntime.ErrUnprepared) {
				t.Fatal("failed startup published serving data", err)
			}
			if previous != nil {
				owner := b.listeners["api"]
				if owner != previous || owner.listener.Addr().String() != base.Addr().String() || base.closes.Load() != 0 || owner.kube.result.File != "retained-kubeconfig" {
					t.Fatal("replacement lost reusable listener or Kubernetes ownership")
				}
			}
			address := ""
			if owner := b.listeners["api"]; owner != nil {
				address = owner.listener.Addr().String()
			}
			if err := b.Close(t.Context()); err != nil {
				t.Fatal(err)
			}
			if closes.Load() != 1 || base != nil && base.closes.Load() != 1 {
				t.Fatal("owner shutdown closed resources more than once")
			}
			if address != "" {
				listener, err := net.Listen("tcp4", address)
				if err != nil {
					t.Fatal("failed preparation leaked its local listener", err)
				}
				_ = listener.Close()
			}
		})
	}
}

package stream

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"testing"
	"time"

	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func unreachableControlConfig() ControlConfig {
	return ControlConfig{
		Signer:  func(context.Context, string) (Signer, error) { panic("unexpected signing") },
		Resolve: func(context.Context, string) (Run, error) { panic("unexpected selection") },
		Pair: func(context.Context, string, controlv1.ConnectorPeerPairRequest) (controlv1.ConnectorPeerPair, error) {
			panic("unexpected pair preparation")
		},
		RenewPair: func(context.Context, string, controlv1.ConnectorPeerPairRequest) (controlv1.ConnectorPeerPairRenewal, error) {
			panic("unexpected pair renewal")
		},
		RebindPair: func(context.Context, string, string, controlv1.ConnectorPeerPairRebindRequest) (controlv1.ConnectorPeerPairRebindState, error) {
			panic("unexpected pair rebind")
		},
		Permission: func(context.Context, string) (controlv1.VisitorTokenResponse, error) { panic("unexpected permission") },
		Close:      func(context.Context) error { panic("unexpected close") },
	}
}

func TestControlConfigRequiresEveryAuthorityAndCleanupOperation(t *testing.T) {
	complete := unreachableControlConfig()
	for name, remove := range map[string]func(*ControlConfig){
		"signer":     func(c *ControlConfig) { c.Signer = nil },
		"resolve":    func(c *ControlConfig) { c.Resolve = nil },
		"pair":       func(c *ControlConfig) { c.Pair = nil },
		"renew":      func(c *ControlConfig) { c.RenewPair = nil },
		"rebind":     func(c *ControlConfig) { c.RebindPair = nil },
		"close":      func(c *ControlConfig) { c.Close = nil },
		"permission": func(c *ControlConfig) { c.Permission = nil },
	} {
		t.Run(name, func(t *testing.T) {
			config := complete
			remove(&config)
			if _, err := NewControlWithConfig(config); !errors.Is(err, ErrServiceConnection) {
				t.Fatal("accepted incomplete connector control", err)
			}
		})
	}
}

func TestControlCleanupReceivesBoundedIndependentContext(t *testing.T) {
	operationFailure, cleanupFailure := errors.New("signer failed"), errors.New("cleanup failed")
	ctx, cancel := context.WithCancel(t.Context())
	closed := false
	callbacks := unreachableControlConfig()
	callbacks.Signer = func(context.Context, string) (Signer, error) {
		cancel()
		return Signer{}, errors.Join(context.Canceled, operationFailure)
	}
	callbacks.Close = func(cleanup context.Context) error {
		closed = true
		deadline, bounded := cleanup.Deadline()
		if cleanup.Err() != nil || !bounded || !deadline.After(time.Now()) || deadline.After(time.Now().Add(5*time.Second)) {
			t.Error("cleanup inherited cancellation or lost its bound")
		}
		return cleanupFailure
	}
	control, err := NewControlWithConfig(callbacks)
	if err != nil {
		t.Fatal(err)
	}
	config := Config{Control: control, ServiceID: "svc_aaaaaaaaaaaaaaaaaaaaaa", Protocol: "tcp", TrustRevision: 1,
		Endpoint: &controlv1.ServiceEndpoint{Hostname: "db.example", Port: 15443}, ServiceTLS: &tls.Config{MinVersion: tls.VersionTLS12}}
	err = serveConnections(ctx, config, func(context.Context, func(context.Context, net.Conn) error) error {
		t.Fatal("failed signing reached the application")
		return nil
	})
	var cleanup *CleanupError
	if !closed || !errors.Is(err, operationFailure) || !errors.Is(err, cleanupFailure) || !errors.As(err, &cleanup) {
		t.Fatal("connector did not join operation and cleanup failures", err)
	}
}

func TestConfiguredControlForwardsRebindContextAndRequest(t *testing.T) {
	want := errors.New("rebind stopped")
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	body := controlv1.ConnectorPeerPairRebindRequest{Phase: controlv1.ConnectorPeerPairInspect}
	config := unreachableControlConfig()
	config.RebindPair = func(got context.Context, service, pair string, request controlv1.ConnectorPeerPairRebindRequest) (controlv1.ConnectorPeerPairRebindState, error) {
		if got != ctx || service != "service" || pair != "pair" || request.Phase != body.Phase {
			t.Fatal("rebind lost its context or pair selection")
		}
		return controlv1.ConnectorPeerPairRebindState{}, want
	}
	control, err := NewControlWithConfig(config)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := control.RebindConnectorPeerPair(ctx, "service", "pair", body); !errors.Is(err, want) {
		t.Fatal("rebind lost its authority failure", err)
	}
}

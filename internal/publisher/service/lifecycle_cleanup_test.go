package service

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"testing"

	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/publisher"
	"github.com/tnldotdev/tnl/internal/security/credentials"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type invalidSetupControl struct {
	*lifecycleControl
	closeErr error
	closed   bool
}

func (c *invalidSetupControl) StartServiceRun(ctx context.Context, service, run, access string, number int64) (controlv1.ServiceRunSetup, error) {
	setup, err := c.lifecycleControl.StartServiceRun(ctx, service, run, access, number)
	if err == nil {
		setup.RunNumber++
	}
	return setup, err
}

func (c *invalidSetupControl) CloseServiceRun(_ context.Context, _, _ string, token credentials.ServiceRunToken) error {
	c.closed = token.String() == c.setup.RunToken
	return c.closeErr
}

func TestServiceRunInvalidSetupStillClosesAndPreservesCleanupFailure(t *testing.T) {
	config, control := lifecycleFixture(t)
	cleanup := errors.New("close failed")
	invalid := &invalidSetupControl{lifecycleControl: control, closeErr: cleanup}
	config.Control = invalid
	err := Publish(t.Context(), config)
	if !invalid.closed || !errors.Is(err, ErrPrivateStream) || !errors.Is(err, cleanup) {
		t.Fatal("invalid setup skipped its close or lost either error", err)
	}
}

func TestServiceRunRequiresExplicitProtocolBeforeAccess(t *testing.T) {
	config, _ := lifecycleFixture(t)
	config.Metadata.Protocol = ""
	config.Access = func(context.Context) (string, error) {
		t.Fatal("missing service protocol reached credential exchange")
		return "", nil
	}
	if err := Publish(t.Context(), config); !errors.Is(err, ErrPrivateStream) {
		t.Fatal("missing service protocol used an implicit TCP declaration", err)
	}
}

type canceledHeartbeatControl struct {
	*lifecycleControl
	cancel                  context.CancelFunc
	onHeartbeat, heartbeats int
	failure, cleanup        error
	closed                  bool
}

func (c *canceledHeartbeatControl) HeartbeatServiceRun(ctx context.Context, service, run string, token credentials.ServiceRunToken, health controlv1.ServiceRunHeartbeat) (controlv1.ServiceRunState, error) {
	c.heartbeats++
	if c.heartbeats == c.onHeartbeat {
		c.cancel()
		return controlv1.ServiceRunState{}, errors.Join(ctx.Err(), c.failure)
	}
	return c.lifecycleControl.HeartbeatServiceRun(ctx, service, run, token, health)
}

func (c *canceledHeartbeatControl) CloseServiceRun(ctx context.Context, service, run string, token credentials.ServiceRunToken) error {
	c.closed = true
	return errors.Join(c.lifecycleControl.CloseServiceRun(ctx, service, run, token), c.cleanup)
}

func TestServiceHeartbeatCancellationKeepsIndependentFailures(t *testing.T) {
	for _, heartbeat := range []int{1, 2} {
		for _, kind := range []string{"canceled", "joined", "wrapped", "transient-sibling", "cleanup"} {
			t.Run(fmt.Sprintf("heartbeat-%d/%s", heartbeat, kind), func(t *testing.T) {
				config, base := lifecycleFixture(t)
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				control := &canceledHeartbeatControl{lifecycleControl: base, cancel: cancel, onHeartbeat: heartbeat}
				independent := errors.New("independent heartbeat failure")
				switch kind {
				case "joined":
					control.failure = independent
				case "wrapped":
					control.failure = fmt.Errorf("heartbeat: %w", independent)
				case "transient-sibling":
					control.failure = errors.Join(failure.Wrap("heartbeat", failure.ServerUnavailable, io.EOF), independent)
				case "cleanup":
					control.cleanup = independent
				}
				config.Control = control
				config.Connect = func(context.Context, *Bound, uint8, ConnectOptions) (SlotSession, error) {
					return &heldSlot{stopped: make(chan struct{})}, nil
				}
				err := Publish(ctx, config)
				if !control.closed || control.heartbeats != heartbeat {
					t.Fatal("canceled heartbeat did not close its exact run", err)
				}
				if kind == "canceled" {
					if err != nil {
						t.Fatal("pure cancellation became a stream failure", err)
					}
				} else if !errors.Is(err, independent) {
					t.Fatal("cancellation discarded independent failure", err)
				}
			})
		}
	}
}

type canceledPeerListControl struct {
	*lifecycleControl
	cancel  context.CancelFunc
	failure error
}

func (c canceledPeerListControl) ListConnectorPeerPairs(ctx context.Context, _, _, _ string, _ credentials.ServiceRunToken) (controlv1.ConnectorPeerPairCandidates, error) {
	c.cancel()
	return controlv1.ConnectorPeerPairCandidates{}, errors.Join(ctx.Err(), c.failure)
}

func TestConnectorPeerListCancellationKeepsIndependentFailure(t *testing.T) {
	for _, joined := range []bool{false, true} {
		t.Run(fmt.Sprint(joined), func(t *testing.T) {
			_, base := lifecycleFixture(t)
			_, bound, _, _ := privateFixture(t, "127.0.0.1:1")
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			control := canceledPeerListControl{lifecycleControl: base, cancel: cancel}
			if joined {
				control.failure = errors.New("independent peer list failure")
			}
			err := bound.ServeConnectorPeers(ctx, control, "run-token")
			if joined && !errors.Is(err, control.failure) || !joined && err != nil {
				t.Fatal("peer cancellation changed independent failure", err)
			}
		})
	}
}

type canceledCertificateControl struct {
	*lifecycleControl
	cancel  context.CancelFunc
	failure error
}

func (c canceledCertificateControl) CreateServiceCertificateIssuance(ctx context.Context, _, _ string, _ int64, _ credentials.ServiceRunToken, _ []byte, _ string) (controlv1.ServiceCertificateIssuance, error) {
	c.cancel()
	return controlv1.ServiceCertificateIssuance{}, errors.Join(ctx.Err(), c.failure)
}

func TestServiceCertificateCancellationKeepsIndependentFailure(t *testing.T) {
	for _, joined := range []bool{false, true} {
		t.Run(fmt.Sprint(joined), func(t *testing.T) {
			config, base := lifecycleFixture(t)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			control := canceledCertificateControl{lifecycleControl: base, cancel: cancel}
			if joined {
				control.failure = errors.New("independent certificate issuance failure")
			}
			cache, err := config.State.CertificatesForPublisher(base.prep.TeamId, config.Identity.ClientId, *base.prep.CertificatePlan)
			if err != nil {
				t.Fatal(err)
			}
			err = (publisher.ServiceCertificates{Control: control, Cache: cache, ServiceID: base.prep.ServiceId, RunID: base.prep.ServiceRunId, PublisherIdentityID: config.Identity.ClientId, RunNumber: base.prep.RunNumber, Token: "run-token", Hostname: base.prep.Hostname, Plan: *base.prep.CertificatePlan, Install: func(tls.Certificate) error { t.Fatal("canceled issuance installed material"); return nil }}).Maintain(ctx)
			if !errors.Is(err, context.Canceled) || joined && !errors.Is(err, control.failure) {
				t.Fatal("certificate cancellation discarded independent failure", err)
			}
		})
	}
}

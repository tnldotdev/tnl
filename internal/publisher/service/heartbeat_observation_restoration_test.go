package service

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	clientcontrol "github.com/tnldotdev/tnl/internal/client/control"
	"github.com/tnldotdev/tnl/internal/observability"
	"github.com/tnldotdev/tnl/internal/security/credentials"
	"github.com/tnldotdev/tnl/internal/transport/muxsession"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type observationHeartbeatControl struct {
	*lifecycleControl
	old, next time.Time
	mode      string
	calls     int
}

func (c *observationHeartbeatControl) HeartbeatServiceRun(ctx context.Context, service, run string, token credentials.ServiceRunToken, health controlv1.ServiceRunHeartbeat) (controlv1.ServiceRunState, error) {
	state, err := c.lifecycleControl.HeartbeatServiceRun(ctx, service, run, token, health)
	c.calls++
	state.PublisherExpiresAt = c.old
	if err != nil || c.calls == 1 {
		return state, err
	}
	state.PublisherExpiresAt = c.next
	switch c.mode {
	case "duplicate-slot":
		state.PublisherConnections[1].ConnectionSlot = state.PublisherConnections[0].ConnectionSlot
	case "duplicate-relay":
		state.PublisherConnections[1].RelayServiceId = state.PublisherConnections[0].RelayServiceId
	case "stale-revision":
		state.PublisherConnections[1].ConnectionAssignmentRevision--
	case "unavailable":
		// a tempting deadline in an unsuccessful reply is not confirmed authority.
		return state, clientcontrol.ErrUnavailable
	}
	return state, nil
}

func observationLeaseValue(t *testing.T, owner *observability.Metrics) float64 {
	t.Helper()
	families, err := owner.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, family := range families {
		if family.GetName() == "tnl_publisher_lease_expiration_timestamp_seconds" {
			if len(family.Metric) != 1 {
				t.Fatal("heartbeat created multiple confirmed lease series", family)
			}
			return family.Metric[0].GetGauge().GetValue()
		}
	}
	t.Fatal("heartbeat did not record its confirmed lease")
	return 0
}

func TestServiceHeartbeatObservationRestorationAcceptsOnlyCompleteState(t *testing.T) {
	for _, mode := range []string{"duplicate-slot", "duplicate-relay", "stale-revision", "accepted", "unavailable"} {
		t.Run(mode, func(t *testing.T) {
			_, recorder := observationPublisher(t)
			var runID, token string
			synctest.Test(t, func(t *testing.T) {
				cfg, base := lifecycleFixture(t)
				runID, token = base.prep.ServiceRunId, base.setup.RunToken
				control := &observationHeartbeatControl{lifecycleControl: base, old: time.Now().Add(time.Minute), next: time.Now().Add(time.Hour), mode: mode}
				cfg.Control, cfg.HeartbeatInterval = control, time.Millisecond
				cfg.Connectivity.DisableDirect = true
				unused := muxsession.ConnectorFunc(func(context.Context, muxsession.Endpoint) (muxsession.Session, error) {
					t.Error("heartbeat observation fixture attempted a network relay")
					return nil, ErrPrivateStream
				})
				cfg.RelayQUIC, cfg.RelayWebSocket = unused, unused
				// fake slots isolate renewal observations, not transport qualification.
				cfg.Connect = func(context.Context, *Bound, uint8, ConnectOptions) (SlotSession, error) {
					return &heldSlot{stopped: make(chan struct{})}, nil
				}
				ctx, cancel := context.WithCancel(observability.WithMetrics(t.Context(), recorder.Owner))
				defer cancel()
				stopped := false
				cfg.ObserveReadiness = func(status RunStatus) {
					if control.calls < 2 || stopped {
						return
					}
					stopped = true
					want := control.old
					if mode == "accepted" {
						want = control.next
					}
					if got := observationLeaseValue(t, recorder.Owner); got != float64(want.Unix())+float64(want.Nanosecond())/float64(time.Second) || !status.LeaseExpiresAt.Equal(want) {
						t.Error("unaccepted heartbeat changed the exact confirmed lease", got, status.LeaseExpiresAt, want)
					}
					cancel()
				}
				result := Publish(ctx, cfg)
				if control.calls != 2 || !stopped {
					t.Fatal("fixture did not observe one renewal after its confirmed initial state", control.calls, result)
				}
				if mode != "accepted" && mode != "unavailable" && !errors.Is(result, ErrPrivateStream) {
					t.Error("invalid assignment response lost its cause", result)
				}
				want := control.old
				if mode == "accepted" {
					want = control.next
				}
				if observationLeaseValue(t, recorder.Owner) != float64(want.Unix())+float64(want.Nanosecond())/float64(time.Second) {
					t.Error("cleanup changed the last confirmed lease")
				}
			})
			failed := uint64(1)
			if mode == "accepted" {
				failed = 0
			}
			if observationMetricCount(t, recorder.Owner, "tnl_publisher_operation_duration_seconds", map[string]string{"tnl_operation": "private_heartbeat", "tnl_outcome": "error"}) != failed ||
				observationMetricCount(t, recorder.Owner, "tnl_publisher_operation_duration_seconds", map[string]string{"tnl_operation": "private_heartbeat"}) != 2 {
				t.Fatal("renewal duration omitted or duplicated the single failed operation")
			}
			if mode == "unavailable" && observationMetricCount(t, recorder.Owner, "tnl_publisher_authorization_decisions_total", nil) != 0 {
				t.Fatal("unavailable renewal fallback fabricated a visitor policy denial")
			}
			spans := recorder.Attempts(t, "publisher.private_heartbeat")
			if len(spans) != 2 {
				t.Fatal("heartbeat exported another operation", len(spans))
			}
			families, err := recorder.Owner.Gather()
			if err != nil {
				t.Fatal(err)
			}
			exported := fmt.Sprint(spans, families, recorder.Logs())
			for _, secret := range []string{runID, token, "private-assignment-credential", "scoped-publisher-token"} {
				if strings.Contains(exported, secret) {
					t.Fatal("renewal observations exported run identity or credentials")
				}
			}
		})
	}
}

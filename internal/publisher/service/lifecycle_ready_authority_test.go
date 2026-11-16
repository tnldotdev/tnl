package service

import (
	"context"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	clientcontrol "github.com/tnldotdev/tnl/internal/client/control"
	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/transport/muxsession"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type readyAuthorityControl struct {
	*heldCertificateAcknowledgment
	unavailable atomic.Bool
	short       atomic.Bool
}

func (c *readyAuthorityControl) ReadPublisherVisitorPolicy(ctx context.Context, body controlv1.PublisherVisitorPolicyRequest, token string) (controlv1.VisitorPolicyUpdate, error) {
	if c.unavailable.Load() {
		return controlv1.VisitorPolicyUpdate{}, clientcontrol.ErrUnavailable
	}
	update, err := c.lifecycleControl.ReadPublisherVisitorPolicy(ctx, body, token)
	if c.short.Load() {
		update.Policy.ValidUntil = update.Policy.ObservedAt.Add(time.Second)
	}
	return update, err
}

func readyAuthorityFixture(t *testing.T) (RunConfig, *readyAuthorityControl, <-chan *Bound) {
	t.Helper()
	cfg, control := lifecycleFixture(t)
	approved, err := control.GetPublisherService(t.Context(), cfg.ServiceID, "")
	if err != nil {
		t.Fatal(err)
	}
	approved.Protocol, approved.Endpoint.Port = controlv1.ServiceProtocolHTTP, 443
	control.approved = &approved
	cfg.Metadata.Protocol, cfg.Target = controlv1.ServiceProtocolHTTP, ""
	cfg.Handler = http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})
	cfg.Connectivity.DisableDirect = true
	unused := muxsession.ConnectorFunc(func(context.Context, muxsession.Endpoint) (muxsession.Session, error) {
		return nil, ErrPrivateStream
	})
	cfg.RelayQUIC, cfg.RelayTCP = unused, unused
	authority := &readyAuthorityControl{heldCertificateAcknowledgment: &heldCertificateAcknowledgment{
		lifecycleControl: control, entered: make(chan struct{}), release: make(chan struct{}),
	}}
	cfg.Control = authority
	bounds := make(chan *Bound, 2)
	cfg.Connect = func(_ context.Context, b *Bound, _ uint8, _ ConnectOptions) (SlotSession, error) {
		bounds <- b
		return &heldSlot{stopped: make(chan struct{})}, nil
	}
	return cfg, authority, bounds
}

func awaitReadyAuthority[T any](t *testing.T, event <-chan T, done <-chan struct{}, result *error) T {
	t.Helper()
	select {
	case value := <-event:
		return value
	case <-done:
		t.Fatal("publisher returned before the authority observation", *result)
	case <-time.After(5 * time.Second):
		t.Fatal("publisher did not reach the authority observation")
	}
	var zero T
	return zero
}

func TestServiceRunReadyWaitsForCurrentPolicyThroughPendingIssuanceAndRecovery(t *testing.T) {
	for _, expired := range []bool{false, true} {
		t.Run(map[bool]string{false: "current", true: "expired_while_pending"}[expired], func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				cfg, authority, bounds := readyAuthorityFixture(t)
				authority.short.Store(expired)
				release := sync.OnceFunc(func() { close(authority.release) })
				defer release()
				var notifications, readyStatuses atomic.Int32
				cfg.Ready = func() error { notifications.Add(1); return nil }
				cfg.ObserveReadiness = func(status RunStatus) {
					if status.Ready {
						readyStatuses.Add(1)
					}
				}
				ctx, cancel := context.WithCancel(t.Context())
				joined := make(chan struct{})
				var result error
				go func() { defer close(joined); result = Publish(ctx, cfg) }()
				defer func() {
					release()
					cancel()
					<-joined
					if result != nil {
						t.Error("publisher cleanup failed", result)
					}
				}()
				awaitReadyAuthority(t, authority.entered, joined, &result)
				bound := awaitReadyAuthority(t, bounds, joined, &result)
				synctest.Wait()
				if notifications.Load() != 0 || readyStatuses.Load() != 0 {
					t.Fatal("pending certificate advertised a ready publisher")
				}
				if expired {
					authority.unavailable.Store(true)
					time.Sleep(time.Second)
					if _, current, _ := bound.prepared.policy.Current(); current {
						t.Fatal("fixture policy did not expire while issuance was pending")
					}
				}
				release()
				time.Sleep(20 * time.Millisecond)
				synctest.Wait()
				if expired {
					if notifications.Load() != 0 || readyStatuses.Load() != 0 {
						t.Error("installed certificate advertised readiness with expired policy", notifications.Load(), readyStatuses.Load())
					}
					authority.short.Store(false)
					authority.unavailable.Store(false)
					time.Sleep(2 * time.Second)
					synctest.Wait()
				}
				if notifications.Load() != 1 || readyStatuses.Load() == 0 {
					t.Fatal("current policy and certificate did not produce one ready notification", notifications.Load(), readyStatuses.Load())
				}
				time.Sleep(20 * time.Millisecond)
				synctest.Wait()
				if notifications.Load() != 1 {
					t.Fatal("policy recovery repeated the one-time ready notification", notifications.Load())
				}
			})
		})
	}
}

func TestServiceRunRechecksAuthorityAfterReadinessObserverBeforeNotification(t *testing.T) {
	for _, boundary := range []string{"policy_revoked", "policy_expired", "certificate_expired", "publisher_expired", "caller_canceled"} {
		t.Run(boundary, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				cfg, authority, bounds := readyAuthorityFixture(t)
				release := sync.OnceFunc(func() { close(authority.release) })
				defer release()
				var bound *Bound
				var notifications atomic.Int32
				var changed atomic.Bool
				ctx, cancel := context.WithCancel(t.Context())
				cfg.Ready = func() error { notifications.Add(1); return nil }
				cfg.ObserveReadiness = func(status RunStatus) {
					if !status.Ready || !changed.CompareAndSwap(false, true) {
						return
					}
					switch boundary {
					case "policy_revoked":
						bound.prepared.policy.Close()
					case "policy_expired":
						authority.unavailable.Store(true)
						time.Sleep(31 * time.Second)
					case "certificate_expired":
						bound.prepared.certMu.Lock()
						bound.prepared.certValidTo = time.Now()
						bound.prepared.certMu.Unlock()
					case "publisher_expired":
						time.Sleep(time.Until(status.LeaseExpiresAt))
					case "caller_canceled":
						cancel()
					}
				}
				done := make(chan struct{})
				var result error
				go func() { defer close(done); result = Publish(ctx, cfg) }()
				defer func() { release(); cancel(); <-done }()
				awaitReadyAuthority(t, authority.entered, done, &result)
				bound = awaitReadyAuthority(t, bounds, done, &result)
				release()
				time.Sleep(2 * time.Minute)
				synctest.Wait()
				if !changed.Load() {
					t.Fatal("fixture never reached the ready observation")
				}
				if notifications.Load() != 0 {
					t.Fatal("ready callback ran after its observed authority ended", notifications.Load())
				}
			})
		})
	}
}

func TestServiceRunPolicyReadinessUsesProtocolPermissionShape(t *testing.T) {
	bound, _, _, _, _ := connectorPeerFixture(t, "127.0.0.1:1")
	for _, protocol := range []config.ProtocolName{config.ProtocolTCP, config.ProtocolPostgres, config.ProtocolMySQL, config.ProtocolKubernetes} {
		bound.prepared.managedProtocol = protocol
		if !bound.prepared.currentPolicy() {
			t.Fatal("native readiness required an HTTP policy port", protocol)
		}
	}
	bound.prepared.managedProtocol = config.ProtocolHTTP
	if bound.prepared.currentPolicy() {
		t.Fatal("HTTP readiness accepted a native-only policy shape")
	}
}

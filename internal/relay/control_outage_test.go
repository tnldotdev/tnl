package relay

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/tnldotdev/tnl/internal/policy/controloutage"
	relayv1 "github.com/tnldotdev/tnl/pkg/api/control/private/relay/v1"
)

type outageRoleControl struct {
	ControlClient
	lease relayv1.RelayLease
	renew func() (relayv1.RelayLease, error)
}

func (c outageRoleControl) RegisterRelay(context.Context, relayv1.RelayRegistration) (relayv1.RelayLease, error) {
	return c.lease, nil
}

func (c outageRoleControl) RenewRelay(context.Context, relayv1.RelayID, relayv1.RelayRenewal) (relayv1.RelayLease, error) {
	if c.renew != nil {
		return c.renew()
	}
	return relayv1.RelayLease{}, errors.New("control is unreachable")
}

func TestRelayServingDeadlineDoesNotUseLivenessOrResetOnFailedRefresh(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		started := time.Now()
		lease := relayv1.RelayLease{Region: "local", RelayServiceId: "a", RelayId: "a-1", RelayRunId: "run",
			RelayLeaseRevision: 1, ProtocolVersion: 1, RelayAddress: "relay.example:443", TlsServerName: "relay.example",
			InternalRelayAddress: "relay.internal:443", InternalNetworks: []string{}, ConnectionCapacity: 10, StreamCapacity: 10,
			RegisteredAt: started, RenewedAt: started, LeaseExpiresAt: started.Add(time.Second), ServingUntil: started.Add(3 * time.Second)}
		var fenced atomic.Int64
		var fencedAt time.Time
		controller, err := NewController(ControllerConfig{
			Client: outageRoleControl{lease: lease},
			Registration: relayv1.RelayRegistration{Region: lease.Region, RelayServiceId: lease.RelayServiceId, RelayId: lease.RelayId, RelayRunId: lease.RelayRunId,
				ProtocolVersion: 1, RelayAddress: lease.RelayAddress, TlsServerName: lease.TlsServerName, InternalRelayAddress: lease.InternalRelayAddress,
				InternalNetworks: []string{}, ConnectionCapacity: 10, StreamCapacity: 10},
			RenewalInterval: 500 * time.Millisecond, RetryInterval: 100 * time.Millisecond, Report: func(error) {},
			LeaseChanged: func(previous, current relayv1.RelayLease) {
				if previous.RelayLeaseRevision > 0 && current.RelayLeaseRevision == 0 {
					fencedAt = time.Now()
					fenced.Add(1)
				}
			},
		})
		if err != nil {
			t.Fatal(err)
		}
		done := make(chan error, 1)
		go func() { done <- controller.Run(t.Context()) }()
		synctest.Wait()
		time.Sleep(1500 * time.Millisecond)
		synctest.Wait()
		if !controller.Ready(time.Now()) || fenced.Load() != 0 {
			t.Fatal("liveness expiry revoked existing serving authority")
		}
		time.Sleep(1500 * time.Millisecond)
		synctest.Wait()
		err = <-done
		if !errors.Is(err, controloutage.ErrDeadline) || fenced.Load() != 1 || !fencedAt.Equal(started.Add(3*time.Second)) {
			t.Fatal("failed refreshes or duplicate registrations moved the serving fence", err, fenced.Load(), fencedAt)
		}
		if controller.Ready(time.Now()) || controller.Lease().RelayLeaseRevision != 0 {
			t.Fatal("expired relay retained authority")
		}
	})
}

func TestRelayServingDeadlineWatcherAcceptsShorterConfirmation(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		started := time.Now()
		lease := relayv1.RelayLease{Region: "local", RelayServiceId: "a", RelayId: "a-1", RelayRunId: "run",
			RelayLeaseRevision: 1, ProtocolVersion: 1, RelayAddress: "relay.example:443", TlsServerName: "relay.example",
			InternalRelayAddress: "relay.internal:443", InternalNetworks: []string{}, ConnectionCapacity: 10, StreamCapacity: 10,
			RegisteredAt: started, RenewedAt: started, ServingUntil: started.Add(time.Minute)}
		control := outageRoleControl{lease: lease, renew: func() (relayv1.RelayLease, error) {
			shorter := lease
			shorter.RenewedAt, shorter.ServingUntil = started.Add(time.Second), started.Add(1500*time.Millisecond)
			return shorter, nil
		}}
		controller, err := NewController(ControllerConfig{Client: control,
			Registration: relayv1.RelayRegistration{Region: lease.Region, RelayServiceId: lease.RelayServiceId, RelayId: lease.RelayId, RelayRunId: lease.RelayRunId,
				ProtocolVersion: 1, RelayAddress: lease.RelayAddress, TlsServerName: lease.TlsServerName, InternalRelayAddress: lease.InternalRelayAddress,
				InternalNetworks: []string{}, ConnectionCapacity: 10, StreamCapacity: 10},
			RenewalInterval: time.Second, RetryInterval: 100 * time.Millisecond, Report: func(error) {}})
		if err != nil {
			t.Fatal(err)
		}
		done := make(chan error, 1)
		go func() { done <- controller.Run(t.Context()) }()
		synctest.Wait()
		time.Sleep(1500 * time.Millisecond)
		synctest.Wait()
		select {
		case err := <-done:
			if !errors.Is(err, controloutage.ErrDeadline) {
				t.Fatal(err)
			}
		default:
			t.Fatal("watcher retained its older, longer sleep after a shorter confirmation")
		}
	})
}

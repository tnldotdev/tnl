package ingress

import (
	"context"
	"errors"
	"net/netip"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	ingressv1 "github.com/tnldotdev/tnl/pkg/api/control/private/ingress/v1"
)

func TestServiceRoutingServingDeadlineDoesNotReanchorSameSourceAuthority(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		lease, snapshot := serviceRoutingFixture(t)
		started := time.Now()
		snapshot.ObservedAt = started.Add(time.Second)
		routing := NewServiceRouting()
		defer routing.Close()
		if err := routing.apply(started, lease, snapshot); err != nil {
			t.Fatal(err)
		}
		original := routing.lookup("route.example", 443, lease, time.Now())[0]
		var closed atomic.Int64
		release, err := routing.bind(original, netip.MustParseAddr("192.0.2.1"), func() { closed.Add(1) })
		if err != nil {
			t.Fatal(err)
		}
		defer release()
		remoteRelayUntil := snapshot.Runs[0].ConnectedRelays[0].ServingUntil
		time.Sleep(2 * time.Second)
		snapshot.ObservedAt = time.Now()
		if err := routing.apply(time.Now(), lease, snapshot); err != nil {
			t.Fatal(err)
		}
		current := routing.lookup("route.example", 443, lease, time.Now())[0]
		if !current.until.Equal(original.until) || !snapshot.Runs[0].ConnectedRelays[0].ServingUntil.Equal(remoteRelayUntil) {
			t.Fatal("new observation extended fixed source authority or mutated the caller's relay facts")
		}
		time.Sleep(time.Until(original.until))
		synctest.Wait()
		if closed.Load() != 1 {
			t.Fatal("traffic outlived its previously accepted source authority")
		}
	})
}

type outageIngressControl struct {
	ControlClient
	lease ingressv1.IngressLease
	renew func() (ingressv1.IngressLease, error)
}

func (c outageIngressControl) RegisterIngress(context.Context, ingressv1.IngressRegistration) (ingressv1.IngressLease, error) {
	return c.lease, nil
}

func (c outageIngressControl) RenewIngress(context.Context, ingressv1.IngressID, ingressv1.IngressRenewal) (ingressv1.IngressLease, error) {
	if c.renew != nil {
		return c.renew()
	}
	return ingressv1.IngressLease{}, errors.New("control is unreachable")
}

func TestIngressServingDeadlineSurvivesLivenessButExpiresWithoutConfirmation(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		started := time.Now()
		lease := ingressv1.IngressLease{Region: "local", IngressId: "ingress", IngressRunId: "run", IngressLeaseRevision: 1,
			ProtocolVersion: 1, ConnectionCapacity: 10, RegisteredAt: started, RenewedAt: started,
			LeaseExpiresAt: started.Add(time.Second), ServingUntil: started.Add(3 * time.Second)}
		controller, err := NewController(ControllerConfig{
			Client: outageIngressControl{lease: lease},
			Registration: ingressv1.IngressRegistration{Region: lease.Region, IngressId: lease.IngressId, IngressRunId: lease.IngressRunId,
				ProtocolVersion: 1, ConnectionCapacity: 10, IngressPoolId: "ingress-a", ServicePorts: []int{}},
			RenewalInterval: 500 * time.Millisecond, RetryInterval: 100 * time.Millisecond, Report: func(error) {},
		})
		if err != nil {
			t.Fatal(err)
		}
		done := make(chan error, 1)
		go func() { done <- controller.Run(t.Context()) }()
		synctest.Wait()
		time.Sleep(1500 * time.Millisecond)
		synctest.Wait()
		if !controller.Ready(time.Now()) {
			t.Fatal("liveness expiry revoked existing ingress authority")
		}
		time.Sleep(1500 * time.Millisecond)
		synctest.Wait()
		if err := <-done; !errors.Is(err, ErrIngressLeaseLost) {
			t.Fatal("ingress failed to stop at its captured serving deadline", err)
		}
		if controller.Ready(time.Now()) || controller.Lease().IngressLeaseRevision != 0 {
			t.Fatal("expired ingress retained authority")
		}
	})
}

func TestIngressServingDeadlineWatcherAcceptsShorterConfirmation(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		started := time.Now()
		lease := ingressv1.IngressLease{Region: "local", IngressId: "ingress", IngressRunId: "run", IngressLeaseRevision: 1,
			ProtocolVersion: 1, ConnectionCapacity: 10, RegisteredAt: started, RenewedAt: started, ServingUntil: started.Add(time.Minute)}
		control := outageIngressControl{lease: lease, renew: func() (ingressv1.IngressLease, error) {
			shorter := lease
			shorter.RenewedAt, shorter.ServingUntil = started.Add(time.Second), started.Add(1500*time.Millisecond)
			return shorter, nil
		}}
		controller, err := NewController(ControllerConfig{Client: control,
			Registration: ingressv1.IngressRegistration{Region: lease.Region, IngressId: lease.IngressId, IngressRunId: lease.IngressRunId,
				ProtocolVersion: 1, ConnectionCapacity: 10, IngressPoolId: "ingress-a", ServicePorts: []int{}},
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
			if !errors.Is(err, ErrIngressLeaseLost) {
				t.Fatal(err)
			}
		default:
			t.Fatal("watcher retained its older, longer sleep after a shorter confirmation")
		}
	})
}

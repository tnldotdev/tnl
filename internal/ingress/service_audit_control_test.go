package ingress

import (
	"errors"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/pkg/api/ingressv1"
)

func TestLeaseAuditBindingPrecedesVisibilityAndDoesNotRepeatOnRenewal(t *testing.T) {
	now := time.Now()
	calls := 0
	var controller *Controller
	var err error
	controller, err = NewController(ControllerConfig{Client: leaseTestClient{}, RoutingTable: new(RoutingTable), Registration: ingressv1.IngressRegistration{IngressId: "ingress", IngressRunId: "run", ProtocolVersion: 1, ConnectionCapacity: 10}, RenewalInterval: time.Second, RetryInterval: time.Second, RoutingWait: time.Second,
		LeaseEstablished: func(lease ingressv1.IngressLease) error {
			calls++
			if controller.lease.IngressLeaseRevision != 0 || lease.IngressLeaseRevision != 1 {
				t.Error("lease became visible before its audit sink was bound")
			}
			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	lease := testIngressLease(now)
	if err = controller.setLease(lease); err != nil {
		t.Fatal(err)
	}
	lease.RenewedAt = now.Add(time.Second)
	lease.LeaseExpiresAt = lease.LeaseExpiresAt.Add(time.Minute)
	if err = controller.setLease(lease); err != nil || calls != 1 {
		t.Fatal("renewal rebound accounting identity", err)
	}
	lease.IngressLeaseRevision++
	if err = controller.setLease(lease); !errors.Is(err, ErrIngressLeaseLost) || calls != 1 {
		t.Fatal("lease replacement reused an old audit sink", err)
	}
}

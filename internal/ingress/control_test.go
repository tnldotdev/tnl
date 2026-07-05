package ingress

import (
	"context"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/controlstate"
	"github.com/tnldotdev/tnl/internal/ingressapi"
	"github.com/tnldotdev/tnl/pkg/api/ingressv1"
)

func TestDirectStaleLeaseClearsController(t *testing.T) {
	client, err := ingressapi.NewDirectClient(ingressapi.DirectConfig{Store: staleLeaseStore{}, LeaseDuration: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	response, err := client.RenewIngressWithResponse(t.Context(), "ingress-1", ingressv1.IngressRenewal{
		IngressId: "ingress-1", IngressRunId: "run-1", IngressLeaseRevision: 1,
	})
	if err != nil {
		t.Fatalf("store error escaped direct adapter: %v", err)
	}
	controller := &Controller{lease: ingressv1.IngressLease{IngressLeaseRevision: 1}, routingTableCurrent: true}
	controller.responseError("renew", response.StatusCode(), response.ApplicationproblemJSONDefault)
	if controller.lease.IngressLeaseRevision != 0 || controller.routingTableCurrent {
		t.Fatalf("stale state retained: %#v", controller)
	}
}

type staleLeaseStore struct{ ingressapi.Store }

func (staleLeaseStore) RenewIngress(context.Context, controlstate.IngressRenewal, time.Time, time.Duration) (controlstate.IngressLease, error) {
	return controlstate.IngressLease{}, controlstate.ErrIngressLeaseStale
}

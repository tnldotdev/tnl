package ingressapi

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/controlstate"
	"github.com/tnldotdev/tnl/pkg/api/ingressv1"
)

func TestDirectRoutingEventsProblemFieldsMatchHTTP(t *testing.T) {
	for _, resnapshot := range []bool{false, true} {
		store := &ingressStoreStub{readRoutingEvents: func(context.Context, controlstate.IngressLeaseIdentity, uint64, int, time.Time) (controlstate.IngressRoutingTablePage, error) {
			if resnapshot {
				return controlstate.IngressRoutingTablePage{ResnapshotRequired: true}, nil
			}
			return controlstate.IngressRoutingTablePage{}, controlstate.ErrIngressLeaseStale
		}}
		client, err := NewDirectClient(DirectConfig{Store: store, LeaseDuration: time.Minute})
		if err != nil {
			t.Fatal(err)
		}
		params := &ingressv1.GetIngressRoutingTableEventsParams{IngressRunId: "run-1", IngressLeaseRevision: 7, After: 11}
		direct, err := client.GetIngressRoutingTableEventsWithResponse(t.Context(), "ingress-1", params)
		if err != nil {
			t.Fatal(err)
		}
		response := httptest.NewRecorder()
		testIngressHandler(t, store, time.Now(), nil).ServeHTTP(response, authenticatedIngressRequest(http.MethodGet,
			"/internal/v1/ingresses/ingress-1/routing-table/events?ingress_run_id=run-1&ingress_lease_revision=7&after=11", nil, "ingress-1"))
		wire, err := ingressv1.ParseGetIngressRoutingTableEventsResponse(response.Result())
		if err != nil || direct.StatusCode() != http.StatusConflict || direct.ApplicationproblemJSONDefault != nil || direct.ApplicationproblemJSON409 == nil || wire.ApplicationproblemJSON409 == nil || *direct.ApplicationproblemJSON409 != *wire.ApplicationproblemJSON409 {
			t.Fatalf("direct = %#v, HTTP = %#v, error = %v", direct, wire, err)
		}
	}
}

func TestDirectRoutingEventsDefaultWaitAndCancellation(t *testing.T) {
	store := &ingressStoreStub{readRoutingEvents: func(context.Context, controlstate.IngressLeaseIdentity, uint64, int, time.Time) (controlstate.IngressRoutingTablePage, error) {
		return controlstate.IngressRoutingTablePage{}, nil
	}}
	client, err := NewDirectClient(DirectConfig{Store: store, LeaseDuration: time.Minute, RoutingPollInterval: time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	zero := "0s"
	params := &ingressv1.GetIngressRoutingTableEventsParams{IngressRunId: "run-1", IngressLeaseRevision: 1, Wait: &zero}
	response, err := client.GetIngressRoutingTableEventsWithResponse(t.Context(), "ingress-1", params)
	if err != nil || response.StatusCode() != http.StatusOK || response.JSON200 == nil {
		t.Fatalf("zero wait = %#v, %v", response, err)
	}
	params.Wait = nil
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
	defer cancel()
	response, err = client.GetIngressRoutingTableEventsWithResponse(ctx, "ingress-1", params)
	if response != nil || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("default wait = %#v, %v", response, err)
	}
}

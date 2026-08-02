package ingressapi

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/controlstate"
	"github.com/tnldotdev/tnl/internal/serviceapi"
	"github.com/tnldotdev/tnl/pkg/api/ingressv1"
)

func TestDirectRoutingEventsProblemFieldsMatchHTTP(t *testing.T) {
	for _, test := range []struct {
		name, detail string
		resnapshot   bool
		failure      error
	}{
		{"ingress_lease_stale", "The ingress lease is no longer current", false, controlstate.ErrIngressLeaseStale},
		{"routing_table_resnapshot_required", "The routing-table revision was compacted; load a new snapshot", true, nil},
	} {
		for _, transport := range []string{"direct", "HTTP"} {
			t.Run(test.name+"/"+transport, func(t *testing.T) {
				var identity controlstate.IngressLeaseIdentity
				var after uint64
				var limit, calls int
				store := &ingressStoreStub{readRoutingEvents: func(_ context.Context, got controlstate.IngressLeaseIdentity, cursor uint64, count int, _ time.Time) (controlstate.IngressRoutingTablePage, error) {
					identity, after, limit = got, cursor, count
					calls++
					return controlstate.IngressRoutingTablePage{ResnapshotRequired: test.resnapshot}, test.failure
				}}
				client, err := NewDirectClient(DirectConfig{Store: store, LeaseDuration: time.Minute})
				if err != nil {
					t.Fatal(err)
				}
				var status int
				var problem *ingressv1.Problem
				if transport == "direct" {
					count := 8
					_, err = client.GetIngressRoutingTableEvents(t.Context(), "ingress-1", ingressv1.GetIngressRoutingTableEventsParams{IngressRunId: "run-1", IngressLeaseRevision: 7, After: 11, Limit: &count})
					var direct *serviceapi.ProblemError
					if !errors.As(err, &direct) {
						t.Fatalf("direct error = %v", err)
					}
					status = direct.Status
					problem = &ingressv1.Problem{Status: direct.Status, Type: direct.Type, Title: direct.Title, Detail: direct.Detail}
				} else {
					wire := httptest.NewRecorder()
					testIngressHandler(t, store, time.Now(), nil).ServeHTTP(wire, authenticatedIngressRequest(http.MethodGet,
						"/internal/v1/ingresses/ingress-1/routing-table/events?ingress_run_id=run-1&ingress_lease_revision=7&after=11&limit=8", nil))
					response, parseErr := ingressv1.ParseGetIngressRoutingTableEventsResponse(wire.Result())
					if parseErr != nil {
						t.Fatal(parseErr)
					}
					status = response.StatusCode()
					problem = response.ApplicationproblemJSON409
				}
				want := ingressv1.Problem{Status: http.StatusConflict, Type: "https://tnl.dev/problems/" + test.name, Title: strings.ReplaceAll(test.name, "_", " "), Detail: test.detail}
				if status != http.StatusConflict || !reflect.DeepEqual(problem, &want) {
					t.Fatalf("response = %d %#v, want %#v", status, problem, want)
				}
				if calls != 1 || identity != (controlstate.IngressLeaseIdentity{IngressID: "ingress-1", IngressRunID: "run-1", IngressLeaseRevision: 7}) || after != 11 || limit != 8 {
					t.Fatalf("routing lookup = %#v after %d limit %d, calls %d", identity, after, limit, calls)
				}
			})
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
	params := ingressv1.GetIngressRoutingTableEventsParams{IngressRunId: "run-1", IngressLeaseRevision: 1, Wait: &zero}
	page, err := client.GetIngressRoutingTableEvents(t.Context(), "ingress-1", params)
	if err != nil {
		t.Fatalf("zero wait = %#v, %v", page, err)
	}
	params.Wait = nil
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
	defer cancel()
	page, err = client.GetIngressRoutingTableEvents(ctx, "ingress-1", params)
	if !reflect.DeepEqual(page, ingressv1.IngressRoutingTablePage{}) || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("default wait = %#v, %v", page, err)
	}
}

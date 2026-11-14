package ingress

import (
	"context"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	ingressv1 "github.com/tnldotdev/tnl/pkg/api/control/private/ingress/v1"
)

type closureStore struct {
	publicServiceStore
	lookup func(context.Context, controlstate.IngressLeaseIdentity, []controlstate.ServiceRunReference, time.Time) ([]controlstate.ServiceRunReference, error)
}

func (s closureStore) ClosedServiceRuns(ctx context.Context, lease controlstate.IngressLeaseIdentity, runs []controlstate.ServiceRunReference, now time.Time) ([]controlstate.ServiceRunReference, error) {
	return s.lookup(ctx, lease, runs, now)
}

func TestServiceRunClosureLookupIsAuthenticatedBoundedAndExact(t *testing.T) {
	now := time.Now().UTC()
	ref := ingressv1.ServiceRunReference{ServiceId: "svc_" + strings.Repeat("S", 22), ServiceRunId: "srun_" + strings.Repeat("R", 22), RunNumber: 7}
	request := ingressv1.ServiceRunClosureLookup{IngressRunId: "ingress-run", IngressLeaseRevision: 4, ServiceRuns: []ingressv1.ServiceRunReference{ref}}
	calls := 0
	store := closureStore{lookup: func(_ context.Context, lease controlstate.IngressLeaseIdentity, runs []controlstate.ServiceRunReference, at time.Time) ([]controlstate.ServiceRunReference, error) {
		calls++
		if lease.IngressID != "ingress" || lease.IngressRunID != request.IngressRunId || lease.IngressLeaseRevision != 4 || !at.Equal(now) ||
			!reflect.DeepEqual(runs, []controlstate.ServiceRunReference{{ServiceID: ref.ServiceId, RunID: ref.ServiceRunId, RunNumber: ref.RunNumber}}) {
			t.Fatal("closure lookup changed exact authority", lease, runs, at)
		}
		return runs, nil
	}}
	h := testIngressHandler(t, &ingressStoreStub{publicServiceStore: store}, now, nil)
	const path = "/internal/v1/ingresses/ingress/public-services/closed-runs"
	unauthenticated := httptest.NewRecorder()
	h.ServeHTTP(unauthenticated, httptest.NewRequest(http.MethodPost, path, nil))
	if unauthenticated.Code != http.StatusUnauthorized || calls != 0 {
		t.Fatal("closure proof bypassed cluster authentication")
	}
	for _, change := range []func(*ingressv1.ServiceRunClosureLookup){
		func(r *ingressv1.ServiceRunClosureLookup) { r.ServiceRuns = nil },
		func(r *ingressv1.ServiceRunClosureLookup) { r.ServiceRuns = []ingressv1.ServiceRunReference{ref, ref} },
		func(r *ingressv1.ServiceRunClosureLookup) { r.ServiceRuns = make([]ingressv1.ServiceRunReference, 129) },
		func(r *ingressv1.ServiceRunClosureLookup) { r.IngressLeaseRevision = 0 },
		func(r *ingressv1.ServiceRunClosureLookup) {
			invalid := ref
			invalid.RunNumber = 0
			r.ServiceRuns = []ingressv1.ServiceRunReference{invalid}
		},
	} {
		invalid := request
		change(&invalid)
		response := serveIngressJSON(t, h, http.MethodPost, path, invalid)
		if response.Code != http.StatusBadRequest || calls != 0 {
			t.Fatal("unbounded or invalid closure lookup reached state", response.Code)
		}
	}
	response := serveIngressJSON(t, h, http.MethodPost, path, request)
	var result ingressv1.ServiceRunClosures
	decodeIngressResponse(t, response, &result)
	if response.Code != http.StatusOK || calls != 1 || !reflect.DeepEqual(result.Closed, request.ServiceRuns) {
		t.Fatal("exact terminal proof changed at API boundary", response.Code, result)
	}
	store.lookup = func(context.Context, controlstate.IngressLeaseIdentity, []controlstate.ServiceRunReference, time.Time) ([]controlstate.ServiceRunReference, error) {
		return []controlstate.ServiceRunReference{{ServiceID: ref.ServiceId, RunID: ref.ServiceRunId, RunNumber: ref.RunNumber + 1}}, nil
	}
	h = testIngressHandler(t, &ingressStoreStub{publicServiceStore: store}, now, nil)
	response = serveIngressJSON(t, h, http.MethodPost, path, request)
	if response.Code != http.StatusInternalServerError {
		t.Fatal("API returned terminal proof for an unrequested sibling", response.Code)
	}
}

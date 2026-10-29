package ingress

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	"github.com/tnldotdev/tnl/internal/policy/visitorscope"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type ingressPreparationStore struct {
	Store
	read func(controlstate.IngressLeaseIdentity, visitorscope.Scope, int64, time.Time, []controlstate.IngressStreamAllocationObservation)
}

func (s ingressPreparationStore) ReadIngressVisitorPolicy(_ context.Context, owner controlstate.IngressLeaseIdentity, scope visitorscope.Scope, after int64, now time.Time, observed ...controlstate.IngressStreamAllocationObservation) (controlv1.VisitorPolicyUpdate, error) {
	s.read(owner, scope, after, now, observed)
	return controlv1.VisitorPolicyUpdate{}, nil
}

func TestPublicReadinessIngressPolicyCarriesExactInstalledObservation(t *testing.T) {
	now := time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)
	url, allocation, run := "url_"+strings.Repeat("A", 22), "salloc_"+strings.Repeat("B", 22), "pr_"+strings.Repeat("C", 22)
	called := false
	store := ingressPreparationStore{read: func(owner controlstate.IngressLeaseIdentity, scope visitorscope.Scope, after int64, at time.Time, observed []controlstate.IngressStreamAllocationObservation) {
		called = true
		if owner != (controlstate.IngressLeaseIdentity{IngressID: "ingress-a", IngressRunID: "process-a", IngressLeaseRevision: 3}) || scope != (visitorscope.Scope{Kind: visitorscope.PublicURL, ID: url}) || after != 7 || !at.Equal(now) {
			t.Fatal("policy request lost resource, exact process or installed revision")
		}
		if len(observed) != 1 || observed[0] != (controlstate.IngressStreamAllocationObservation{AllocationID: allocation, RunID: run, RunNumber: 4, ValidUntil: now.Add(5 * time.Second)}) {
			t.Fatal("policy request lost exact allocation/run/deadline")
		}
	}}
	body, err := json.Marshal(map[string]any{"ingress_run_id": "process-a", "ingress_lease_revision": 3, "resource": map[string]string{"kind": "public_url", "id": url}, "after_revision": 7,
		"observed_allocations": []map[string]any{{"allocation_id": allocation, "run_id": run, "run_number": 4, "valid_until": now.Add(5 * time.Second)}}})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/internal/v1/ingresses/ingress-a/visitor-policy", strings.NewReader(string(body)))
	request.Header.Set("Authorization", "Bearer "+testIngressClusterSecret)
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	testIngressHandler(t, store, now, nil).ServeHTTP(response, request)
	if response.Code != http.StatusOK || !called {
		t.Fatalf("policy observation: status=%d called=%t body=%s", response.Code, called, response.Body.String())
	}
}
